/*
 * Copyright (c) 2017, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <errno.h>
#include <fcntl.h>
#include <gio/gio.h>
#include <glib.h>
#include <glib-unix.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sapi/tpm20.h>
#include "tabrmd.h"
#include "access-broker.h"
#include "connection.h"
#include "connection-manager.h"
#include "tabrmd.h"
#include "logging.h"
#include "thread.h"
#include "command-source.h"
#include "random.h"
#include "resource-manager.h"
#include "response-sink.h"
#include "source-interface.h"
#include "tcti-options.h"
#include "ipc-frontend.h"
#include "ipc-frontend-dbus.h"

/* Structure to hold data that we pass to the gmain loop as 'user_data'.
 * This data will be available to events from gmain including events from
 * the DBus.
 */
typedef struct gmain_data {
    tabrmd_options_t        options;
    GMainLoop              *loop;
    AccessBroker           *access_broker;
    ResourceManager        *resource_manager;
     CommandSource         *command_source;
    Random                 *random;
    ResponseSink           *response_sink;
    GMutex                  init_mutex;
    Tcti                   *tcti;
    IpcFrontend            *ipc_frontend;
} gmain_data_t;

/**
 * This is a simple function to do sanity checks before calling
 * g_main_loop_quit.
 */
static void
main_loop_quit (GMainLoop *loop)
{
    g_info ("main_loop_quit");
    if (loop && g_main_loop_is_running (loop))
        g_main_loop_quit (loop);
}
/**
 * This is a very poorly named signal handling function. It is invoked in
 * response to a Unix signal. It does one thing:
 * - Shuts down the GMainLoop.
 */
static gboolean
signal_handler (gpointer user_data)
{
    g_info ("handling signal");
    /* this is the only place the global poiner to the GMainLoop is accessed */
    main_loop_quit ((GMainLoop*)user_data);

    return G_SOURCE_CONTINUE;
}

static void
on_ipc_frontend_disconnect (IpcFrontend *ipc_frontend,
                           GMainLoop  *loop)
{
    g_info ("IpcFrontend 0x%" PRIxPTR " disconnected", (uintptr_t)ipc_frontend);
    main_loop_quit (loop);
}
/**
 * This function initializes and configures all of the long-lived objects
 * in the tabrmd system. It is invoked on a thread separate from the main
 * thread as a way to get the main thread listening for connections on
 * DBus as quickly as possible. Any incomming DBus requests will block
 * on the 'init_mutex' until this thread completes but they won't be
 * timing etc. This function does X things:
 * - Locks the init_mutex.
 * - Registers a handler for UNIX signals for SIGINT and SIGTERM.
 * - Seeds the RNG state from an entropy source.
 * - Creates the ConnectionManager.
 * - Creates the TCTI instance used by the Tab.
 * - Creates an access broker and verify the current state of the TPM.
 * - Creates and wires up the objects that make up the TPM command
 *   processing pipeline.
 * - Starts all of the threads in the command processing pipeline.
 * - Unlocks the init_mutex.
 */
static gpointer
init_thread_func (gpointer user_data)
{
    gmain_data_t *data = (gmain_data_t*)user_data;
    gint ret;
    uint32_t loaded_trans_objs;
    TSS2_RC rc;
    CommandAttrs *command_attrs;
    ConnectionManager *connection_manager = NULL;

    g_info ("init_thread_func start");
    g_mutex_lock (&data->init_mutex);
    /* Setup program signals */
    if (g_unix_signal_add(SIGINT, signal_handler, data->loop) <= 0 ||
        g_unix_signal_add(SIGTERM, signal_handler, data->loop) <= 0)
    {
        g_error("failed to setup signal handlers");
    }

    data->random = random_new();
    ret = random_seed_from_file (data->random, data->options.prng_seed_file);
    if (ret != 0)
        g_error ("failed to seed Random object");

    connection_manager = connection_manager_new(data->options.max_connections);
    if (connection_manager == NULL)
        g_error ("failed to allocate connection_manager");
    g_debug ("ConnectionManager: 0x%" PRIxPTR, (uintptr_t)connection_manager);
    /* setup IpcFrontend */
    data->ipc_frontend =
        IPC_FRONTEND (ipc_frontend_dbus_new (data->options.bus,
                                            data->options.dbus_name,
                                            connection_manager,
                                            data->options.max_transient_objects,
                                            data->random));
    if (data->ipc_frontend == NULL) {
        g_error ("failed to allocate IpcFrontend object");
    }
    g_signal_connect (data->ipc_frontend,
                      "disconnected",
                      (GCallback) on_ipc_frontend_disconnect,
                      data->loop);
    ipc_frontend_connect (data->ipc_frontend,
                         &data->init_mutex);

    /**
     * this isn't strictly necessary but it allows us to detect a failure in
     * the TCTI before we start communicating with clients
     */
    rc = tcti_initialize (data->tcti);
    if (rc != TSS2_RC_SUCCESS) {
        tabrmd_critical ("TCTI initialization failed: 0x%x", rc);
    }

    data->access_broker = access_broker_new (data->tcti);
    g_debug ("created AccessBroker: 0x%" PRIxPTR,
             (uintptr_t)data->access_broker);
    rc = access_broker_init_tpm (data->access_broker);
    if (rc != TSS2_RC_SUCCESS)
        g_error ("failed to initialize AccessBroker: 0x%" PRIx32, rc);
    /*
     * Ensure the TPM is in a state in which we can use it w/o stepping all
     * over someone else.
     */
    rc = access_broker_get_trans_object_count (data->access_broker,
                                               &loaded_trans_objs);
    if (rc != TSS2_RC_SUCCESS)
        g_error ("failed to get number of loaded transient objects from "
                 "access broker 0x%" PRIxPTR " RC: 0x%" PRIx32,
                 (uintptr_t)data->access_broker,
                 rc);
    if ((loaded_trans_objs > 0) && data->options.fail_on_loaded_trans) {
        tabrmd_critical ("TPM reports 0x%" PRIx32 " loaded transient objects, "
                         "aborting", loaded_trans_objs);
    }
    /**
     * Instantiate and the objects that make up the TPM command processing
     * pipeline.
     */
    command_attrs = command_attrs_new ();
    g_debug ("created CommandAttrs: 0x%" PRIxPTR, (uintptr_t)command_attrs);
    ret = command_attrs_init_tpm (command_attrs, data->access_broker);
    if (ret != 0)
        g_error ("failed to initialize CommandAttribute object: 0x%" PRIxPTR,
                 (uintptr_t)command_attrs);

    data->command_source =
        command_source_new (connection_manager, command_attrs);
    g_debug ("created command source: 0x%" PRIxPTR,
             (uintptr_t)data->command_source);
    data->resource_manager = resource_manager_new (data->access_broker);
    g_debug ("created ResourceManager: 0x%" PRIxPTR,
             (uintptr_t)data->resource_manager);
    data->response_sink = response_sink_new ();
    g_debug ("created response source: 0x%" PRIxPTR,
             (uintptr_t)data->response_sink);
    g_object_unref (command_attrs);
    g_object_unref (data->access_broker);
    /*
     * Connect the ResourceManager to the ConnectionManager
     * 'connection-removed' signal.
     */
    g_signal_connect (connection_manager,
                      "connection-removed",
                      G_CALLBACK (resource_manager_on_connection_removed),
                      data->resource_manager);
    g_object_unref (connection_manager);
    /**
     * Wire up the TPM command processing pipeline. TPM command buffers
     * flow from the CommandSource, to the Tab then finally back to the
     * caller through the ResponseSink.
     */
    source_add_sink (SOURCE (data->command_source),
                     SINK   (data->resource_manager));
    source_add_sink (SOURCE (data->resource_manager),
                     SINK   (data->response_sink));
    /**
     * Start the TPM command processing pipeline.
     */
    ret = thread_start (THREAD (data->command_source));
    if (ret != 0)
        g_error ("failed to start connection_source");
    ret = thread_start (THREAD (data->resource_manager));
    if (ret != 0)
        g_error ("failed to start ResourceManager: %s", strerror (errno));
    ret = thread_start (THREAD (data->response_sink));
    if (ret != 0)
        g_error ("failed to start response_source");

    g_mutex_unlock (&data->init_mutex);
    g_info ("init_thread_func done");

    return NULL;
}
/*
 * This is a GOptionArgFunc callback invoked from the GOption processor from
 * the parse_opts function below. It will be called when the daemon is
 * invoked with the -v/--version option. This will cause the daemon to
 * display a version string and exit.
 */
gboolean
show_version (const gchar  *option_name,
              const gchar  *value,
              gpointer      data,
              GError      **error)
{
    g_print ("tpm2-abrmd version %s\n", VERSION);
    exit (0);
}
/**
 * This function parses the parameter argument vector and populates the
 * parameter 'options' structure with data needed to configure the tabrmd.
 * We rely heavily on the GOption module here and we get our GOptionEntry
 * array from two places:
 * - The TctiOption module.
 * - The local application options specified here.
 * Then we do a bit of sanity checking and setting up default values if
 * none were supplied.
 */
void
parse_opts (gint            argc,
            gchar          *argv[],
            tabrmd_options_t *options)
{
    gchar *logger_name = "stdout";
    GOptionContext *ctx;
    GError *err = NULL;
    gboolean session_bus = FALSE;

    options->max_connections = MAX_CONNECTIONS_DEFAULT;
    options->max_transient_objects = MAX_TRANSIENT_OBJECTS_DEFAULT;
    options->dbus_name = TABRMD_DBUS_NAME_DEFAULT;
    options->prng_seed_file = RANDOM_ENTROPY_FILE_DEFAULT;

    GOptionEntry entries[] = {
        { "dbus-name", 'n', 0, G_OPTION_ARG_STRING, &options->dbus_name,
          "Name for daemon to \"own\" on the D-Bus",
          TABRMD_DBUS_NAME_DEFAULT },
        { "logger", 'l', 0, G_OPTION_ARG_STRING, &logger_name,
          "The name of desired logger, stdout is default.", "[stdout|syslog]"},
        { "session", 's', 0, G_OPTION_ARG_NONE, &session_bus,
          "Connect to the session bus (system bus is default)." },
        { "fail-on-loaded-trans", 'i', 0, G_OPTION_ARG_NONE,
          &options->fail_on_loaded_trans,
          "Fail initialization if the TPM reports loaded transient objects" },
        { "max-connections", 'c', G_OPTION_FLAG_NONE, G_OPTION_ARG_INT,
          &options->max_connections, "Maximum number of client connections." },
        { "max-transient-objects", 'r', G_OPTION_FLAG_NONE, G_OPTION_ARG_INT,
          &options->max_transient_objects,
          "Maximum number of loaded transient objects per client." },
        { "prng-seed-file", 'g', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING,
          &options->prng_seed_file, "File to read seed value for PRNG",
          options->prng_seed_file },
        { "version", 'v', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
          show_version, "Show version string" },
        { NULL },
    };

    ctx = g_option_context_new (" - TPM2 software stack Access Broker Daemon (tabrmd)");
    g_option_context_add_main_entries (ctx, entries, NULL);
    g_option_context_add_group (ctx, tcti_options_get_group (options->tcti_options));
    if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
        tabrmd_critical ("Failed to parse options: %s", err->message);
    }
    /* select the bus type, default to G_BUS_TYPE_SESSION */
    options->bus = session_bus ? G_BUS_TYPE_SESSION : G_BUS_TYPE_SYSTEM;
    if (set_logger (logger_name) == -1) {
        tabrmd_critical ("Unknown logger: %s, try --help\n", logger_name);
    }
    if (options->max_connections < 1 ||
        options->max_connections > MAX_CONNECTIONS)
    {
        tabrmd_critical ("MAX_CONNECTIONS must be between 1 and %d",
                         MAX_CONNECTIONS);
    }
    if (options->max_transient_objects < 1 ||
        options->max_transient_objects > MAX_TRANSIENT_OBJECTS)
    {
        tabrmd_critical ("max-trans-obj parameter must be between 1 and %d",
                         MAX_TRANSIENT_OBJECTS);
    }
    g_option_context_free (ctx);
}
void
thread_cleanup (Thread *thread)
{
    thread_cancel (thread);
    thread_join (thread);
    g_object_unref (thread);
}
/**
 * This is the entry point for the TPM2 Access Broker and Resource Manager
 * daemon. It is responsible for the top most initialization and
 * coordination before blocking on the GMainLoop (g_main_loop_run):
 * - Collects / parses command line options.
 * - Creates the initialization thread and kicks it off.
 * - Registers / owns a name on a DBus.
 * - Blocks on the main loop.
 * At this point all of the tabrmd processing is being done on other threads.
 * When the daemon shutsdown (for any reason) we do cleanup here:
 * - Join / cleanup the initialization thread.
 * - Release the name on the DBus.
 * - Cancel and join all of the threads started by the init thread.
 * - Cleanup all of the objects created by the init thread.
 */
int
main (int argc, char *argv[])
{
    gmain_data_t gmain_data = { 0 };
    GThread *init_thread;

    g_info ("tabrmd startup");
    /* instantiate a TctiOptions object for the parse_opts function to use */
    gmain_data.options.tcti_options = tcti_options_new ();
    parse_opts (argc, argv, &gmain_data.options);
    gmain_data.tcti = tcti_options_get_tcti (gmain_data.options.tcti_options);

    g_mutex_init (&gmain_data.init_mutex);
    gmain_data.loop = g_main_loop_new (NULL, FALSE);
    /*
     * Initialize program data on a separate thread. The main thread needs to
     * get into the GMainLoop ASAP to acquire a dbus name and become
     * responsive to clients.
     */
    init_thread = g_thread_new (TABD_INIT_THREAD_NAME,
                                init_thread_func,
                                &gmain_data);
    g_info ("entering g_main_loop");
    g_main_loop_run (gmain_data.loop);
    g_info ("g_main_loop_run done, cleaning up");
    g_thread_join (init_thread);
    /* cleanup glib stuff first so we stop getting events */
    ipc_frontend_disconnect (gmain_data.ipc_frontend);
    g_object_unref (gmain_data.ipc_frontend);
        /* tear down the command processing pipeline */
    thread_cleanup (THREAD (gmain_data.command_source));
    thread_cleanup (THREAD (gmain_data.resource_manager));
    thread_cleanup (THREAD (gmain_data.response_sink));
    /* clean up what remains */
    g_object_unref (gmain_data.options.tcti_options);
    g_object_unref (gmain_data.random);
    g_object_unref (gmain_data.tcti);
    return 0;
}
