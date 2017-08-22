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

#include <gio/gunixfdlist.h>
#include <inttypes.h>

#include "ipc-backend-dbus.h"
#include "tabrmd.h"

G_DEFINE_TYPE (IpcBackendDbus, ipc_backend_dbus, TYPE_IPC_BACKEND);

typedef enum {
    TABRMD_ERROR_INTERNAL         = TSS2_RESMGR_RC_INTERNAL_ERROR,
    TABRMD_ERROR_MAX_CONNECTIONS  = TSS2_RESMGR_RC_GENERAL_FAILURE,
    TABRMD_ERROR_ID_GENERATION    = TSS2_RESMGR_RC_GENERAL_FAILURE,
    TABRMD_ERROR_NOT_IMPLEMENTED  = TSS2_RESMGR_RC_NOT_IMPLEMENTED,
    TABRMD_ERROR_NOT_PERMITTED    = TSS2_RESMGR_RC_NOT_PERMITTED,
} TabrmdErrorEnum;

enum {
    PROP_0,
    PROP_BUS_NAME,
    PROP_BUS_TYPE,
    PROP_CONNECTION_MANAGER,
    PROP_MAX_TRANS,
    PROP_RANDOM,
    N_PROPERTIES
};
static GParamSpec *obj_properties[N_PROPERTIES] = { NULL };

static void
ipc_backend_dbus_set_property (GObject      *object,
                               guint         property_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
    IpcBackendDbus *self = IPC_BACKEND_DBUS (object);

    switch (property_id) {
    case PROP_BUS_NAME:
        self->bus_name = g_value_dup_string (value);
        g_debug ("IpcBackendDbus set bus_name: %s", self->bus_name);
        break;
    case PROP_BUS_TYPE:
        self->bus_type = g_value_get_int (value);
        break;
    case PROP_CONNECTION_MANAGER:
        self->connection_manager = g_value_get_object (value);
        g_object_ref (self->connection_manager);
    case PROP_MAX_TRANS:
        self->max_transient_objects = g_value_get_uint (value);
        break;
    case PROP_RANDOM:
        self->random = g_value_get_object (value);
        g_object_ref (self->random);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}
static void
ipc_backend_dbus_get_property (GObject    *object,
                               guint       property_id,
                               GValue     *value,
                               GParamSpec *pspec)
{
    IpcBackendDbus *self = IPC_BACKEND_DBUS (object);

    switch (property_id) {
    case PROP_BUS_NAME:
        g_value_set_string (value, self->bus_name);
        break;
    case PROP_BUS_TYPE:
        g_value_set_int (value, self->bus_type);
        break;
    case PROP_CONNECTION_MANAGER:
        g_value_set_object (value, self->connection_manager);
        break;
    case PROP_MAX_TRANS:
        g_value_set_uint (value, self->max_transient_objects);
        break;
    case PROP_RANDOM:
        g_value_set_object (value, self->random);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}
static void
ipc_backend_dbus_init (IpcBackendDbus *self)
{ /* n00p */ }
/*
 * Dispose method where where we free up references to other objects.
 */
static void
ipc_backend_dbus_dispose (GObject *obj)
{
    IpcBackendDbus *self = IPC_BACKEND_DBUS (obj);

    g_clear_object (&self->connection_manager);
    g_clear_object (&self->random);
    g_clear_object (&self->skeleton);
    if (ipc_backend_dbus_parent_class != NULL) {
        G_OBJECT_CLASS (ipc_backend_dbus_parent_class)->dispose (obj);
    }
}
/*
 * Finalize method where we free resources.
 */
static void
ipc_backend_dbus_finalize (GObject *obj)
{
    IpcBackendDbus *self = IPC_BACKEND_DBUS (obj);

    if (self->bus_name != NULL) {
        g_free (self->bus_name);
    }
    if (ipc_backend_dbus_parent_class != NULL) {
        G_OBJECT_CLASS (ipc_backend_dbus_parent_class)->finalize (obj);
    }
}

static void
ipc_backend_dbus_class_init (IpcBackendDbusClass *klass)
{
    GObjectClass    *object_class      = G_OBJECT_CLASS (klass);
    IpcBackendClass *ipc_backend_class = IPC_BACKEND_CLASS (klass);

    if (ipc_backend_dbus_parent_class == NULL)
        ipc_backend_dbus_parent_class = g_type_class_peek_parent (klass);
    /* GObject functions */
    object_class->dispose      = ipc_backend_dbus_dispose;
    object_class->finalize     = ipc_backend_dbus_finalize;
    object_class->get_property = ipc_backend_dbus_get_property;
    object_class->set_property = ipc_backend_dbus_set_property;
    /* IpcBackend functions */
    ipc_backend_class->connect    = (IpcBackendConnect)ipc_backend_dbus_connect;
    ipc_backend_class->disconnect = (IpcBackendDisconnect)ipc_backend_dbus_disconnect;
    obj_properties [PROP_BUS_NAME] =
        g_param_spec_string ("bus-name",
                             "Bus name",
                             "GIO Bus name",
                             IPC_BACKEND_DBUS_NAME_DEFAULT,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    obj_properties [PROP_BUS_TYPE] =
        g_param_spec_int ("bus-type",
                          "Bus type",
                          "GIO Bus type",
                          G_BUS_TYPE_STARTER,
                          G_BUS_TYPE_SESSION,
                          IPC_BACKEND_DBUS_TYPE_DEFAULT,
                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    obj_properties [PROP_CONNECTION_MANAGER] =
        g_param_spec_object ("connection-manager",
                             "ConnectionManager object",
                             "ConnectionManager object for connection",
                             TYPE_CONNECTION_MANAGER,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    obj_properties [PROP_MAX_TRANS] =
        g_param_spec_uint ("max-trans",
                          "maximum transient objects",
                          "maximum number of transient objects for the handle map",
                          1,
                          MAX_TRANSIENT_OBJECTS,
                          MAX_TRANSIENT_OBJECTS_DEFAULT,
                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    obj_properties [PROP_RANDOM] =
        g_param_spec_object ("random",
                             "Random object",
                             "Source of random numbers.",
                             TYPE_RANDOM,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_properties (object_class,
                                       N_PROPERTIES,
                                       obj_properties);
}

IpcBackendDbus*
ipc_backend_dbus_new (GBusType           bus_type,
                      gchar const       *bus_name,
                      ConnectionManager *connection_manager,
                      guint              max_trans,
                      Random            *random)
{
    GObject *object = NULL;

    object = g_object_new (TYPE_IPC_BACKEND_DBUS,
                           "bus-name",           bus_name,
                           "bus-type",           bus_type,
                           "connection-manager", connection_manager,
                           "max-trans",          max_trans,
                           "random",             random,
                           NULL);
    return IPC_BACKEND_DBUS (object);
}
/* TabrmdSkeleton signal handlers */
/*
 * This is a utility function that builds an array of handles as a
 * GVariant object. The handles that make up the array are passed in
 * as a GUnixFDList.
 */
static GVariant*
handle_array_variant_from_fdlist (GUnixFDList *fdlist)
{
    GVariant *tuple;
    GVariantBuilder *builder;
    gint i = 0;

    /* build array of handles as GVariant */
    builder = g_variant_builder_new (G_VARIANT_TYPE ("ah"));
    for (i = 0; i < g_unix_fd_list_get_length (fdlist); ++i)
        g_variant_builder_add (builder, "h", i);
    /* create tuple variant from builder */
    tuple = g_variant_new ("ah", builder);
    g_variant_builder_unref (builder);

    return tuple;
}
/*
 * Give this function a dbus proxy and invocation object from a method
 * invocation and it will get the PID of the process associated with the
 * invocation. If an error occurs this function returns false.
 */
static gboolean
get_pid_from_dbus_invocation (GDBusProxy            *proxy,
                              GDBusMethodInvocation *invocation,
                              guint32               *pid)
{
    const gchar *name   = NULL;
    GError      *error  = NULL;
    GVariant    *result = NULL;

    if (proxy == NULL || invocation == NULL || pid == NULL)
        return FALSE;

    name = g_dbus_method_invocation_get_sender (invocation);
    result = g_dbus_proxy_call_sync (G_DBUS_PROXY (proxy),
                                     "GetConnectionUnixProcessID",
                                     g_variant_new("(s)", name),
                                     G_DBUS_CALL_FLAGS_NONE,
                                     -1,
                                     NULL,
                                     &error);
    if (error) {
        g_error ("Unable to get PID for %s: %s", name, error->message);
        g_error_free (error);
        error = NULL;
        return FALSE;
    } else {
        g_variant_get (result, "(u)", pid);
        g_variant_unref (result);
        return TRUE;
    }
}
/*
 * Generate a random uint64 returned in the id out paramter.
 * Mix this random ID with the PID from the caller. This is obtained
 * through the invocation parameter. Mix the two together using xor and
 * return the result through the id_pid_mix out parameter.
 * NOTE: if an error occurs then a response is sent through the invocation
 * to the client and FALSE is returned to the caller.
 *
 * Returns FALSE on error, TRUE otherwise.
 */
static gboolean
generate_id_pid_mix_from_invocation (IpcBackendDbus        *self,
                                     GDBusMethodInvocation *invocation,
                                     guint64               *id,
                                     guint64               *id_pid_mix)
{
    gboolean pid_ret = FALSE;
    guint32  pid = 0;

    pid_ret = get_pid_from_dbus_invocation (self->dbus_daemon_proxy,
                                            invocation,
                                            &pid);
    if (pid_ret == TRUE) {
        *id = random_get_uint64 (self->random);
        *id_pid_mix = *id ^ pid;
    } else {
        g_dbus_method_invocation_return_error (invocation,
                                               TABRMD_ERROR,
                                               TABRMD_ERROR_INTERNAL,
                                               "Failed to get client PID");
    }

    return pid_ret;
}
/*
 * Mix PID into provide id. Returns mixed value in id_pid_mix out parameter.
 * NOTE: if an error occurs then an error response is sent through the
 * invocation to the client and FALSE is returned to the caller
 *
 * Returns FALSE on error, TRUE otherwise.
 */
static gboolean
get_id_pid_mix_from_invocation (GDBusProxy            *proxy,
                                GDBusMethodInvocation *invocation,
                                guint64                id,
                                guint64               *id_pid_mix)
{
    guint32 pid = 0;
    gboolean pid_ret = FALSE;

    g_debug ("get_id_pid_mix_from_invocation");
    pid_ret = get_pid_from_dbus_invocation (proxy,
                                            invocation,
                                            &pid);
    g_debug ("id 0x%" PRIx64 " pid: 0x%" PRIx32, id, pid);
    if (pid_ret == TRUE) {
        *id_pid_mix = id ^ pid;
        g_debug ("mixed: 0x%" PRIx64, *id_pid_mix);
    } else {
        g_dbus_method_invocation_return_error (
            invocation,
            TABRMD_ERROR,
            TABRMD_ERROR_INTERNAL,
            "Failed to get client PID");
    }

    return pid_ret;
}
/*
 * This is a signal handler for the handle-create-connection signal from
 * the Tpm2AccessBroker DBus interface. This signal is triggered by a
 * request from a client to create a new connection with the tabrmd. This
 * requires a few things be done:
 * - Create a new ID (uint64) for the connection.
 * - Create a new Connection object getting the FDs that must be returned
 *   to the client.
 * - Build up a dbus response to the client with their connection ID and
 *   send / receive FDs.
 * - Send the response message back to the client.
 * - Insert the new Connection object into the ConnectionManager.
 * - Notify the CommandSource of the new Connection that it needs to
 *   watch by writing a magic value to the wakeup_send_fd.
 */
static gboolean
on_handle_create_connection (TctiTabrmd            *skeleton,
                             GDBusMethodInvocation *invocation,
                             gpointer               user_data)
{
    IpcBackendDbus *self = NULL;
    HandleMap   *handle_map = NULL;
    Connection *connection = NULL;
    gint client_fds[2] = { 0, 0 }, ret = 0;
    GVariant *response_variants[2], *response_tuple;
    GUnixFDList *fd_list = NULL;
    guint64 id = 0, id_pid_mix = 0;
    gboolean id_ret = FALSE;

    self = IPC_BACKEND_DBUS (user_data);
    ipc_backend_init_guard (IPC_BACKEND (user_data));
    if (connection_manager_is_full (self->connection_manager)) {
        g_dbus_method_invocation_return_error (invocation,
                                               TABRMD_ERROR,
                                               TABRMD_ERROR_MAX_CONNECTIONS,
                                               "MAX_COMMANDS exceeded. Try again later.");
        return TRUE;
    }
    id_ret = generate_id_pid_mix_from_invocation (self,
                                                  invocation,
                                                  &id,
                                                  &id_pid_mix);
    /* error already returned to caller over dbus */
    if (id_ret == FALSE) {
        return TRUE;
    }
    g_debug ("Creating connection with id: 0x%" PRIx64, id_pid_mix);
    if (connection_manager_contains_id (self->connection_manager,
                                        id_pid_mix)) {
        g_warning ("ID collision in ConnectionManager: %" PRIu64, id_pid_mix);
        g_dbus_method_invocation_return_error (
            invocation,
            TABRMD_ERROR,
            TABRMD_ERROR_ID_GENERATION,
            "Failed to allocate connection ID. Try again later.");
        return TRUE;
    }
    handle_map = handle_map_new (TPM_HT_TRANSIENT, self->max_transient_objects);
    if (handle_map == NULL)
        g_error ("Failed to allocate new HandleMap");
    connection = connection_new (&client_fds[0], &client_fds[1], id_pid_mix, handle_map);
    g_object_unref (handle_map);
    if (connection == NULL)
        g_error ("Failed to allocate new connection.");
    g_debug ("Created connection with fds: %d, %d and id: 0x%" PRIx64,
             client_fds[0], client_fds[1], id_pid_mix);
    /* prepare tuple variant for response message */
    fd_list = g_unix_fd_list_new_from_array (client_fds, 2);
    response_variants[0] = handle_array_variant_from_fdlist (fd_list);
    /* return the random id to client, *not* xor'd with PID */
    response_variants[1] = g_variant_new_uint64 (id);
    response_tuple = g_variant_new_tuple (response_variants, 2);
    /*
     * Issue the callback to notify subscribers that a new connection has
     * been created.
     */
    ret = connection_manager_insert (self->connection_manager, connection);
    if (ret != 0) {
        g_warning ("Failed to add new connection to connection_manager.");
    }
    /* send response */
    g_dbus_method_invocation_return_value_with_unix_fd_list (
        invocation,
        response_tuple,
        fd_list);
    g_object_unref (fd_list);
    g_object_unref (connection);

    return TRUE;
}
/*
 * This is a signal handler for the Cancel event emitted by the
 * Tpm2AcessBroker. It is invoked by a signal generated by a user
 * requesting that an outstanding TPM command should be canceled. It is
 * registered with the Tabrmd in response to acquiring a name
 * on the dbus (on_name_acquired). It does X things:
 * - Locate the Connection object associted with the 'id' parameter in
 *   the ConnectionManager.
 * - If the connection has a command being processed by the tabrmd then it's
 *   removed from the processing queue.
 * - If the connection has a command being processed by the TPM then the
 *   request to cancel the command will be sent down to the TPM.
 * - If the connection has no commands outstanding then an error is
 *   returned.
 */
static gboolean
on_handle_cancel (TctiTabrmd           *skeleton,
                  GDBusMethodInvocation *invocation,
                  gint64                 id,
                  gpointer               user_data)
{
    IpcBackendDbus *self = IPC_BACKEND_DBUS (user_data);
    Connection *connection = NULL;
    guint64   id_pid_mix = 0;
    gboolean mix_ret = FALSE;

    g_info ("on_handle_cancel for id 0x%" PRIx64, id);
    ipc_backend_init_guard (IPC_BACKEND (self));
    mix_ret = get_id_pid_mix_from_invocation (self->dbus_daemon_proxy,
                                              invocation,
                                              id,
                                              &id_pid_mix);
    /* error already sent over dbus */
    if (mix_ret == FALSE) {
        return TRUE;
    }
    connection = connection_manager_lookup_id (self->connection_manager,
                                               id_pid_mix);
    if (connection == NULL) {
        g_warning ("no active connection for id_pid_mix: 0x%" PRIx64,
                   id_pid_mix);
        g_dbus_method_invocation_return_error (invocation,
                                               TABRMD_ERROR,
                                               TABRMD_ERROR_NOT_PERMITTED,
                                               "No connection.");
        return TRUE;
    }
    g_info ("canceling command for connection 0x%" PRIxPTR " with "
            "id_pid_mix: 0x%" PRIx64, (uintptr_t)connection, id_pid_mix);
    /* cancel any existing commands for the connection */
    g_dbus_method_invocation_return_error (invocation,
                                           TABRMD_ERROR,
                                           TABRMD_ERROR_NOT_IMPLEMENTED,
                                           "Cancel function not implemented.");
    g_object_unref (connection);

    return TRUE;
}
/*
 * This is a signal handler for the handle-set-locality signal from the
 * Tabrmd DBus interface. This signal is triggered by a request
 * from a client to set the locality for TPM commands associated with the
 * connection (the 'id' parameter). This requires a few things be done:
 * - Find the Connection object associated with the 'id' parameter.
 * - Set the locality for the Connection object.
 * - Pass result of the operation back to the user.
 */
static gboolean
on_handle_set_locality (TctiTabrmd            *skeleton,
                        GDBusMethodInvocation *invocation,
                        gint64                 id,
                        guint8                 locality,
                        gpointer               user_data)
{
    IpcBackendDbus *self = IPC_BACKEND_DBUS (user_data);
    Connection *connection = NULL;
    guint64   id_pid_mix = 0;
    gboolean mix_ret = FALSE;

    g_info ("on_handle_set_locality for id 0x%" PRIx64, id);
    ipc_backend_init_guard (IPC_BACKEND (self));
    mix_ret = get_id_pid_mix_from_invocation (self->dbus_daemon_proxy,
                                              invocation,
                                              id,
                                              &id_pid_mix);
    /* error already sent over dbus */
    if (mix_ret == FALSE) {
        return TRUE;
    }
    connection = connection_manager_lookup_id (self->connection_manager,
                                               id_pid_mix);
    if (connection == NULL) {
        g_warning ("no active connection for id_pid_mix: 0x%" PRIx64,
                   id_pid_mix);
        g_dbus_method_invocation_return_error (invocation,
                                               TABRMD_ERROR,
                                               TABRMD_ERROR_NOT_PERMITTED,
                                               "No connection.");
        return TRUE;
    }
    g_info ("setting locality for connection 0x%" PRIxPTR " with "
            "id_pid_mix: 0x%" PRIx64 " to: %" PRIx8,
            (uintptr_t)connection, id_pid_mix, locality);
    /* set locality for an existing connection */
    g_dbus_method_invocation_return_error (invocation,
                                           TABRMD_ERROR,
                                           TABRMD_ERROR_NOT_IMPLEMENTED,
                                           "setLocality function not implemented.");
    g_object_unref (connection);

    return TRUE;
}
/* D-Bus signal handlers */
/*
 * This is a signal handler of type GBusAcquiredCallback. It is registered
 * by the g_bus_own_name function and invoked then a connectiont to a bus
 * is acquired in response to a request for the parameter 'name'.
 */
static void
on_bus_acquired (GDBusConnection *connection,
                 const gchar     *name,
                 gpointer         user_data)
{
    g_info ("on_bus_acquired: %s", name);
}
/*
 * This is a signal handler of type GBusNameAcquiredCallback. It is
 * registered by the g_bus_own_name function and invoked when the parameter
 * 'name' is acquired on the requested bus. It does 3 things:
 * - Obtains a new TctiTabrmd instance and stores a reference in
 *   the 'user_data' parameter (which is a reference to the gmain_data_t.
 * - Register signal handlers for the CreateConnection, Cancel and
 *   SetLocality signals.
 * - Export the TctiTabrmd interface (skeleton) on the DBus
 *   connection.
 */
static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
    g_info ("on_name_acquired: %s", name);
    IpcBackendDbus *self = NULL;
    GError *error = NULL;
    gboolean ret;

    if (user_data == NULL)
        g_error ("bus_acquired but user_data is NULL");
    self = IPC_BACKEND_DBUS (user_data);
    if (self->skeleton == NULL)
        self->skeleton = tcti_tabrmd_skeleton_new ();
    g_signal_connect (self->skeleton,
                      "handle-create-connection",
                      G_CALLBACK (on_handle_create_connection),
                      user_data);
    g_signal_connect (self->skeleton,
                      "handle-cancel",
                      G_CALLBACK (on_handle_cancel),
                      user_data);
    g_signal_connect (self->skeleton,
                      "handle-set-locality",
                      G_CALLBACK (on_handle_set_locality),
                      user_data);
    ret = g_dbus_interface_skeleton_export (
        G_DBUS_INTERFACE_SKELETON (self->skeleton),
        connection,
        TABRMD_DBUS_PATH,
        &error);
    if (ret == FALSE)
        g_warning ("failed to export interface: %s", error->message);
}
/*
 * This is a signal handler of type GBusNameLostCallback. It is
 * registered with the g_dbus_own_name function and is invoked when the
 * parameter 'name' is lost on the requested bus. This signal is propagated
 * to any subscribers through the IpcBackend 'disconnected' signal.
 */
static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         user_data)
{
    g_info ("on_name_lost: %s", name);
    IpcBackend *ipc_backend = IPC_BACKEND (user_data);

    ipc_backend_disconnected_invoke (ipc_backend);
}
/*
 * Callback handling the acquisition of a GDBusProxy object for communication
 * with the well known org.freedesktop.DBus object. This is an object exposed
 * by the dbus daemon.
 */
static void
on_get_dbus_daemon_proxy (GObject      *source_object,
                          GAsyncResult *result,
                          gpointer      user_data)
{
    GError *error = NULL;
    IpcBackendDbus *self = IPC_BACKEND_DBUS (user_data);

    self->dbus_daemon_proxy = g_dbus_proxy_new_finish (result, &error);
    if (error) {
        g_warning ("Failed to get proxy for DBus daemon "
                   "(org.freedesktop.DBus): %s", error->message);
        g_error_free (error);
        self->dbus_daemon_proxy = NULL;
    } else {
        g_debug ("Got proxy object for DBus daemon.");
    }
}
/*
 * This function overrides the ipc_backend_connect function from the
 * IpcBackend base class. It causes the IpcBackendDbus object to connect
 * to the D-Bus instance provided in the constructor while claiming the name
 * provided in the same.
 * This function registers several callbacks with the GDbus machinery. A
 * reference to the IpcBackendDbus parameter (self) is passed as data to
 * these callbacks.
 */
void
ipc_backend_dbus_connect (IpcBackendDbus *self,
                          GMutex         *init_mutex)
{
    IpcBackend *backend = IPC_BACKEND (self);
    g_return_if_fail (IS_IPC_BACKEND_DBUS (self));

    backend->init_mutex = init_mutex;
    self->dbus_name_owner_id = g_bus_own_name (self->bus_type,
                                               self->bus_name,
                                               G_BUS_NAME_OWNER_FLAGS_NONE,
                                               on_bus_acquired,
                                               on_name_acquired,
                                               on_name_lost,
                                               self,
                                               NULL);
    g_dbus_proxy_new_for_bus (self->bus_type,
                              G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
                              NULL,
                              "org.freedesktop.DBus",
                              "/org/freedesktop/DBus",
                              "org.freedesktop.DBus",
                              NULL,
                              (GAsyncReadyCallback)on_get_dbus_daemon_proxy,
                              self);
}
/*
 * This function overrides the ipc_backend_disconnect function from the
 * IpcBackend base class. When successfully disconnected this object will
 * emit the 'disconnected' signal.
 */
void
ipc_backend_dbus_disconnect (IpcBackendDbus *self)
{
    g_bus_unown_name (self->dbus_name_owner_id);
    IPC_BACKEND (self)->init_mutex = NULL;
}
