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

#include "ipc-backend-tls.h"
#include "tabrmd.h"
#include "util.h"

G_DEFINE_TYPE (IpcBackendTls, ipc_backend_tls, TYPE_IPC_BACKEND);
GSocket *tcti_tabrmd_server_new (const gchar *ip, guint port);

typedef enum {
    TABRMD_ERROR_INTERNAL         = TSS2_RESMGR_RC_INTERNAL_ERROR,
    TABRMD_ERROR_MAX_CONNECTIONS  = TSS2_RESMGR_RC_GENERAL_FAILURE,
    TABRMD_ERROR_ID_GENERATION    = TSS2_RESMGR_RC_GENERAL_FAILURE,
    TABRMD_ERROR_NOT_IMPLEMENTED  = TSS2_RESMGR_RC_NOT_IMPLEMENTED,
    TABRMD_ERROR_NOT_PERMITTED    = TSS2_RESMGR_RC_NOT_PERMITTED,
} TabrmdErrorEnum;

enum {
    PROP_0,
    PROP_SOCKET_IP,
    PROP_SOCKET_PORT,
    PROP_CONNECTION_MANAGER,
    PROP_MAX_TRANS,
    PROP_TLS_CERT,
    N_PROPERTIES
};
static GParamSpec *obj_properties[N_PROPERTIES] = { NULL };

static void
ipc_backend_tls_set_property (GObject      *object,
                               guint         property_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
    IpcBackendTls *self = IPC_BACKEND_TLS (object);

    switch (property_id) {
    case PROP_SOCKET_IP:
        self->socket_ip = g_value_dup_string (value);
        g_debug ("IpcBackendTls set socket_ip: %s", self->socket_ip);
        break;
    case PROP_SOCKET_PORT:
        self->socket_port = g_value_get_uint (value);
        break;
    case PROP_CONNECTION_MANAGER:
        self->connection_manager = g_value_get_object (value);
        g_object_ref (self->connection_manager);
        break;
    case PROP_MAX_TRANS:
        self->max_transient_objects = g_value_get_uint (value);
        break;
    case PROP_TLS_CERT:
        self->tls_cert = g_value_get_object (value);
        g_object_ref (self->tls_cert);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}
static void
ipc_backend_tls_get_property (GObject    *object,
                               guint       property_id,
                               GValue     *value,
                               GParamSpec *pspec)
{
    IpcBackendTls *self = IPC_BACKEND_TLS (object);

    switch (property_id) {
    case PROP_SOCKET_IP:
        g_value_set_string (value, self->socket_ip);
        break;
    case PROP_SOCKET_PORT:
        g_value_set_uint (value, self->socket_port);
        break;
    case PROP_CONNECTION_MANAGER:
        g_value_set_object (value, self->connection_manager);
        break;
    case PROP_MAX_TRANS:
        g_value_set_uint (value, self->max_transient_objects);
        break;
    case PROP_TLS_CERT:
        g_value_set_object (value, self->tls_cert);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}
static void
ipc_backend_tls_init (IpcBackendTls *self)
{ /* noop */ }
/*
 * Dispose method where where we free up references to other objects.
 */
static void
ipc_backend_tls_dispose (GObject *obj)
{
    IpcBackendTls *self = IPC_BACKEND_TLS (obj);

    g_clear_object (&self->connection_manager);
    g_clear_object (&self->tls_cert);
    if (ipc_backend_tls_parent_class != NULL) {
        G_OBJECT_CLASS (ipc_backend_tls_parent_class)->dispose (obj);
    }
}
/*
 * Finalize method where we free resources.
 */
static void
ipc_backend_tls_finalize (GObject *obj)
{
    IpcBackendTls *self = IPC_BACKEND_TLS (obj);

    if (self->socket_ip != NULL) {
        g_free (self->socket_ip);
    }
    if (ipc_backend_tls_parent_class != NULL) {
        G_OBJECT_CLASS (ipc_backend_tls_parent_class)->finalize (obj);
    }
}

static void
ipc_backend_tls_class_init (IpcBackendTlsClass *klass)
{
    GObjectClass    *object_class      = G_OBJECT_CLASS (klass);
    IpcBackendClass *ipc_backend_class = IPC_BACKEND_CLASS (klass);

    if (ipc_backend_tls_parent_class == NULL)
        ipc_backend_tls_parent_class = g_type_class_peek_parent (klass);
    /* GObject functions */
    object_class->dispose      = ipc_backend_tls_dispose;
    object_class->finalize     = ipc_backend_tls_finalize;
    object_class->get_property = ipc_backend_tls_get_property;
    object_class->set_property = ipc_backend_tls_set_property;
    /* IpcBackend functions */
    ipc_backend_class->connect    = (IpcBackendConnect)ipc_backend_tls_connect;
    ipc_backend_class->disconnect = (IpcBackendDisconnect)ipc_backend_tls_disconnect;
    obj_properties [PROP_SOCKET_IP] =
        g_param_spec_string ("socket-ip",
                             "Socket IP",
                             "Socket IP address",
                             IPC_BACKEND_SOCKET_IP_DEFAULT,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    obj_properties [PROP_SOCKET_PORT] =
        g_param_spec_uint ("socket-port",
                              "Socket port",
                              "Socket port",
                              1,
                              65535,
                              IPC_BACKEND_SOCKET_PORT_DEFAULT,
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
    obj_properties [PROP_TLS_CERT] =
        g_param_spec_object ("tls-cert",
                             "TLS certificate",
                             "TLS connection server side certificate",
                             G_TYPE_TLS_CERTIFICATE,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_properties (object_class,
                                       N_PROPERTIES,
                                       obj_properties);
}

IpcBackendTls*
ipc_backend_tls_new (const gchar     *socket_ip,
                      guint socket_port,
                      ConnectionManager *connection_manager,
                      guint              max_trans,
                      const gchar    *cert_file)
{
    GObject *object = NULL;
    GTlsCertificate *tls_cert = NULL;
    GError *err = NULL;

    tls_cert = g_tls_certificate_new_from_file (cert_file, &err);
    if (!tls_cert) {
        g_error ("Could not read server certificate '%s': %s",
                 cert_file, err->message);
        return NULL;
    }

    object = g_object_new (TYPE_IPC_BACKEND_TLS,
                           "socket-ip",           socket_ip,
                           "socket-port",           socket_port,
                           "connection-manager", connection_manager,
                           "max-trans",          max_trans,
                           "tls-cert",              tls_cert,
                           NULL);
    return IPC_BACKEND_TLS (object);
}

/*
 * Give this function a dbus proxy and invocation object from a method
 * invocation and it will get the PID of the process associated with the
 * invocation. If an error occurs this function returns false.
 */
static gboolean
get_remote_name (GSocket *socket, gchar **name)
{
    GSocketAddress *address;
    GError      *error  = NULL;

    if (!socket)
        return FALSE;

    address = g_socket_get_remote_address (socket, &error);
    if (!address) {
        g_error ("Error getting remote address: %s", error->message);
        return FALSE;
    }
    *name = socket_address_to_string (address);
    g_object_unref (address);

    return TRUE;
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
generate_id (GSocket *socket, guint64 *id)
{
    gchar *name;
    gboolean ret = FALSE;

    ret = get_remote_name (socket, &name);
    if (ret == TRUE) {
        *id = g_str_hash (name);
        g_free (name);
    } else {
        g_error ("Failed to generate ID");
    }

    return ret;
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
on_handle_create_connection (GPollableInputStream *stream,
                             guint events,
                             gpointer user_data)
{
    IpcBackendTls *self = NULL;
    GSocket *socket = NULL;
    HandleMap   *handle_map = NULL;
    Connection *connection = NULL;
    gint ret = 0;
    guint64 id = 0;
    gboolean ret_b = FALSE;

    GCancellable *cancellable = NULL;
    GError *error = NULL;
    gint timeout = 0;
    gchar *remote_name;
    GIOStream *conn, *tls_conn;
    gint fd = 0;

    self = IPC_BACKEND_TLS (user_data);
    ipc_backend_init_guard (IPC_BACKEND (user_data));
    if (connection_manager_is_full (self->connection_manager)) {
        g_warning ("MAX_COMMANDS exceeded. Try again later.");
        return TRUE;
    }

    socket = g_socket_accept (self->socket, cancellable, &error);
    if (!socket) {
        g_error ("Error accepting socket: %s", error->message);
        return FALSE;
    }

    g_socket_set_blocking (socket, FALSE);
    g_socket_set_timeout (socket, timeout);

    ret_b = get_remote_name(socket, &remote_name);
    if (!ret_b) {
        return FALSE;
    }
    g_debug ("got a new connection from %s", remote_name);
    g_free (remote_name);

    conn = G_IO_STREAM (g_socket_connection_factory_create_connection (socket));
    if (!conn) {
        g_error ("Could not create TCP connection");
        return FALSE;
    }

    if (self->tls_cert) {
        tls_conn = g_tls_server_connection_new (conn, self->tls_cert, &error);
        if (!tls_conn) {
            g_error ("Could not create TLS connection: %s", error->message);
            return FALSE;
        }

        if (!g_tls_connection_handshake (G_TLS_CONNECTION (tls_conn),
                                                     cancellable, &error)) {
            g_error ("Error during TLS handshake: %s", error->message);
            return FALSE;
        }

        g_object_unref (conn);
        conn = tls_conn;
    }

    ret_b = generate_id (socket, &id);
    /* error already returned to caller over dbus */
    if (ret_b == FALSE) {
        return TRUE;
    }
    g_debug ("Creating connection with id: 0x%" PRIx64, id);
    if (connection_manager_contains_id (self->connection_manager, id)) {
        g_warning ("ID collision in ConnectionManager: %" PRIu64, id);
        g_error ("Failed to allocate connection ID. Try again later.");
        return TRUE;
    }
    handle_map = handle_map_new (TPM_HT_TRANSIENT, self->max_transient_objects);
    if (handle_map == NULL)
        g_error ("Failed to allocate new HandleMap");
    fd = g_socket_get_fd (socket);
    connection = connection_new (&fd, &fd, id, handle_map, conn);
    if (connection == NULL)
        g_error ("Failed to allocate new connection.");
    g_debug ("Created connection with fds: %d, %d and id: 0x%" PRIx64,
             fd, fd, id);
    g_object_unref (handle_map);
    g_object_unref (socket);
    /*
     * Issue the callback to notify subscribers that a new connection has
     * been created.
     */
    ret = connection_manager_insert (self->connection_manager, connection);
    if (ret != 0) {
        g_warning ("Failed to add new connection to connection_manager.");
    }

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
on_handle_cancel (TctiTabrmd           *server,
                  gint64                 id,
                  gpointer               user_data)
{
    IpcBackendTls *self = IPC_BACKEND_TLS (user_data);
    Connection *connection = NULL;

    g_info ("on_handle_cancel for id 0x%" PRIx64, id);
    ipc_backend_init_guard (IPC_BACKEND (self));
    connection = connection_manager_lookup_id (self->connection_manager,
                                               id);
    if (connection == NULL) {
        g_warning ("no active connection for id: 0x%" PRIx64, id);
        g_error ("No connection.");
        return TRUE;
    }
    g_info ("canceling command for connection 0x%" PRIxPTR " with "
            "id: 0x%" PRIx64, (uintptr_t)connection, id);
    /* cancel any existing commands for the connection */
    g_error ("Cancel function not implemented.");
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
on_handle_set_locality (TctiTabrmd            *sever,
                        gint64                 id,
                        guint8                 locality,
                        gpointer               user_data)
{
    IpcBackendTls *self = IPC_BACKEND_TLS (user_data);
    Connection *connection = NULL;

    g_info ("on_handle_set_locality for id 0x%" PRIx64, id);
    ipc_backend_init_guard (IPC_BACKEND (self));
    connection = connection_manager_lookup_id (self->connection_manager,
                                               id);
    if (connection == NULL) {
        g_warning ("no active connection for id: 0x%" PRIx64,
                   id);
        g_error ("No connection.");
        return TRUE;
    }
    g_info ("setting locality for connection 0x%" PRIxPTR " with "
            "id: 0x%" PRIx64 " to: %" PRIx8,
            (uintptr_t)connection, id, locality);
    /* set locality for an existing connection */
    g_error ("setLocality function not implemented.");
    g_object_unref (connection);

    return TRUE;
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
ipc_backend_tls_connect (IpcBackendTls *self,
                          GMutex         *init_mutex)
{
    
    GSource *source;
    GCancellable * cancellable = NULL;
    GIOCondition condition = G_IO_IN;

    IpcBackend *backend = IPC_BACKEND (self);
    g_return_if_fail (IS_IPC_BACKEND_TLS (self));

    backend->init_mutex = init_mutex;
    /* Create a listening socket with specified IP address and TCP port. */
    self->socket = tcti_tabrmd_server_new (self->socket_ip, self->socket_port);
    if (self->socket)
        g_debug ("listening on %s, port  %d...", self->socket_ip, self->socket_port);
    else 
        return;

    /* register signal handler */
    source = g_socket_create_source (self->socket, condition, cancellable);
    g_source_set_callback (source, (GSourceFunc) on_handle_create_connection, self, NULL);
    g_source_attach (source, NULL);
    g_source_unref (source);

    if (0) {
        on_handle_cancel (NULL, 0, NULL);
        on_handle_set_locality (NULL, 0, 0, NULL);
    }
}
/*
 * This function overrides the ipc_backend_disconnect function from the
 * IpcBackend base class. When successfully disconnected this object will
 * emit the 'disconnected' signal.
 */
void
ipc_backend_tls_disconnect (IpcBackendTls *self)
{
    GError *err;

    IPC_BACKEND (self)->init_mutex = NULL;
    /* close socket to stop accepting new connection */
    if (!g_socket_close (self->socket, &err)) {
        g_error ("Error closing listening socket: %s", err->message);
    }
    /* need to move to dispose method ?? */
    g_clear_object (&self->socket);
}

GSocket *
tcti_tabrmd_server_new (const gchar *ip, guint port)
{
    GSocket *socket;
    GSocketAddress *address;
    GSocketType socket_type = G_SOCKET_TYPE_STREAM;
    GSocketFamily socket_family = G_SOCKET_FAMILY_IPV4;
    GError *error = NULL;

    socket = g_socket_new (socket_family, socket_type, 0, &error);
    if (socket == NULL) {
        g_error ("Can't create socket: %s", error->message);
    }
    g_socket_set_blocking (socket, FALSE);

    address = g_inet_socket_address_new_from_string (ip, port);
    if (!g_socket_bind (socket, address, TRUE, &error)) {
        g_error ("Can't bind socket: %s", error->message);
    }
    g_object_unref (address);

    if (!g_socket_listen (socket, &error)) {
        g_error ("Can't listen on socket: %s", error->message);
    }

    return socket;
}

