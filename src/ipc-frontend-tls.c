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

#include <inttypes.h>

#include "ipc-frontend-tls.h"
#include "tabrmd.h"
#include "util.h"

G_DEFINE_TYPE (IpcFrontendTls, ipc_frontend_tls, TYPE_IPC_FRONTEND);

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
ipc_frontend_tls_set_property (GObject      *object,
                               guint         property_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
    IpcFrontendTls *self = IPC_FRONTEND_TLS (object);

    switch (property_id) {
    case PROP_SOCKET_IP:
        self->socket_ip = g_value_dup_string (value);
        g_debug ("IpcFrontendTls set socket_ip: %s", self->socket_ip);
        break;
    case PROP_SOCKET_PORT:
        self->socket_port = g_value_get_uint (value);
        g_debug ("IpcFrontendTls set socket_port: %d", self->socket_port);
        break;
    case PROP_CONNECTION_MANAGER:
        self->connection_manager = g_value_get_object (value);
        g_object_ref (self->connection_manager);
        break;
    case PROP_MAX_TRANS:
        self->max_transient_objects = g_value_get_uint (value);
        break;
    case PROP_TLS_CERT:
        self->tls_cert = g_value_dup_object (value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}
static void
ipc_frontend_tls_get_property (GObject    *object,
                               guint       property_id,
                               GValue     *value,
                               GParamSpec *pspec)
{
    IpcFrontendTls *self = IPC_FRONTEND_TLS (object);

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
ipc_frontend_tls_init (IpcFrontendTls *self)
{ /* noop */ }
/*
 * Dispose method where where we free up references to other objects.
 */
static void
ipc_frontend_tls_dispose (GObject *obj)
{
    IpcFrontendTls *self = IPC_FRONTEND_TLS (obj);

    g_clear_object (&self->connection_manager);
    g_clear_object (&self->tls_cert);
    G_OBJECT_CLASS (ipc_frontend_tls_parent_class)->dispose (obj);
}
/*
 * Finalize method where we free resources.
 */
static void
ipc_frontend_tls_finalize (GObject *obj)
{
    IpcFrontendTls *self = IPC_FRONTEND_TLS (obj);

    g_clear_pointer (&self->socket_ip, g_free);
    G_OBJECT_CLASS (ipc_frontend_tls_parent_class)->finalize (obj);
}

static void
ipc_frontend_tls_class_init (IpcFrontendTlsClass *klass)
{
    GObjectClass    *object_class      = G_OBJECT_CLASS (klass);
    IpcFrontendClass *ipc_frontend_class = IPC_FRONTEND_CLASS (klass);

    if (ipc_frontend_tls_parent_class == NULL)
        ipc_frontend_tls_parent_class = g_type_class_peek_parent (klass);
    /* GObject functions */
    object_class->dispose      = ipc_frontend_tls_dispose;
    object_class->finalize     = ipc_frontend_tls_finalize;
    object_class->get_property = ipc_frontend_tls_get_property;
    object_class->set_property = ipc_frontend_tls_set_property;
    /* IpcFrontend functions */
    ipc_frontend_class->connect    = (IpcFrontendConnect)ipc_frontend_tls_connect;
    ipc_frontend_class->disconnect = (IpcFrontendDisconnect)ipc_frontend_tls_disconnect;
    obj_properties [PROP_SOCKET_IP] =
        g_param_spec_string ("socket-ip",
                             "Socket IP",
                             "Socket IP address",
                             IPC_FRONTEND_SOCKET_IP_DEFAULT,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    obj_properties [PROP_SOCKET_PORT] =
        g_param_spec_uint ("socket-port",
                           "Socket port",
                           "Socket port",
                           1,
                           65535,
                           IPC_FRONTEND_SOCKET_PORT_DEFAULT,
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
                           TABRMD_TRANSIENT_MAX,
                           TABRMD_TRANSIENT_MAX_DEFAULT,
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

IpcFrontendTls*
ipc_frontend_tls_new (const gchar       *socket_ip,
                      guint              socket_port,
                      ConnectionManager *connection_manager,
                      guint              max_trans,
                      const gchar       *cert_file)
{
    GObject *object = NULL;
    GTlsCertificate *tls_cert = NULL;
    GError *error = NULL;

    if (cert_file) {
        tls_cert = g_tls_certificate_new_from_file (cert_file, &error);
        if (!tls_cert) {
            g_warning ("Could not read server certificate '%s': %s",
                       cert_file, error->message);
            g_error_free (error);
            return NULL;
        }
     }

    object = g_object_new (TYPE_IPC_FRONTEND_TLS,
                           "socket-ip",          socket_ip,
                           "socket-port",        socket_port,
                           "connection-manager", connection_manager,
                           "max-trans",          max_trans,
                           "tls-cert",           tls_cert,
                           NULL);
    return IPC_FRONTEND_TLS (object);
}

/*
 * Give this function a local GSocket and it will get the GsocketAddress
 * of the remote side. A sring concatenating ip address and port is used
 * as the name of the remote side. If an error occurs this function
 * returns false.
 */
static gboolean
get_remote_name (GSocket *socket, gchar **name)
{
    GSocketAddress *address;
    GError *error  = NULL;

    if (!socket)
        return FALSE;

    address = g_socket_get_remote_address (socket, &error);
    if (!address) {
        g_warning ("Error getting remote address: %s", error->message);
        g_error_free (error);
        return FALSE;
    }
    *name = socket_address_to_string (address);
    g_object_unref (address);

    return TRUE;
}

/*
 * Generate an ID based on the ip address and port.
 * In fact the ID is only 32-bit length due to the
 * limit of the hash function.
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
        g_warning ("Failed to generate ID");
    }

    return ret;
}

/*
 * This is a signal handler for the G_IO_IN event from a listening
 * socket. This signal is triggered by a request from a client to
 * create a new connection with the tabrmd via the TLS machinery.
 * This requires a few things be done:
 * - Create a new socket for the request.
 * - Set some options on the socket and maybe convert it
 *   to a TLS connection.
 * - Create a new ID (uint64) for the connection.
 * - Create a new Connection object.
 * - Insert the new Connection object into the ConnectionManager.
 */
static gboolean
on_handle_create_connection (GPollableInputStream *istream,
                             guint events,
                             gpointer user_data)
{
    IpcFrontendTls *self = NULL;
    GSocket *socket = NULL;
    HandleMap *handle_map = NULL;
    Connection *connection = NULL;
    GCancellable *cancellable = NULL;
    gchar *remote_name;
    GIOStream *stream, *tls_stream;
    GError *error = NULL;
    guint64 id = 0;
    gint ret = 0;

    self = IPC_FRONTEND_TLS (user_data);
    ipc_frontend_init_guard (IPC_FRONTEND (user_data));
    if (connection_manager_is_full (self->connection_manager)) {
        g_warning ("MAX_COMMANDS exceeded and try again later.");
        return TRUE;
    }

    socket = g_socket_accept (self->socket, cancellable, &error);
    if (!socket) {
        g_warning ("Error accepting socket: %s", error->message);
        g_error_free (error);
        return FALSE;
    }

    g_socket_set_blocking (socket, FALSE);
    g_socket_set_timeout (socket, IPC_FRONTEND_SOCKET_TIME_OUT_DEFAULT);

    if (!get_remote_name(socket, &remote_name)) {
        g_warning ("Error getting remote name");
        g_object_unref (socket);
        return FALSE;
    }
    g_debug ("Get a new connection from %s", remote_name);
    g_free (remote_name);

    stream = G_IO_STREAM (g_socket_connection_factory_create_connection (socket));
    if (!stream) {
        g_warning ("Could not create TCP connection");
        g_object_unref (socket);
        return FALSE;
    }

    if (!generate_id (socket, &id)) {
        g_object_unref (socket);
        g_object_unref (stream);
        return FALSE;
    }
    g_object_unref (socket);

    if (self->tls_cert) {
        tls_stream = g_tls_server_connection_new (stream, self->tls_cert, &error);
        if (!tls_stream) {
            g_warning ("Could not create TLS connection: %s", error->message);
            g_object_unref (stream);
            g_error_free (error);
            return FALSE;
        }
        g_object_unref (stream);

        if (!g_tls_connection_handshake (G_TLS_CONNECTION (tls_stream),
                                         cancellable, &error)) {
            g_warning ("Error during TLS handshake: %s", error->message);
            g_object_unref (tls_stream);
            g_error_free (error);
            return FALSE;
        }

        stream = tls_stream;
    }

    g_debug ("Creating connection with id: 0x%" PRIx64, id);
    if (connection_manager_contains_id (self->connection_manager, id)) {
        g_warning ("ID collision in ConnectionManager: %" PRIu64, id);
        g_object_unref (stream);
        return FALSE;
    }
    handle_map = handle_map_new (TPM2_HT_TRANSIENT, self->max_transient_objects);
    if (!handle_map) {
        g_warning ("Failed to allocate new HandleMap");
        g_object_unref (stream);
        return FALSE;
    }
    connection = connection_new (stream, id, handle_map);
    if (!connection) {
        g_warning ("Failed to allocate new connection");
        g_object_unref (handle_map);
        g_object_unref (stream);
        return FALSE;
    }
    g_object_unref (handle_map);
    g_object_unref (stream);
    /*
     * Issue the callfront to notify subscribers that a new connection has
     * been created.
     */
    ret = connection_manager_insert (self->connection_manager, connection);
    if (ret) {
        g_warning ("Failed to add new connection to connection_manager");
        g_object_unref (connection);
        return FALSE;
    }

    g_object_unref (connection);

    return TRUE;
}
/*
 * This function is used to create a listening socket.
 */
static GSocket*
create_listen_socket(gchar *ip, guint port)
{
    GSocket *socket;
    GSocketAddress *address;
    GSocketType socket_type = G_SOCKET_TYPE_STREAM;
    GSocketFamily socket_family;
    GError *error = NULL;

    /* parse ip addr to get the family of socket */
    socket_family = check_ipstring_family (ip);

    /* Create a listening socket with specified IP address and TCP port. */
    socket = g_socket_new (socket_family, socket_type, 0, &error);
    if (socket == NULL) {
        g_warning ("Can't create socket: %s", error->message);
        g_error_free (error);
        return NULL;
    }

    g_socket_set_blocking (socket, FALSE);

    address = g_inet_socket_address_new_from_string (ip, port);
    if (!g_socket_bind (socket, address, TRUE, &error)) {
        g_warning ("Can't bind socket: %s", error->message);
        g_error_free (error);
        g_object_unref (socket);
        return NULL;
    }
    g_object_unref (address);

    if (!g_socket_listen (socket, &error)) {
        g_warning ("Can't listen on socket: %s", error->message);
        g_error_free (error);
        g_object_unref (socket);
        return NULL;
    }

    return socket;
}
/*
 * This function overrides the ipc_frontend_connect function from the
 * IpcFrontend base class. It creates a listening socket to monitor the
 * connection request from the clients.
 * This function registers a callback to the listening socket to handle
 * the G_IO_IN event.
 */
void
ipc_frontend_tls_connect (IpcFrontendTls *self,
                          GMutex         *init_mutex)
{
    GSource *source;
    GCancellable * cancellable = NULL;
    GIOCondition condition = G_IO_IN;

    IpcFrontend *frontend = IPC_FRONTEND (self);
    g_return_if_fail (IS_IPC_FRONTEND_TLS (self));

    frontend->init_mutex = init_mutex;

    self->socket = create_listen_socket(self->socket_ip, self->socket_port);
    if (!self->socket)
        g_error("Failed to create the TLS listening socket.");

    g_debug ("listening on %s, port  %d...", self->socket_ip, self->socket_port);

    /* register signal handler */
    source = g_socket_create_source (self->socket, condition, cancellable);
    g_source_set_callback (source, (GSourceFunc) on_handle_create_connection, self, NULL);
    g_source_attach (source, NULL);
    g_source_unref (source);
}
/*
 * This function overrides the ipc_frontend_disconnect function from the
 * IpcFrontend base class. When successfully disconnected this object will
 * emit the 'disconnected' signal.
 */
void
ipc_frontend_tls_disconnect (IpcFrontendTls *self)
{
    GError *error;

    IPC_FRONTEND (self)->init_mutex = NULL;
    /* close socket to stop accepting new connection */
    if (!g_socket_close (self->socket, &error)) {
        g_warning ("Error closing listening socket: %s", error->message);
        g_error_free (error);
    }
    g_clear_object (&self->socket);
}
