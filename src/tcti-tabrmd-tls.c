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
#include <gio/gunixfdlist.h>
#include <glib.h>
#include <inttypes.h>
#include <poll.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "tabrmd.h"
#include "tcti-tabrmd-tls.h"
#include "tcti-tabrmd-tls-priv.h"
#include "tpm2-header.h"
#include "util.h"

static TSS2_RC
tss2_tcti_tabrmd_tls_transmit (TSS2_TCTI_CONTEXT *context,
                               size_t             size,
                               const uint8_t     *command)
{
    GOutputStream *ostream;
    ssize_t write_ret;
    TSS2_RC tss2_ret = TSS2_RC_SUCCESS;

    g_debug ("tss2_tcti_tabrmd_tls_transmit");
    if (context == NULL || command == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    if (size == 0) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (TSS2_TCTI_MAGIC (context) != TSS2_TCTI_TABRMD_TLS_MAGIC ||
        TSS2_TCTI_VERSION (context) != TSS2_TCTI_TABRMD_TLS_VERSION) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    if (TSS2_TCTI_TABRMD_TLS_STATE (context) != TABRMD_TLS_STATE_TRANSMIT) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    g_debug_bytes (command, size, 16, 4);
    ostream = TSS2_TCTI_TABRMD_TLS_OSTREAM(context);
    g_debug ("blocking write on iostream: 0x%" PRIxPTR,
             (uintptr_t)ostream);
    write_ret = write_all (ostream, command, size);
    /* should switch on possible errors to translate to TSS2 error codes */
    switch (write_ret) {
    case -1:
        g_debug ("tss2_tcti_tabrmd_tls_transmit: error writing to pipe: %s",
                 strerror (errno));
        tss2_ret = TSS2_TCTI_RC_IO_ERROR;
        break;
    case 0:
        g_debug ("tss2_tcti_tabrmd_tls_transmit: EOF returned writing to pipe");
        tss2_ret = TSS2_TCTI_RC_NO_CONNECTION;
        break;
    default:
        if (write_ret == size) {
            TSS2_TCTI_TABRMD_TLS_STATE (context) = TABRMD_TLS_STATE_RECEIVE;
        } else {
            g_debug ("tss2_tcti_tabrmd_tls_transmit: short write");
            tss2_ret = TSS2_TCTI_RC_GENERAL_FAILURE;
        }
        break;
    }
    return tss2_ret;
}
/*
 * This function maps errno values to TCTI RCs.
 */
static TSS2_RC
errno_to_tcti_rc (int error_number)
{
    switch (error_number) {
    case -1:
        return TSS2_TCTI_RC_NO_CONNECTION;
    case 0:
        return TSS2_RC_SUCCESS;
    case EAGAIN:
#if EAGAIN != EWOULDBLOCK
    case EWOULDBLOCK:
#endif
        return TSS2_TCTI_RC_TRY_AGAIN;
    case EIO:
        return TSS2_TCTI_RC_IO_ERROR;
    default:
        g_debug ("mapping errno %d with message \"%s\" to "
                 "TSS2_TCTI_RC_GENERAL_FAILURE",
                 error_number, strerror (error_number));
        return TSS2_TCTI_RC_GENERAL_FAILURE;
    }
}
/*
 * This function maps GError code values to TCTI RCs.
 */
static TSS2_RC
gerror_code_to_tcti_rc (int error_number)
{
    switch (error_number) {
    case -1:
        return TSS2_TCTI_RC_NO_CONNECTION;
    case G_IO_ERROR_WOULD_BLOCK:
        return TSS2_TCTI_RC_TRY_AGAIN;
    case G_IO_ERROR_FAILED:
    case G_IO_ERROR_HOST_UNREACHABLE:
    case G_IO_ERROR_NETWORK_UNREACHABLE:
#if G_IO_ERROR_BROKEN_PIPE != G_IO_ERROR_CONNECTION_CLOSED
    case G_IO_ERROR_CONNECTION_CLOSED:
#endif
#if GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION >= 44
    case G_IO_ERROR_NOT_CONNECTED:
#endif
        return TSS2_TCTI_RC_IO_ERROR;
    default:
        g_debug ("mapping errno %d with message \"%s\" to "
                 "TSS2_TCTI_RC_GENERAL_FAILURE",
                 error_number, strerror (error_number));
        return TSS2_TCTI_RC_GENERAL_FAILURE;
    }
}
/*
 * This is a thin wrapper around a call to poll. It packages up the provided
 * file descriptor and timeout and polls on that same FD for data or a hangup.
 * Returns:
 *   -1 on timeout
 *   0 when data is ready
 *   errno on error
 */
static int
tcti_tabrmd_tls_poll (int        fd,
                      int32_t    timeout)
{
    struct pollfd pollfds [] = {
        {
            .fd = fd,
            .events = POLLIN | POLLPRI | POLLRDHUP,
        }
    };
    int ret;
    int errno_tmp;

    ret = TEMP_FAILURE_RETRY (poll (pollfds,
                                    sizeof (pollfds) / sizeof (struct pollfd),
                                    timeout));
    errno_tmp = errno;
    switch (ret) {
    case -1:
        g_debug ("poll produced error: %d, %s",
                 errno_tmp, strerror (errno_tmp));
        return errno_tmp;
    case 0:
        g_debug ("poll timed out after %" PRId32 " miniseconds", timeout);
        return -1;
    default:
        g_debug ("poll has %d fds ready", ret);
        if (pollfds[0].revents & POLLIN) {
            g_debug ("  POLLIN");
        }
        if (pollfds[0].revents & POLLPRI) {
            g_debug ("  POLLPRI");
        }
        if (pollfds[0].revents & POLLRDHUP) {
            g_debug ("  POLLRDHUP");
        }
        return 0;
    }
}
/*
 * This is the receive function that is exposed to clients through the TCTI
 * API.
 */
static TSS2_RC
tss2_tcti_tabrmd_tls_receive (TSS2_TCTI_CONTEXT *context,
                              size_t            *size,
                              uint8_t           *response,
                              int32_t            timeout)
{
    TSS2_TCTI_TABRMD_TLS_CONTEXT *tabrmd_ctx = (TSS2_TCTI_TABRMD_TLS_CONTEXT*)context;
    size_t ret = 0;

    g_debug ("tss2_tcti_tabrmd_tls_receive");
    if (context == NULL || size == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    if (response == NULL && *size != 0) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (TSS2_TCTI_MAGIC (context) != TSS2_TCTI_TABRMD_TLS_MAGIC ||
        TSS2_TCTI_VERSION (context) != TSS2_TCTI_TABRMD_TLS_VERSION) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    if (tabrmd_ctx->state != TABRMD_TLS_STATE_RECEIVE) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    if (timeout < TSS2_TCTI_TIMEOUT_BLOCK) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (size == NULL || (response == NULL && *size != 0)) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    /* response buffer must be at least as large as the header */
    if (response != NULL && *size < TPM_HEADER_SIZE) {
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }
    ret = tcti_tabrmd_tls_poll (TSS2_TCTI_TABRMD_TLS_FD (context), timeout);
    switch (ret) {
    case -1:
        return TSS2_TCTI_RC_TRY_AGAIN;
    case 0:
        break;
    default:
        return errno_to_tcti_rc (ret);
    }
    /* make sure we've got the response header */
    if (tabrmd_ctx->index < TPM_HEADER_SIZE) {
        ret = read_data (TSS2_TCTI_TABRMD_TLS_ISTREAM (context),
                         &tabrmd_ctx->index,
                         tabrmd_ctx->header_buf,
                         TPM_HEADER_SIZE - tabrmd_ctx->index);
        if (ret != 0) {
            return gerror_code_to_tcti_rc (ret);
        }
        if (tabrmd_ctx->index == TPM_HEADER_SIZE) {
            tabrmd_ctx->header.tag  = get_response_tag  (tabrmd_ctx->header_buf);
            tabrmd_ctx->header.size = get_response_size (tabrmd_ctx->header_buf);
            tabrmd_ctx->header.code = get_response_code (tabrmd_ctx->header_buf);
            if (tabrmd_ctx->header.size < TPM_HEADER_SIZE) {
                tabrmd_ctx->state = TABRMD_TLS_STATE_TRANSMIT;
                return TSS2_TCTI_RC_MALFORMED_RESPONSE;
            }
        }
    }
    /* if response is NULL, caller is querying size, we know size isn't NULL */
    if (response == NULL) {
        *size = tabrmd_ctx->header.size;
        return TSS2_RC_SUCCESS;
    } else if (tabrmd_ctx->index == TPM_HEADER_SIZE) {
        /* once we have the full header copy it to the callers buffer */
        memcpy (response, tabrmd_ctx->header_buf, TPM_HEADER_SIZE);
    }
    if (tabrmd_ctx->header.size == TPM_HEADER_SIZE) {
        tabrmd_ctx->index = 0;
        tabrmd_ctx->state = TABRMD_TLS_STATE_TRANSMIT;
        return TSS2_RC_SUCCESS;
    }
    if (*size < tabrmd_ctx->header.size) {
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }
    ret = read_data (TSS2_TCTI_TABRMD_TLS_ISTREAM (context),
                     &tabrmd_ctx->index,
                     response,
                     tabrmd_ctx->header.size - tabrmd_ctx->index);
    if (ret == 0) {
        /* We got all the bytes we asked for, reset the index & state: done */
        *size = tabrmd_ctx->index;
        tabrmd_ctx->index = 0;
        tabrmd_ctx->state = TABRMD_TLS_STATE_TRANSMIT;
    }
    return errno_to_tcti_rc (ret);
}

static void
tss2_tcti_tabrmd_tls_finalize (TSS2_TCTI_CONTEXT *context)
{
    GError *error = NULL;

    g_debug ("tss2_tcti_tabrmd_tls_finalize");
    if (context == NULL) {
        g_warning ("Invalid parameter");
        return;
    }

    TSS2_TCTI_TABRMD_TLS_STATE (context) = TABRMD_TLS_STATE_FINAL;
    if (!g_io_stream_close (TSS2_TCTI_TABRMD_TLS_IOSTREAM (context),
                            NULL, &error)) {
        g_warning ("Error closing connection stream: %s", error->message);
        g_error_free (error);
    }
    g_clear_object (&TSS2_TCTI_TABRMD_TLS_IOSTREAM (context));
    g_clear_object (&TSS2_TCTI_TABRMD_TLS_SOCKET (context));
}

static TSS2_RC
tss2_tcti_tabrmd_tls_cancel (TSS2_TCTI_CONTEXT *context)
{
    if (context == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    g_info("tss2_tcti_tabrmd_tls_cancel: id 0x%" PRIx64,
           TSS2_TCTI_TABRMD_TLS_ID (context));
    if (TSS2_TCTI_TABRMD_TLS_STATE (context) != TABRMD_TLS_STATE_RECEIVE) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }

    g_warning ("cancel command not implemented");
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static TSS2_RC
tss2_tcti_tabrmd_tls_get_poll_handles (TSS2_TCTI_CONTEXT     *context,
                                       TSS2_TCTI_POLL_HANDLE *handles,
                                       size_t                *num_handles)
{
    if (context == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    if (num_handles == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    if (handles != NULL && *num_handles < 1) {
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }
    *num_handles = 1;
    if (handles != NULL) {
        handles [0].fd = TSS2_TCTI_TABRMD_TLS_FD (context);
    }
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
tss2_tcti_tabrmd_tls_set_locality (TSS2_TCTI_CONTEXT *context,
                                   guint8             locality)
{
    if (context == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    g_info ("tss2_tcti_tabrmd_tls_set_locality: id 0x%" PRIx64,
            TSS2_TCTI_TABRMD_TLS_ID (context));
    if (TSS2_TCTI_TABRMD_TLS_STATE (context) != TABRMD_TLS_STATE_TRANSMIT) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }

    g_warning ("set locality command not implemented");
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

/*
 * Initialization function to set context data values and function pointers.
 */
static void
init_tcti_data (TSS2_TCTI_CONTEXT *context)
{
    TSS2_TCTI_MAGIC (context)            = TSS2_TCTI_TABRMD_TLS_MAGIC;
    TSS2_TCTI_VERSION (context)          = TSS2_TCTI_TABRMD_TLS_VERSION;
    TSS2_TCTI_TABRMD_TLS_STATE (context) = TABRMD_TLS_STATE_TRANSMIT;
    TSS2_TCTI_TRANSMIT (context)         = tss2_tcti_tabrmd_tls_transmit;
    TSS2_TCTI_RECEIVE (context)          = tss2_tcti_tabrmd_tls_receive;
    TSS2_TCTI_FINALIZE (context)         = tss2_tcti_tabrmd_tls_finalize;
    TSS2_TCTI_CANCEL (context)           = tss2_tcti_tabrmd_tls_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (context) = tss2_tcti_tabrmd_tls_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (context)     = tss2_tcti_tabrmd_tls_set_locality;
}

static gboolean
check_server_certificate (GTlsClientConnection *conn,
                          GTlsCertificate      *cert,
                          GTlsCertificateFlags  errors,
                          gpointer              user_data)
{
    g_print ("Certificate would have been rejected ( ");
    if (errors & G_TLS_CERTIFICATE_UNKNOWN_CA)
        g_print ("unknown-ca ");
    if (errors & G_TLS_CERTIFICATE_BAD_IDENTITY)
        g_print ("bad-identity ");
    if (errors & G_TLS_CERTIFICATE_NOT_ACTIVATED)
        g_print ("not-activated ");
    if (errors & G_TLS_CERTIFICATE_EXPIRED)
        g_print ("expired ");
    if (errors & G_TLS_CERTIFICATE_REVOKED)
        g_print ("revoked ");
    if (errors & G_TLS_CERTIFICATE_INSECURE)
        g_print ("insecure ");
    g_print (") but accepting anyway.\n");

    return TRUE;
}

static gboolean
tcti_tabrmd_call_create_connection_tls (const char       *ip_addr,
                                        unsigned int      port,
                                        gboolean          tls_enabled,
                                        GTlsCertificate  *certificate,
                                        GCancellable     *cancellable,
                                        GIOStream       **stream,
                                        GSocket         **socket,
                                        guint64          *id,
                                        GError          **error)
{
    GSocketType socket_type = G_SOCKET_TYPE_STREAM;
    GSocketFamily socket_family;
    GSocketConnectable *connectable;
    GIOStream *c_stream, *tls_stream;
    GSocket *c_socket = NULL;
    GSocketAddress *src_address, *address = NULL;
    guint64 c_id;
    guint timeout = 1;

    /* parse ip addr to get the family of socket */
    socket_family = check_ipstring_family (ip_addr);

    c_socket = g_socket_new (socket_family, socket_type, 0, error);
    if (c_socket == NULL) {
        return FALSE;
    }

    g_socket_set_timeout (c_socket, timeout);
    address = g_inet_socket_address_new_from_string (ip_addr, port);

    if (!g_socket_connect (c_socket, address, cancellable, error)) {
        g_warning ("Connection to %s with port %d failed", ip_addr, port);
        g_object_unref (c_socket);
        g_object_unref (address);
        return FALSE;
    }

    g_socket_set_blocking (c_socket, FALSE);
    g_debug ("Connected to %s", socket_address_to_string (address));
    g_object_unref (address);

    src_address = g_socket_get_local_address (c_socket, error);
    if (!src_address) {
        g_warning ("Error getting local address");
        g_object_unref (c_socket);
        return FALSE;
    }
    g_debug ("Local address: %s", socket_address_to_string (src_address));
    c_id = g_str_hash (socket_address_to_string (src_address));
    g_object_unref (src_address);

    c_stream = G_IO_STREAM (g_socket_connection_factory_create_connection (c_socket));
    if (!c_stream) {
       g_warning ("Error getting IOStream");
       g_object_unref (c_socket);
       return FALSE;
    }

    if (tls_enabled) {
        connectable = g_network_address_new (ip_addr, port);
        tls_stream = g_tls_client_connection_new (c_stream, connectable, error);
        if (!tls_stream) {
            g_warning ("Could not create TLS connection");
            g_object_unref (c_socket);
            g_object_unref (connectable);
            g_object_unref (c_stream);
            return FALSE;
        }
        g_object_unref (connectable);
        g_object_unref (c_stream);

        g_signal_connect (tls_stream, "accept-certificate",
                          G_CALLBACK (check_server_certificate), NULL);

        if (certificate)
            g_tls_connection_set_certificate (G_TLS_CONNECTION (tls_stream), certificate);

        c_stream = tls_stream;

        if (!g_tls_connection_handshake (G_TLS_CONNECTION (c_stream),
                                         cancellable,
                                         error)) {
            g_warning ("Error during TLS handshake");
            g_object_unref (c_socket);
            g_object_unref (c_stream);
            return FALSE;
        }
    }

    /* Return results to caller */
    *socket = c_socket;
    *stream = c_stream;
    *id = c_id;

    return TRUE;
}

TSS2_RC
tss2_tcti_tabrmd_tls_init (TSS2_TCTI_CONTEXT      *context,
                           size_t                 *size,
                           const char             *ip_addr,
                           unsigned int            port,
                           const char             *cert_file,
                           bool                    tls_enabled)
{
    GSocket *socket = NULL;
    GCancellable *cancellable = NULL;
    GIOStream *connection = NULL;
    GTlsCertificate  *certificate = NULL;
    guint64 id;
    GError *error = NULL;
    gboolean ret = NULL;

    if (context == NULL && size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (context == NULL && size != NULL) {
        *size = sizeof (TSS2_TCTI_TABRMD_TLS_CONTEXT);
        return TSS2_RC_SUCCESS;
    }
    if (ip_addr == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (cert_file) {
        certificate = g_tls_certificate_new_from_file (cert_file, &error);
        if (!certificate) {
            g_warning ("Could not read certificate '%s': %s",
                       cert_file, error->message);
            g_error_free (error);
            return TSS2_TCTI_RC_BAD_VALUE;
        }
    }

    init_tcti_data (context);
    ret = tcti_tabrmd_call_create_connection_tls(ip_addr,
                                                 port,
                                                 tls_enabled,
                                                 certificate,
                                                 cancellable,
                                                 &connection,
                                                 &socket,
                                                 &id,
                                                 &error);
    if (ret == FALSE) {
        g_warning ("Failed to create connection with service: %s",
                   error->message);
        g_error_free (error);
        return TSS2_TCTI_RC_NO_CONNECTION;
    }

    TSS2_TCTI_TABRMD_TLS_ID (context) = id;
    g_debug ("initialized tabrmd TCTI context with id: 0x%" PRIx64,
             TSS2_TCTI_TABRMD_TLS_ID (context));
    TSS2_TCTI_TABRMD_TLS_SOCKET (context) = socket;
    TSS2_TCTI_TABRMD_TLS_IOSTREAM (context) = connection;

    if (certificate)
        g_object_unref (certificate);
    return TSS2_RC_SUCCESS;
}
