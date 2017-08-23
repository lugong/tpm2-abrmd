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
#include "tcti-tabrmd.h"
#include "tcti-tabrmd-priv.h"
#include "tpm2-header.h"
#include "util.h"

static TSS2_RC
tss2_tcti_tabrmd_transmit (TSS2_TCTI_CONTEXT *context,
                           size_t             size,
                           uint8_t           *command)
{
    ssize_t write_ret;
    TSS2_RC tss2_ret = TSS2_RC_SUCCESS;

    g_debug ("tss2_tcti_tabrmd_transmit");
    if (context == NULL || command == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    if (size == 0) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (TSS2_TCTI_MAGIC (context) != TSS2_TCTI_TABRMD_MAGIC ||
        TSS2_TCTI_VERSION (context) != TSS2_TCTI_TABRMD_VERSION) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    if (TSS2_TCTI_TABRMD_STATE (context) != TABRMD_STATE_TRANSMIT) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    g_debug_bytes (command, size, 16, 4);
    g_debug ("blocking on FD_TRANSMIT: %d", TSS2_TCTI_TABRMD_FD_TRANSMIT (context));
    write_ret = write_all (TSS2_TCTI_TABRMD_FD_TRANSMIT (context),
                           command,
                           size, NULL);
    /* should switch on possible errors to translate to TSS2 error codes */
    switch (write_ret) {
    case -1:
        g_debug ("tss2_tcti_tabrmd_transmit: error writing to pipe: %s",
                 strerror (errno));
        tss2_ret = TSS2_TCTI_RC_IO_ERROR;
        break;
    case 0:
        g_debug ("tss2_tcti_tabrmd_transmit: EOF returned writing to pipe");
        tss2_ret = TSS2_TCTI_RC_NO_CONNECTION;
        break;
    default:
        if (write_ret == size) {
            TSS2_TCTI_TABRMD_STATE (context) = TABRMD_STATE_RECEIVE;
        } else {
            g_debug ("tss2_tcti_tabrmd_transmit: short write");
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
    case EPROTO:
        return TSS2_TCTI_RC_GENERAL_FAILURE;
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
 * This is a thin wrapper around a call to poll. It packages up the provided
 * file descriptor and timeout and polls on that same FD for data or a hangup.
 * Returns:
 *   -1 on timeout
 *   0 when data is ready
 *   errno on error
 */
int
tcti_tabrmd_poll (int        fd,
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
TSS2_RC
tss2_tcti_tabrmd_receive (TSS2_TCTI_CONTEXT *context,
                          size_t            *size,
                          uint8_t           *response,
                          int32_t            timeout)
{
    TSS2_TCTI_TABRMD_CONTEXT *tabrmd_ctx = (TSS2_TCTI_TABRMD_CONTEXT*)context;
    size_t ret = 0;

    g_debug ("tss2_tcti_tabrmd_receive");
    if (context == NULL || size == NULL) {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    if (response == NULL && *size != 0) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (TSS2_TCTI_MAGIC (context) != TSS2_TCTI_TABRMD_MAGIC ||
        TSS2_TCTI_VERSION (context) != TSS2_TCTI_TABRMD_VERSION) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    if (tabrmd_ctx->state != TABRMD_STATE_RECEIVE) {
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
    ret = tcti_tabrmd_poll (tabrmd_ctx->fd_receive, timeout);
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
        ret = read_data (tabrmd_ctx->fd_receive,
                         &tabrmd_ctx->index,
                         tabrmd_ctx->header_buf,
                         TPM_HEADER_SIZE - tabrmd_ctx->index,
                         NULL);
        if (ret != 0) {
            return errno_to_tcti_rc (ret);
        }
        if (tabrmd_ctx->index == TPM_HEADER_SIZE) {
            tabrmd_ctx->header.tag  = get_response_tag  (tabrmd_ctx->header_buf);
            tabrmd_ctx->header.size = get_response_size (tabrmd_ctx->header_buf);
            tabrmd_ctx->header.code = get_response_code (tabrmd_ctx->header_buf);
            if (tabrmd_ctx->header.size < TPM_HEADER_SIZE) {
                tabrmd_ctx->state = TABRMD_STATE_TRANSMIT;
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
        tabrmd_ctx->state = TABRMD_STATE_TRANSMIT;
        return TSS2_RC_SUCCESS;
    }
    if (*size < tabrmd_ctx->header.size) {
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }
    ret = read_data (tabrmd_ctx->fd_receive,
                     &tabrmd_ctx->index,
                     response,
                     tabrmd_ctx->header.size - tabrmd_ctx->index,
                     NULL);
    if (ret == 0) {
        /* We got all the bytes we asked for, reset the index & state: done */
        *size = tabrmd_ctx->index;
        tabrmd_ctx->index = 0;
        tabrmd_ctx->state = TABRMD_STATE_TRANSMIT;
    }
    return errno_to_tcti_rc (ret);
}

static void
tss2_tcti_tabrmd_finalize (TSS2_TCTI_CONTEXT *context)
{
    int ret = 0;

    g_debug ("tss2_tcti_tabrmd_finalize");
    if (context == NULL) {
        g_warning ("Invalid parameter");
        return;
    }
    if (TSS2_TCTI_TABRMD_FD_RECEIVE (context) != 0) {
        ret = close (TSS2_TCTI_TABRMD_FD_RECEIVE (context));
        TSS2_TCTI_TABRMD_FD_RECEIVE (context) = 0;
    }
    if (ret != 0 && ret != EBADF) {
        g_warning ("Failed to close receive pipe: %s", strerror (errno));
    }
    if (TSS2_TCTI_TABRMD_FD_TRANSMIT (context) != 0) {
        ret = close (TSS2_TCTI_TABRMD_FD_TRANSMIT (context));
        TSS2_TCTI_TABRMD_FD_TRANSMIT (context) = 0;
    }
    if (ret != 0 && ret != EBADF) {
        g_warning ("Failed to close send pipe: %s", strerror (errno));
    }
    TSS2_TCTI_TABRMD_STATE (context) = TABRMD_STATE_FINAL;
    g_object_unref (TSS2_TCTI_TABRMD_PROXY (context));
}

static TSS2_RC
tss2_tcti_tabrmd_cancel (TSS2_TCTI_CONTEXT *context)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;
    GError *error = NULL;
    gboolean cancel_ret;

    g_info("tss2_tcti_tabrmd_cancel: id 0x%" PRIx64,
           TSS2_TCTI_TABRMD_ID (context));
    if (context == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    if (TSS2_TCTI_TABRMD_STATE (context) != TABRMD_STATE_RECEIVE) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    cancel_ret = tcti_tabrmd_call_cancel_sync (
                     TSS2_TCTI_TABRMD_PROXY (context),
                     TSS2_TCTI_TABRMD_ID (context),
                     &ret,
                     NULL,
                     &error);
    if (cancel_ret == FALSE) {
        g_warning ("cancel command failed with error code: 0x%" PRIx32
                   ", messag: %s", error->code, error->message);
        ret = error->code;
        g_error_free (error);
    }

    return ret;
}

static TSS2_RC
tss2_tcti_tabrmd_get_poll_handles (TSS2_TCTI_CONTEXT     *context,
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
        handles [0].fd = TSS2_TCTI_TABRMD_FD_RECEIVE (context);
    }
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
tss2_tcti_tabrmd_set_locality (TSS2_TCTI_CONTEXT *context,
                               guint8             locality)
{
    gboolean status;
    TSS2_RC ret = TSS2_RC_SUCCESS;
    GError *error = NULL;

    g_info ("tss2_tcti_tabrmd_set_locality: id 0x%" PRIx64,
            TSS2_TCTI_TABRMD_ID (context));
    if (context == NULL) {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    }
    if (TSS2_TCTI_TABRMD_STATE (context) != TABRMD_STATE_TRANSMIT) {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    status = tcti_tabrmd_call_set_locality_sync (
                 TSS2_TCTI_TABRMD_PROXY (context),
                 TSS2_TCTI_TABRMD_ID (context),
                 locality,
                 &ret,
                 NULL,
                 &error);

    if (status == FALSE) {
        g_warning ("set locality command failed with error code: 0x%" PRIx32
                   ", message: %s", error->code, error->message);
        ret = error->code;
        g_error_free (error);
    }

    return ret;
}

/*
 * Initialization function to set context data values and function pointers.
 */
void
init_tcti_data (TSS2_TCTI_CONTEXT *context)
{
    TSS2_TCTI_MAGIC (context)            = TSS2_TCTI_TABRMD_MAGIC;
    TSS2_TCTI_VERSION (context)          = TSS2_TCTI_TABRMD_VERSION;
    TSS2_TCTI_TABRMD_STATE (context)     = TABRMD_STATE_TRANSMIT;
    TSS2_TCTI_TRANSMIT (context)         = tss2_tcti_tabrmd_transmit;
    TSS2_TCTI_RECEIVE (context)          = tss2_tcti_tabrmd_receive;
    TSS2_TCTI_FINALIZE (context)         = tss2_tcti_tabrmd_finalize;
    TSS2_TCTI_CANCEL (context)           = tss2_tcti_tabrmd_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (context) = tss2_tcti_tabrmd_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (context)     = tss2_tcti_tabrmd_set_locality;
}

static gboolean
tcti_tabrmd_call_create_connection_sync_fdlist (TctiTabrmd     *proxy,
                                                GVariant      **out_fds,
                                                guint64        *out_id,
                                                GUnixFDList   **out_fd_list,
                                                GCancellable   *cancellable,
                                                GError        **error)
{
    GVariant *_ret;
    _ret = g_dbus_proxy_call_with_unix_fd_list_sync (G_DBUS_PROXY (proxy),
        "CreateConnection",
        g_variant_new ("()"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        out_fd_list,
        cancellable,
        error);
    if (_ret == NULL) {
        goto _out;
    }
    g_variant_get (_ret, "(@aht)", out_fds, out_id);
    g_variant_unref (_ret);
_out:
    return _ret != NULL;
}

TSS2_RC
tss2_tcti_tabrmd_init_full (TSS2_TCTI_CONTEXT      *context,
                            size_t                 *size,
                            TCTI_TABRMD_DBUS_TYPE   bus_type,
                            const char             *bus_name)
{
    GBusType g_bus_type;
    GError *error = NULL;
    GVariant *fds_variant;
    guint64 id;
    GUnixFDList *fd_list;
    gboolean call_ret;
    int ret;

    if (context == NULL && size == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    if (context == NULL && size != NULL) {
        *size = sizeof (TSS2_TCTI_TABRMD_CONTEXT);
        return TSS2_RC_SUCCESS;
    }
    if (bus_name == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    switch (bus_type) {
    case TCTI_TABRMD_DBUS_TYPE_SESSION:
        g_bus_type = G_BUS_TYPE_SESSION;
        break;
    case TCTI_TABRMD_DBUS_TYPE_SYSTEM:
        g_bus_type = G_BUS_TYPE_SYSTEM;
        break;
    default:
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    /* Register dbus error mapping for tabrmd. Gets us RCs from Gerror codes */
    TABRMD_ERROR;
    init_tcti_data (context);
    TSS2_TCTI_TABRMD_PROXY (context) =
        tcti_tabrmd_proxy_new_for_bus_sync (
            g_bus_type,
            G_DBUS_PROXY_FLAGS_NONE,
            bus_name,
            TABRMD_DBUS_PATH, /* object */
            NULL,                          /* GCancellable* */
            &error);
    if (TSS2_TCTI_TABRMD_PROXY (context) == NULL) {
        g_error ("failed to allocate dbus proxy object: %s", error->message);
    }
    call_ret = tcti_tabrmd_call_create_connection_sync_fdlist (
        TSS2_TCTI_TABRMD_PROXY (context),
        &fds_variant,
        &id,
        &fd_list,
        NULL,
        &error);
    if (call_ret == FALSE) {
        g_warning ("Failed to create connection with service: %s",
                 error->message);
        return TSS2_TCTI_RC_NO_CONNECTION;
    }
    if (fd_list == NULL) {
        g_error ("call to CreateConnection returned a NULL GUnixFDList");
    }
    gint num_handles = g_unix_fd_list_get_length (fd_list);
    if (num_handles != 2) {
        g_error ("CreateConnection expected to return 2 handles, received %d",
                 num_handles);
    }
    gint fd = g_unix_fd_list_get (fd_list, 0, &error);
    if (fd == -1) {
        g_error ("unable to get receive handle from GUnixFDList: %s",
                 error->message);
    }
    ret = set_flags (fd, O_NONBLOCK);
    if (ret == -1) {
        g_error ("failed to set O_NONBLOCK for client fd: %d", fd);
    }
    TSS2_TCTI_TABRMD_FD_RECEIVE (context) = fd;
    fd = g_unix_fd_list_get (fd_list, 1, &error);
    if (fd == -1) {
        g_error ("failed to get transmit handle from GUnixFDList: %s",
                 error->message);
    }
    TSS2_TCTI_TABRMD_FD_TRANSMIT (context) = fd;
    TSS2_TCTI_TABRMD_ID (context) = id;
    g_debug ("initialized tabrmd TCTI context with id: 0x%" PRIx64,
             TSS2_TCTI_TABRMD_ID (context));

    return TSS2_RC_SUCCESS;
}

TSS2_RC
tss2_tcti_tabrmd_init (TSS2_TCTI_CONTEXT *context,
                       size_t            *size)
{
    return tss2_tcti_tabrmd_init_full (context,
                                       size,
                                       TCTI_TABRMD_DBUS_TYPE_DEFAULT,
                                       TCTI_TABRMD_DBUS_NAME_DEFAULT);
}
