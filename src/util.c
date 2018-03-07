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
#include <gio/gunixinputstream.h>
#include <gio/gunixoutputstream.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "util.h"
#include "tpm2-header.h"

/**
 * This is a wrapper around g_debug to dump a binary buffer in a human
 * readable format. Since g_debug appends a new line to each string that
 * it builds we dump a single line at a time. Each line is indented by
 * 'indent' spaces. The 'width' parameter determines how many bytes are
 * output on each line.
 */
#define MAX_LINE_LENGTH 200
void
g_debug_bytes (uint8_t const *byte_array,
               size_t         array_size,
               size_t         width,
               size_t         indent)
{
    guint byte_ctr;
    guint indent_ctr;
    size_t line_length = indent + width * 3 + 1;
    char  line [MAX_LINE_LENGTH] = { 0 };
    char  *line_position = NULL;

    if (line_length > MAX_LINE_LENGTH) {
        g_warning ("g_debug_bytes: MAX_LINE_LENGTH exceeded");
        return;
    }

    for (byte_ctr = 0; byte_ctr < array_size; ++byte_ctr) {
        /* index into line where next byte is written */
        line_position = line + indent + (byte_ctr % width) * 3;
        /* detect the beginning of a line, pad indent spaces */
        if (byte_ctr % width == 0)
            for (indent_ctr = 0; indent_ctr < indent; ++indent_ctr)
                line [indent_ctr] = ' ';
        sprintf (line_position, "%02x", byte_array [byte_ctr]);
        /**
         *  If we're not width bytes into the array AND we're not at the end
         *  of the byte array: print a space. This is padding between the
         *  current byte and the next.
         */
        if (byte_ctr % width != width - 1 && byte_ctr != array_size - 1) {
            sprintf (line_position + 2, " ");
        } else {
            g_debug ("%s", line);
        }
    }
}
/** Write as many of the size bytes from buf to fd as possible.
 */
ssize_t
write_all (GOutputStream *ostream,
           const uint8_t *buf,
           const size_t   size)
{
    ssize_t written = 0;
    size_t written_total = 0;
    GError *error = NULL;

    do {
        g_debug ("writing %zu bytes starting at 0x%" PRIxPTR " to socket 0x%"
                 PRIxPTR,
                 size - written_total,
                 (uintptr_t)buf + written_total,
                 (uintptr_t)socket);
        written = g_output_stream_write (ostream,
                                         (const gchar*)&buf [written_total],
                                         size - written_total,
                                         NULL,
                                         &error);
        switch (written) {
        case -1:
            g_assert (error != NULL);
            g_warning ("failed to write to ostream 0x%" PRIxPTR ": %s",
                       (uintptr_t)ostream, error->message);
            g_error_free (error);
            return written;
        case  0:
            return (ssize_t)written_total;
        default:
            g_debug ("wrote %zd bytes to ostream 0x%" PRIxPTR,
                     written, (uintptr_t)ostream);
        }
        written_total += (size_t)written;
    } while (written_total < size);
    g_debug ("returning %zu", written_total);

    return (ssize_t)written_total;
}
/*
 * Read data from a GSocket.
 * Parameters:
 *   socket:  A connected GSocket.
 *   *index:  A reference to the location in the buffer where data will be
 *            written. This reference is updated to the end of the location
 *            where data is written.
 *   buf:      destination buffer
 *   count:    number of bytes to read
 * Returns:
 *   -1:     when EOF is reached
 *   0:      if requested number of bytes received
 *   errno:  in the event of an error from the 'read' call
 * NOTE: The caller must ensure that 'buf' is large enough to hold count
 *       bytes.
 */
int
read_data (GInputStream  *istream,
           size_t        *index,
           uint8_t       *buf,
           size_t         count)
{
    ssize_t num_read = 0;
    size_t bytes_left = count;
    gint error_code;
    GError *error = NULL;

    g_assert (index != NULL);
    do {
        g_debug ("reading %zd bytes socket 0x%" PRIxPTR", to 0x%" PRIxPTR,
                 bytes_left, (uintptr_t)socket, (uintptr_t)&buf [*index]);
        num_read = g_input_stream_read (istream,
                                        (gchar*)&buf [*index],
                                        bytes_left,
                                        NULL,
                                        &error);
        if (num_read > 0) {
            g_debug ("successfully read %zd bytes", num_read);
            g_debug_bytes ((uint8_t*)&buf [*index], num_read, 16, 4);
            /* Advance index by the number of bytes read. */
            *index += num_read;
            bytes_left -= num_read;
        } else if (num_read == 0) {
            g_debug ("read produced EOF");
            return -1;
        } else { /* num_read < 0 */
            g_assert (error != NULL);
            g_warning ("read on istream 0x%" PRIxPTR " produced error: %s",
                       (uintptr_t)istream, error->message);
            error_code = error->code;
            g_error_free (error);
            return error_code;
        }
    } while (bytes_left);

    return 0;
}
/*
 * This function attempts to read a TPM2 command or response into the provided
 * buffer. It specifically handles the details around reading the command /
 * response header, determining the size of the data that it needs to read and
 * keeping track of past / partial reads.
 * Returns:
 *   -1: If the underlying syscall results in an EOF
 *   0: If data is successfully read.
 *      NOTE: The index will be updated to the size of the command buffer.
 *   errno: In the event of an error from the underlying 'read' syscall.
 *   EPROTO: If buf_size is less than the size from the command buffer.
 */
int
read_tpm_buffer (GInputStream             *istream,
                 size_t                   *index,
                 uint8_t                  *buf,
                 size_t                    buf_size)
{
    ssize_t ret = 0;
    uint32_t size = 0;

    /* if the buf_size isn't at least large enough to hold the header */
    if (buf_size < TPM_HEADER_SIZE) {
        return EPROTO;
    }
    /* If we don't have the whole header yet try to get it. */
    if (*index < TPM_HEADER_SIZE) {
        ret = read_data (istream, index, buf, TPM_HEADER_SIZE - *index);
        if (ret != 0) {
            /* Pass errors up to the caller. */
            return ret;
        }
    }

    /* Once we have the header we can get the size of the whole blob. */
    size = get_command_size (buf);
    /* If size from header is size of header, there's nothing more to read. */
    if (size == TPM_HEADER_SIZE) {
        return ret;
    }
    /* Not enough space in buf to for data in the buffer (header.size). */
    if (size > buf_size) {
        return EPROTO;
    }
    /* Now that we have the header, we know the whole buffer size. Get it. */
    return read_data (istream, index, buf, size - *index);
}
/*
 * This fucntion is a wrapper around the read_tpm_buffer function above. It
 * adds the memory allocation logic necessary to create the buffer to hold
 * the TPM command / response buffer.
 * Returns NULL on error, and a pointer to the allocated buffer on success.
 *   The size of the allocated buffer is returned through the *buf_size
 *   parameter on success.
 */
uint8_t*
read_tpm_buffer_alloc (GInputStream *istream,
                       size_t       *buf_size)
{
    uint8_t *buf = NULL;
    size_t   size_tmp = TPM_HEADER_SIZE, index = 0;
    int ret = 0;

    if (istream == NULL || buf_size == NULL) {
        g_warning ("%s: got null parameter", __func__);
        return NULL;
    }
    do {
        buf = g_realloc (buf, size_tmp);
        ret = read_tpm_buffer (istream, &index, buf, size_tmp);
        switch (ret) {
        case EPROTO:
            size_tmp = get_command_size (buf);
            if (size_tmp < TPM_HEADER_SIZE && size_tmp > UTIL_BUF_MAX) {
                g_warning ("%s: tpm buffer size is ouside of acceptable bounds: %zd",
                           __func__, size_tmp);
                goto err_out;
            }
            break;
        case 0:
            /* done */
            break;
        default:
            goto err_out;
        }
    } while (ret == EPROTO);
    g_debug ("%s: read TPM buffer to 0x%" PRIxPTR " of size: %zd",
             __func__, (uintptr_t)buf, index);
    g_debug_bytes (buf, index, 16, 4);
    *buf_size = size_tmp;
    return buf;
err_out:
    g_debug ("%s: err_out freeing buffer at 0x%" PRIxPTR, __func__, (uintptr_t)buf);
    if (buf != NULL) {
        g_free (buf);
    }
    return NULL;
}
/*
 * Create a GSocket for use by the daemon for communicating with the client.
 * The client end of the socket is returned through the client_fd
 * parameter.
 */
GIOStream*
create_connection_iostream (int *client_fd)
{
    GIOStream *iostream;
    GSocket *sock;
    int server_fd, ret;

    ret = create_socket_pair (client_fd,
                              &server_fd,
                              SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (ret == -1) {
        g_error ("CreateConnection failed to make fd pair %s", strerror (errno));
    }
    sock = g_socket_new_from_fd (server_fd, NULL);
    iostream = G_IO_STREAM (g_socket_connection_factory_create_connection (sock));
    g_object_unref (sock);
    return iostream;
}
/*
 * Create a socket and return the fds for both ends of the communication
 * channel.
 */
int
create_socket_pair (int *fd_a,
                    int *fd_b,
                    int  flags)
{
    int ret, fds[2] = { 0, };

    ret = socketpair (PF_LOCAL, SOCK_STREAM | flags, 0, fds);
    if (ret == -1) {
        g_warning ("%s: failed to create socket pair with errno: %d",
                   __func__, errno);
        return ret;
    }
    *fd_a = fds [0];
    *fd_b = fds [1];
    return 0;
}
/*
 * Generate ip and port string according to RFC 3986.
 */
char *
socket_address_to_string (GSocketAddress *address)
{
    GInetAddress *inet_address;
    char *str;
    int port;
    char *res = NULL;
    GSocketFamily family;

    if (!G_IS_INET_SOCKET_ADDRESS (address))
        return NULL;

    inet_address = g_inet_socket_address_get_address (
                     G_INET_SOCKET_ADDRESS (address));
    str = g_inet_address_to_string (inet_address);
    port = g_inet_socket_address_get_port (
                     G_INET_SOCKET_ADDRESS (address));
    family = g_inet_address_get_family (inet_address);
    if (family == G_SOCKET_FAMILY_IPV4)
        res = g_strdup_printf ("%s:%d", str, port);
    else
        res = g_strdup_printf ("[%s]:%d", str, port);
    g_free (str);

    return res;
}
/*
 * Roughly derive the socket family from the ip string.
 */
GSocketFamily
check_ipstring_family (const char *ipstring)
{
    GSocketFamily family;

    if (strchr (ipstring, '.'))
       family = G_SOCKET_FAMILY_IPV4;
    else if (strchr (ipstring, ':'))
       family = G_SOCKET_FAMILY_IPV6;
    else
       family = G_SOCKET_FAMILY_INVALID;

    return family;
}
/* pretty print */
void
g_debug_tpma_cc (TPMA_CC tpma_cc)
{
    g_debug ("TPMA_CC: 0x%08" PRIx32, tpma_cc);
    g_debug ("  commandIndex: 0x%" PRIx16, tpma_cc & TPMA_CC_COMMANDINDEX);
    g_debug ("  reserved1:    0x%" PRIx8, (tpma_cc & TPMA_CC_RESERVED1) >> 16);
    g_debug ("  nv:           %s", prop_str (tpma_cc & TPMA_CC_NV));
    g_debug ("  extensive:    %s", prop_str (tpma_cc & TPMA_CC_EXTENSIVE));
    g_debug ("  flushed:      %s", prop_str (tpma_cc & TPMA_CC_FLUSHED));
    g_debug ("  cHandles:     0x%" PRIx8, (tpma_cc & TPMA_CC_CHANDLES) >> 25);
    g_debug ("  rHandle:      %s", prop_str (tpma_cc & TPMA_CC_RHANDLE));
    g_debug ("  V:            %s", prop_str (tpma_cc & TPMA_CC_V));
    g_debug ("  Res:          0x%" PRIx8, (tpma_cc & TPMA_CC_RES) >> 30);
}
