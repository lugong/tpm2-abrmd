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
#ifndef TSS2TCTI_TABRMD_TLS_PRIV_H
#define TSS2TCTI_TABRMD_TLS_PRIV_H

#include <glib.h>
#include <pthread.h>

#include <sapi/tpm20.h>

#include "tpm2-header.h"

#define TSS2_TCTI_TABRMD_TLS_MAGIC 0x1c8e03ff00db0f93
#define TSS2_TCTI_TABRMD_TLS_VERSION 1

#define TSS2_TCTI_TABRMD_TLS_ID(context) \
    ((TSS2_TCTI_TABRMD_TLS_CONTEXT*)context)->id
#define TSS2_TCTI_TABRMD_TLS_SOCKET(context) \
    ((TSS2_TCTI_TABRMD_TLS_CONTEXT*)context)->socket
#define TSS2_TCTI_TABRMD_TLS_IOSTREAM(context) \
    ((TSS2_TCTI_TABRMD_TLS_CONTEXT*)context)->stream
#define TSS2_TCTI_TABRMD_TLS_HEADER(context) \
    ((TSS2_TCTI_TABRMD_TLS_CONTEXT*)context)->header
#define TSS2_TCTI_TABRMD_TLS_STATE(context) \
    ((TSS2_TCTI_TABRMD_TLS_CONTEXT*)context)->state

/*
 * Macros for accessing the internals of the I/O stream. These are helpers
 * for getting at the underlying GSocket and raw fds that we need to
 * implement polling etc.
 */
#define TSS2_TCTI_TABRMD_TLS_FD(context) \
    g_socket_get_fd (TSS2_TCTI_TABRMD_TLS_SOCKET (context))
#define TSS2_TCTI_TABRMD_TLS_ISTREAM(context) \
    g_io_stream_get_input_stream (TSS2_TCTI_TABRMD_TLS_IOSTREAM(context))
#define TSS2_TCTI_TABRMD_TLS_OSTREAM(context) \
    g_io_stream_get_output_stream (TSS2_TCTI_TABRMD_TLS_IOSTREAM(context))

/*
 * The elements in this enumeration represent the possible states that the
 * tabrmd TCTI can be in. The state machine is as follows:
 * An instantiated TCTI context begins in the TRANSMIT state:
 *   TRANSMIT:
 *     transmit:    success transitions the state machine to RECEIVE
 *                  failure leaves the state unchanged
 *     receieve:    produces TSS2_TCTI_RC_BAD_SEQUENCE
 *     finalize:    transitions state machine to FINAL state
 *     cancel:      produces TSS2_TCTI_RC_BAD_SEQUENCE
 *     setLocality: success or failure leaves state unchanged
 *   RECEIVE:
 *     transmit:    produces TSS2_TCTI_RC_BAD_SEQUENCE
 *     receive:     success transitions the state machine to TRANSMIT
 *                  failure with the following RCs leave the state unchanged:
 *                    TRY_AGAIN, INSUFFICIENT_BUFFER, BAD_CONTEXT,
 *                    BAD_REFERENCE, BAD_VALUE, BAD_SEQUENCE
 *                  all other failures transition state machine to
 *                    TRANSMIT (not recoverable)
 *     finalize:    transitions state machine to FINAL state
 *     cancel:      success transitions state machine to READY_TRANSMIT
 *                  failure leaves state unchanged
 *     setLocality: produces TSS2_TCTI_RC_BAD_SEQUENCE
 *   FINAL:
 *     all function calls produce TSS2_TCTI_RC_BAD_SEQUENCE
 */
typedef enum {
    TABRMD_TLS_STATE_FINAL,
    TABRMD_TLS_STATE_RECEIVE,
    TABRMD_TLS_STATE_TRANSMIT,
} tcti_tabrmd_tls_state_t;

/* This is our private TCTI structure. We're required by the spec to have
 * the same structure as the non-opaque area defined by the
 * TSS2_TCTI_CONTEXT_COMMON_V1 structure. Anything after this data is opaque
 * and private to our implementation. See section 7.3 of the SAPI / TCTI spec
 * for the details.
 */
typedef struct {
    TSS2_TCTI_CONTEXT_COMMON_V1    common;
    guint64                        id;
    GSocket                       *socket;
    GIOStream                     *stream;
    tpm_header_t                   header;
    tcti_tabrmd_tls_state_t        state;
    size_t                         index;
    uint8_t                        header_buf [TPM_HEADER_SIZE];
} TSS2_TCTI_TABRMD_TLS_CONTEXT;

#endif /* TSS2TCTI_TABRMD_TLS_PRIV_H */
