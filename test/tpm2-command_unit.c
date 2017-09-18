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
#include <glib.h>
#include <inttypes.h>
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "tpm2-command.h"

#define HANDLE_FIRST  0x80000000
#define HANDLE_SECOND 0x80000001

uint8_t cmd_with_auths [] = {
    0x80, 0x02, /* TPM_ST_SESSIONS */
    0x00, 0x00, 0x00, 0x73, /* command buffer size */
    0x00, 0x00, 0x01, 0x37, /* command code: 0x137 / TPM_CC_NV_Write */
    0x01, 0x50, 0x00, 0x20, /* auth handle */
    0x01, 0x50, 0x00, 0x20, /* nv index handle */
    0x00, 0x00, 0x00, 0x92, /* size of auth area (2x73 byte auths) */
    0x02, 0x00, 0x00, 0x00, /* auth session handle */
    0x00, 0x20, /* sizeof caller nonce */
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x01, /* session attributes */
    0x00, 0x20, /* sizeof  hmac */
    0x4d, 0x91, 0x26, 0xa3, 0xd9, 0xf6, 0x74, 0xde,
    0x98, 0x94, 0xb1, 0x0f, 0xe6, 0xb1, 0x5c, 0x72,
    0x7d, 0x36, 0xeb, 0x39, 0x6b, 0xf2, 0x31, 0x72,
    0x89, 0xb6, 0xc6, 0x8e, 0x54, 0xa9, 0x4c, 0x3e,
    0x02, 0x00, 0x00, 0x01, /* auth session handle */
    0x00, 0x20, /* sizeof caller nonce */
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x01, /* session attributes */
    0x00, 0x20, /* sizeof  hmac */
    0x4d, 0x91, 0x26, 0xa3, 0xd9, 0xf6, 0x74, 0xde,
    0x98, 0x94, 0xb1, 0x0f, 0xe6, 0xb1, 0x5c, 0x72,
    0x7d, 0x36, 0xeb, 0x39, 0x6b, 0xf2, 0x31, 0x72,
    0x89, 0xb6, 0xc6, 0x8e, 0x54, 0xa9, 0x4c, 0x3e,
    0x00, 0x10, /* sizeof data */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x00, 0x00
};

typedef struct {
    Tpm2Command *command;
    guint8      *buffer;
    Connection *connection;
} test_data_t;
/**
 * This is the minimum work required to instantiate a Tpm2Command. It needs
 * a data buffer to hold the command and a Connection object. We also
 * allocate a structure to hold these things so that we can free them in
 * the teardown.
 */
static void
tpm2_command_setup_base (void **state)
{
    test_data_t *data   = NULL;
    gint         fds[2] = { 0, };
    HandleMap   *handle_map;

    data = calloc (1, sizeof (test_data_t));
    /* allocate a buffer large enough to hold a TPM2 header and 3 handles */
    data->buffer = calloc (1, TPM_RESPONSE_HEADER_SIZE + sizeof (TPM_HANDLE) * 3);
    handle_map = handle_map_new (TPM_HT_TRANSIENT, MAX_ENTRIES_DEFAULT);
    data->connection = connection_new (&fds[0], &fds[1], 0, handle_map, NULL);
    g_object_unref (handle_map);
    *state = data;
}
static void
tpm2_command_setup (void **state)
{
    test_data_t *data   = NULL;
    TPMA_CC  attributes = {
        .val = 0x0,
    };

    tpm2_command_setup_base (state);
    data = (test_data_t*)*state;
    data->command = tpm2_command_new (data->connection,
                                      data->buffer,
                                      attributes);
    *state = data;
}
static void
tpm2_command_setup_two_handles (void **state)
{
    test_data_t *data = NULL;
    TPMA_CC  attributes = {
       .val = 2 << 25,
    };

    tpm2_command_setup_base (state);
    data = (test_data_t*)*state;
    data->command = tpm2_command_new (data->connection,
                                      data->buffer,
                                      attributes);
    /*
     * This sets the two handles to 0x80000000 and 0x80000001, assuming the
     * buffer was initialized to all 0's
     */
    data->buffer [10] = 0x80;
    data->buffer [14] = 0x80;
    data->buffer [17] = 0x01;
}
/*
 * This test setup function is much like the others with the exception of the
 * Tpm2Command buffer being set to the 'cmd_with_auths'. This allows testing
 * of the functions that parse / process the auth are of the command.
 */
static void
tpm2_command_setup_with_auths (void **state)
{
    test_data_t *data   = NULL;
    gint         fds[2] = { 0, };
    HandleMap   *handle_map;
    TPMA_CC attributes = {
        .val = 2 << 25,
    };

    data = calloc (1, sizeof (test_data_t));
    /* allocate a buffer large enough to hold the cmd_with_auths buffer */
    data->buffer = calloc (1, sizeof (cmd_with_auths));
    memcpy (data->buffer, cmd_with_auths, sizeof (cmd_with_auths));
    handle_map = handle_map_new (TPM_HT_TRANSIENT, MAX_ENTRIES_DEFAULT);
    data->connection = connection_new (&fds[0], &fds[1], 0, handle_map, NULL);
    g_object_unref (handle_map);
    data->command = tpm2_command_new (data->connection,
                                      data->buffer,
                                      attributes);

    *state = data;
}
/**
 * Tear down all of the data from the setup function. We don't have to
 * free the data buffer (data->buffer) since the Tpm2Command frees it as
 * part of its finalize function.
 */
static void
tpm2_command_teardown (void **state)
{
    test_data_t *data = (test_data_t*)*state;

    g_object_unref (data->connection);
    g_object_unref (data->command);
    free (data);
}
/**
 * This is a test for memory management / reference counting. The setup
 * function does exactly that so when we get the Tpm2Command object we just
 * check to be sure it's a GObject and then we unref it. This test will
 * probably only fail when run under valgrind if the reference counting is
 * off.
 */
static void
tpm2_command_type_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;

    assert_true (G_IS_OBJECT (data->command));
    assert_true (IS_TPM2_COMMAND (data->command));
}

static void
tpm2_command_get_connection_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;

    assert_int_equal (data->connection, tpm2_command_get_connection (data->command));
}

static void
tpm2_command_get_buffer_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;

    assert_int_equal (data->buffer, tpm2_command_get_buffer (data->command));
}

static void
tpm2_command_get_tag_test (void **state)
{
    test_data_t         *data   = (test_data_t*)*state;
    guint8              *buffer = tpm2_command_get_buffer (data->command);
    TPMI_ST_COMMAND_TAG  tag_ret;

    /* this is TPM_ST_SESSIONS in network byte order */
    buffer[0] = 0x80;
    buffer[1] = 0x02;

    tag_ret = tpm2_command_get_tag (data->command);
    assert_int_equal (tag_ret, TPM_ST_SESSIONS);
}

static void
tpm2_command_get_size_test (void **state)
{
    test_data_t *data     = (test_data_t*)*state;
    guint8      *buffer   = tpm2_command_get_buffer (data->command);
    guint32      size_ret = 0;

    /* this is tpm_st_connections in network byte order */
    buffer[0] = 0x80;
    buffer[1] = 0x02;
    buffer[2] = 0x00;
    buffer[3] = 0x00;
    buffer[4] = 0x00;
    buffer[5] = 0x06;

    size_ret = tpm2_command_get_size (data->command);
    assert_int_equal (0x6, size_ret);
}

static void
tpm2_command_get_code_test (void **state)
{
    test_data_t *data     = (test_data_t*)*state;
    guint8      *buffer   = tpm2_command_get_buffer (data->command);
    TPM_CC       command_code;

    /**
     * This is TPM_ST_SESSIONS + a size of 0x0a + the command code for
     * GetCapability in network byte order
     */
    buffer[0] = 0x80;
    buffer[1] = 0x02;
    buffer[2] = 0x00;
    buffer[3] = 0x00;
    buffer[4] = 0x00;
    buffer[5] = 0x0a;
    buffer[6] = 0x00;
    buffer[7] = 0x00;
    buffer[8] = 0x01;
    buffer[9] = 0x7a;

    command_code = tpm2_command_get_code (data->command);
    assert_int_equal (command_code, TPM_CC_GetCapability);
}

static void
tpm2_command_get_two_handle_count_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;
    guint8 command_handles;

    command_handles = tpm2_command_get_handle_count (data->command);
    assert_int_equal (command_handles, 2);
}

static void
tpm2_command_get_handles_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;
    TPM_HANDLE handles [3] = { 0, };
    gboolean ret;

    ret = tpm2_command_get_handles (data->command, handles, 3);
    assert_true (ret == TRUE);
    assert_int_equal (handles [0], HANDLE_FIRST);
    assert_int_equal (handles [1], HANDLE_SECOND);
}
static void
tpm2_command_set_handles_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;
    gboolean ret;
    TPM_HANDLE handles_in [2] = {
        TPM_HT_TRANSIENT + 0x1,
        TPM_HT_TRANSIENT + 0x2,
    };
    TPM_HANDLE handles_out [2] = { 0, };

    ret = tpm2_command_set_handles (data->command, handles_in, 2);
    assert_true (ret == TRUE);
    ret = tpm2_command_get_handles (data->command, handles_out, 2);
    assert_true (ret == TRUE);
    assert_memory_equal (handles_in, handles_out, 2 * sizeof (TPM_HANDLE));
}
/*
 * Get the handle at the first position in the handle area of the command.
 */
static void
tpm2_command_get_handle_first_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;
    TPM_HANDLE   handle_out;

    handle_out = tpm2_command_get_handle (data->command, 0);
    assert_int_equal (handle_out, HANDLE_FIRST);
}
/*
 * Get the handle at the second position in the handle area of the command.
 */
static void
tpm2_command_get_handle_second_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;
    TPM_HANDLE   handle_out;

    handle_out = tpm2_command_get_handle (data->command, 1);
    assert_int_equal (handle_out, HANDLE_SECOND);
}
/*
 * Attempt to get the handle at the third position in the handle area of the
 * command. This should fail since the command has only two handles.
 */
static void
tpm2_command_get_handle_fail_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;
    TPM_HANDLE   handle_out;

    handle_out = tpm2_command_get_handle (data->command, 2);
    assert_int_equal (handle_out, 0);
}
/*
 */
static void
tpm2_command_set_handle_first_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;
    TPM_HANDLE   handle_in = 0xdeadbeef, handle_out = 0;
    gboolean     ret;

    ret = tpm2_command_set_handle (data->command, handle_in, 0);
    assert_true (ret);
    handle_out = tpm2_command_get_handle (data->command, 0);
    assert_int_equal (handle_out, handle_in);
}
static void
tpm2_command_set_handle_second_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;
    TPM_HANDLE   handle_in = 0xdeadbeef, handle_out = 0;
    gboolean     ret;

    ret = tpm2_command_set_handle (data->command, handle_in, 1);
    assert_true (ret);
    handle_out = tpm2_command_get_handle (data->command, 1);
    assert_int_equal (handle_out, handle_in);
}
static void
tpm2_command_set_handle_fail_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;
    TPM_HANDLE   handle_in = 0xdeadbeef;
    gboolean     ret;

    ret = tpm2_command_set_handle (data->command, handle_in, 2);
    assert_false (ret);
}
static void
tpm2_command_get_auth_size_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;
    UINT32 auths_area_size = 0;

    auths_area_size = tpm2_command_get_auths_size (data->command);
    assert_int_equal (auths_area_size, 0x92);
}
/*
 * This structure is used to track state while processing the authorizations
 * from the command authorization area.
 */
typedef struct {
    size_t counter;
    size_t handles_count;
    TPM_HANDLE handles [3];
} callback_auth_state_t;
/*
 * The tpm2_command_foreach_auth function invokes this function for each
 * authorization in the command authorization area. The 'user_data' is an
 * instance of the callback_auth_state_t structure that we use to track state.
 * The expected handles from the auth area are in the handles array in the
 * order that they should be received. We then use the 'counter' to identify
 * which handle we should receive for each callback (assuming that the
 * callback is invoked for each auth IN ORDER).
 */
static void
tpm2_command_foreach_auth_callback (gpointer authorization,
                                    gpointer user_data)
{
    uint8_t *auth_start = (uint8_t*)authorization;
    callback_auth_state_t *callback_state = (callback_auth_state_t*)user_data;

    g_debug ("tpm2_command_foreach_auth_callback:\n  counter: %zd\n"
            "  handles_count: %zd\n  handle: 0x%08" PRIx32,
            callback_state->counter,
            callback_state->handles_count,
            callback_state->handles [callback_state->counter]);
    g_debug ("  auth_start: 0x%" PRIxPTR, (uintptr_t)auth_start);
    g_debug ("  AUTH_HANDLE_GET: 0x%08" PRIx32, AUTH_HANDLE_GET (auth_start));
    assert_true (callback_state->counter < callback_state->handles_count);
    assert_int_equal (AUTH_HANDLE_GET (auth_start),
                      callback_state->handles [callback_state->counter]);
    ++callback_state->counter;
}
/*
 * This test exercises the tpm2_command_foreach_auth function. The state
 * structure must be initialized with the handles that are expected from
 * the command. Each time the callback is invoked we compare the authorization
 * handle to the handles array.
 */
static void
tpm2_command_foreach_auth_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;
    /* this data is highly dependent on the */
    callback_auth_state_t callback_state = {
        .counter = 0,
        .handles_count = 2,
        .handles = {
            0x02000000,
            0x02000001,
        },
    };

    tpm2_command_foreach_auth (data->command,
                               tpm2_command_foreach_auth_callback,
                               &callback_state);
}
gint
main (gint    argc,
      gchar  *argv[])
{
    const UnitTest tests[] = {
        unit_test_setup_teardown (tpm2_command_type_test,
                                  tpm2_command_setup,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_get_connection_test,
                                  tpm2_command_setup,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_get_buffer_test,
                                  tpm2_command_setup,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_get_tag_test,
                                  tpm2_command_setup,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_get_size_test,
                                  tpm2_command_setup,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_get_code_test,
                                  tpm2_command_setup,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_get_two_handle_count_test,
                                  tpm2_command_setup_two_handles,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_get_handles_test,
                                  tpm2_command_setup_two_handles,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_set_handles_test,
                                  tpm2_command_setup_two_handles,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_get_handle_first_test,
                                  tpm2_command_setup_two_handles,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_get_handle_second_test,
                                  tpm2_command_setup_two_handles,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_get_handle_fail_test,
                                  tpm2_command_setup_two_handles,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_set_handle_first_test,
                                  tpm2_command_setup_two_handles,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_set_handle_second_test,
                                  tpm2_command_setup_two_handles,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_set_handle_fail_test,
                                  tpm2_command_setup_two_handles,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_get_auth_size_test,
                                  tpm2_command_setup_with_auths,
                                  tpm2_command_teardown),
        unit_test_setup_teardown (tpm2_command_foreach_auth_test,
                                  tpm2_command_setup_with_auths,
                                  tpm2_command_teardown),
      };
    return run_tests (tests);
}
