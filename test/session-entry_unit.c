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
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "session-entry.h"

#define CLIENT_ID        1ULL
#define TEST_HANDLE      0x03000000

typedef struct {
    Connection   *connection;
    gint          client_fd;
    HandleMap    *handle_map;
    SessionEntry *session_entry;
} test_data_t;
/*
 * Setup function
 */
static int
session_entry_setup (void **state)
{
    test_data_t *data   = NULL;

    data = calloc (1, sizeof (test_data_t));
    data->handle_map = handle_map_new (TPM_HT_TRANSIENT, 100);
    data->connection = connection_new (&data->client_fd,
                                       CLIENT_ID,
                                       data->handle_map,
                                       NULL);
    data->session_entry = session_entry_new (data->connection, TEST_HANDLE);

    *state = data;
    return 0;
}
/**
 * Tear down all of the data from the setup function. We don't have to
 * free the data buffer (data->buffer) since the Tpm2Command frees it as
 * part of its finalize function.
 */
static int
session_entry_teardown (void **state)
{
    test_data_t *data = (test_data_t*)*state;

    g_object_unref (data->connection);
    g_object_unref (data->handle_map);
    g_object_unref (data->session_entry);
    free (data);
    return 0;
}
/*
 * This is a test for memory management / reference counting. The setup
 * function does exactly that so when we get the Tpm2Command object we just
 * check to be sure it's a GObject and then we unref it. This test will
 * probably only fail when run under valgrind if the reference counting is
 * off.
 */
static void
session_entry_type_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;

    assert_true (G_IS_OBJECT (data->session_entry));
    assert_true (IS_SESSION_ENTRY (data->session_entry));
}

static void
session_entry_get_context_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;

    TPMS_CONTEXT *context = NULL;
    context = session_entry_get_context (data->session_entry);
    assert_non_null (context);
}

static void
session_entry_get_connection_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;

    Connection *connection;
    connection = session_entry_get_connection (data->session_entry);
    assert_true (IS_CONNECTION (connection));
    g_object_unref (connection);
}

static void
session_entry_get_handle_test (void **state)
{
    test_data_t *data = (test_data_t*)*state;

    TPM_HANDLE handle;
    handle = session_entry_get_handle (data->session_entry);
    assert_int_equal (handle, TEST_HANDLE);
}

gint
main (gint argc,
      gchar *arvg[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown (session_entry_type_test,
                                         session_entry_setup,
                                         session_entry_teardown),
        cmocka_unit_test_setup_teardown (session_entry_get_context_test,
                                         session_entry_setup,
                                         session_entry_teardown),
        cmocka_unit_test_setup_teardown (session_entry_get_connection_test,
                                         session_entry_setup,
                                         session_entry_teardown),
        cmocka_unit_test_setup_teardown (session_entry_get_handle_test,
                                         session_entry_setup,
                                         session_entry_teardown),
    };
    return cmocka_run_group_tests (tests, NULL, NULL);
}
