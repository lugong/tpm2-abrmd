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

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include <setjmp.h>
#include <cmocka.h>

#include "connection.h"
#include "connection-manager.h"

static void
connection_manager_allocate_test (void **state)
{
    ConnectionManager *manager = NULL;

    manager = connection_manager_new (MAX_CONNECTIONS_DEFAULT);
    assert_non_null (manager);
    g_object_unref (manager);
}

static void
connection_manager_setup (void **state)
{
    ConnectionManager *manager = NULL;

    manager = connection_manager_new (MAX_CONNECTIONS_DEFAULT);
    assert_non_null (manager);
    *state = manager;
}

static void
connection_manager_teardown (void **state)
{
    ConnectionManager *manager = CONNECTION_MANAGER (*state);

    g_object_unref (manager);
}

static void
connection_manager_insert_test (void **state)
{
    ConnectionManager *manager = CONNECTION_MANAGER (*state);
    Connection *connection = NULL;
    HandleMap   *handle_map = NULL;
    gint ret, receive_fd, send_fd;

    handle_map = handle_map_new (TPM_HT_TRANSIENT, MAX_ENTRIES_DEFAULT);
    connection = connection_new (&receive_fd, &send_fd, 5, handle_map, NULL);
    g_object_unref (handle_map);
    ret = connection_manager_insert (manager, connection);
    assert_int_equal (ret, 0);
}

static void
connection_manager_lookup_fd_test (void **state)
{
    ConnectionManager *manager = CONNECTION_MANAGER (*state);
    Connection *connection = NULL, *connection_lookup = NULL;
    HandleMap   *handle_map = NULL;
    gint ret, receive_fd, send_fd;

    handle_map = handle_map_new (TPM_HT_TRANSIENT, MAX_ENTRIES_DEFAULT);
    connection = connection_new (&receive_fd, &send_fd, 5, handle_map, NULL);
    g_object_unref (handle_map);
    ret = connection_manager_insert (manager, connection);
    assert_int_equal (ret, TSS2_RC_SUCCESS);
    connection_lookup = connection_manager_lookup_fd (manager, *(int*)connection_key_fd (connection));
    assert_int_equal (connection, connection_lookup);
    g_object_unref (connection_lookup);
}

static void
connection_manager_lookup_id_test (void **state)
{
    ConnectionManager *manager = CONNECTION_MANAGER (*state);
    Connection *connection = NULL, *connection_lookup = NULL;
    HandleMap   *handle_map = NULL;
    gint ret, receive_fd, send_fd;

    handle_map = handle_map_new (TPM_HT_TRANSIENT, MAX_ENTRIES_DEFAULT);
    connection = connection_new (&receive_fd, &send_fd, 5, handle_map, NULL);
    g_object_unref (handle_map);
    ret = connection_manager_insert (manager, connection);
    assert_int_equal (ret, TSS2_RC_SUCCESS);
    connection_lookup = connection_manager_lookup_id (manager, *(int*)connection_key_id (connection));
    assert_int_equal (connection, connection_lookup);
}

static void
connection_manager_remove_test (void **state)
{
    ConnectionManager *manager = CONNECTION_MANAGER (*state);
    Connection *connection = NULL;
    HandleMap   *handle_map = NULL;
    gint ret_int, receive_fd, send_fd;
    gboolean ret_bool;

    handle_map = handle_map_new (TPM_HT_TRANSIENT, MAX_ENTRIES_DEFAULT);
    connection = connection_new (&receive_fd, &send_fd, 5, handle_map, NULL);
    g_object_unref (handle_map);
    ret_int = connection_manager_insert (manager, connection);
    assert_int_equal (ret_int, 0);
    ret_bool = connection_manager_remove (manager, connection);
    assert_true (ret_bool);
}

int
main(int argc, char* argv[])
{
    const UnitTest tests[] = {
        unit_test (connection_manager_allocate_test),
        unit_test_setup_teardown (connection_manager_insert_test,
                                  connection_manager_setup,
                                  connection_manager_teardown),
        unit_test_setup_teardown (connection_manager_lookup_fd_test,
                                  connection_manager_setup,
                                  connection_manager_teardown),
        unit_test_setup_teardown (connection_manager_lookup_id_test,
                                  connection_manager_setup,
                                  connection_manager_teardown),
        unit_test_setup_teardown (connection_manager_remove_test,
                                  connection_manager_setup,
                                  connection_manager_teardown),
    };
    return run_tests(tests);
}
