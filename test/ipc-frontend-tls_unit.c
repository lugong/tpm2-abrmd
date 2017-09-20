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

#include "ipc-frontend-tls.h"

static void
ipc_frontend_tls_setup (void **state)
{
    IpcFrontendTls *ipc_frontend_tls = NULL;
    ConnectionManager *connection_manager = NULL;

    connection_manager = connection_manager_new (100);

    ipc_frontend_tls = ipc_frontend_tls_new (IPC_FRONTEND_SOCKET_IP_DEFAULT,
                                             IPC_FRONTEND_SOCKET_PORT_DEFAULT,
                                             connection_manager,
                                             100,
                                             NULL);
    assert_non_null (ipc_frontend_tls);
    *state = ipc_frontend_tls;
    g_object_unref (connection_manager);
}

static void
ipc_frontend_tls_teardown (void **state)
{
    IpcFrontendTls *ipc_frontend_tls = NULL;

    assert_non_null (state);
    ipc_frontend_tls = IPC_FRONTEND_TLS (*state);
    g_object_unref (ipc_frontend_tls);
}
/*
 * This test relies on the setup / teardown functions to instantiate an
 * instance of the TestIpcFrontend. It extracts this object from the state
 * parameter and uses the GObject type macros to ensure that the object
 * system identifies it as both the abstract base type and the derived
 * type.
 */
static void
ipc_frontend_tls_type_test (void **state)
{
    assert_non_null (state);
    assert_true (IS_IPC_FRONTEND (*state));
    assert_true (IS_IPC_FRONTEND_TLS (*state));
}
gint
main (gint     argc,
      gchar   *argv[])
{
    const UnitTest tests[] = {
        unit_test_setup_teardown (ipc_frontend_tls_type_test,
                                  ipc_frontend_tls_setup,
                                  ipc_frontend_tls_teardown),
    };
    return run_tests (tests);
}
