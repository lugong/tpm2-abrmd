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
#include <stdbool.h>
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "handle-map.h"
#include "ipc-backend.h"
/*
 * Begin definition of TestIpcBackend.
 * This is a GObject that derives from the IpcBackend abstract base class.
 */
G_BEGIN_DECLS
typedef struct _TestIpcBackend      TestIpcBackend;
typedef struct _TestIpcBackendClass TestIpcBackendClass;

struct _TestIpcBackend {
    IpcBackend             parent;
    gboolean               connected;
};

struct _TestIpcBackendClass {
    IpcBackendClass        parent;
};

#define TYPE_TEST_IPC_BACKEND             (test_ipc_backend_get_type       ())
#define TEST_IPC_BACKEND(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj),   TYPE_TEST_IPC_BACKEND, TestIpcBackend))
#define IS_TEST_IPC_BACKEND(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj),   TYPE_TEST_IPC_BACKEND))

GType test_ipc_backend_get_type (void);

G_END_DECLS

G_DEFINE_TYPE (TestIpcBackend, test_ipc_backend, TYPE_IPC_BACKEND);
static void
test_ipc_backend_init (TestIpcBackend *self)
{
    self->connected = FALSE;
}
static void
test_ipc_backend_finalize (GObject *obj)
{
    if (test_ipc_backend_parent_class != NULL)
        G_OBJECT_CLASS (test_ipc_backend_parent_class)->finalize (obj);
}
static void
test_ipc_backend_connect (TestIpcBackend *self,
                          GMutex         *init_mutex)
{
    IpcBackend *backend = IPC_BACKEND (self);

    self->connected = TRUE;
    backend->init_mutex = init_mutex;
}
static void
test_ipc_backend_disconnect (TestIpcBackend *self)
{
    IpcBackend *backend = IPC_BACKEND (self);

    self->connected = FALSE;
    backend->init_mutex = NULL;
    /*
     * This is where a child class would emit the 'disconnected' signal.
     * This test class however doesn't need to do this since it's tested
     * elsewhere.
     */
}
static void
test_ipc_backend_class_init (TestIpcBackendClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    IpcBackendClass *ipc_backend_class = IPC_BACKEND_CLASS (klass);

    if (test_ipc_backend_parent_class == NULL)
        test_ipc_backend_parent_class = g_type_class_peek_parent (klass);
    object_class->finalize   = test_ipc_backend_finalize;
    ipc_backend_class->connect    = (IpcBackendConnect)test_ipc_backend_connect;
    ipc_backend_class->disconnect = (IpcBackendDisconnect)test_ipc_backend_disconnect;
}

static TestIpcBackend*
test_ipc_backend_new (void)
{
    return TEST_IPC_BACKEND (g_object_new (TYPE_TEST_IPC_BACKEND, NULL));
}
/*
 * End definition of TestIpcBackend GObject.
 */
/*
 * This is a 'setup' function used by the cmocka machinery to setup the
 * test state before a test is executed.
 */
static void
ipc_backend_setup (void **state)
{
    TestIpcBackend *test_ipc_backend = NULL;

    test_ipc_backend = test_ipc_backend_new ();
    assert_non_null (test_ipc_backend);
    *state = test_ipc_backend;
}
/*
 * This 'teardown' function is used by the cmocka machinery to cleanup the
 * test state.
 */
static void
ipc_backend_teardown (void **state)
{
    TestIpcBackend *test_ipc_backend = NULL;

    assert_non_null (state);
    test_ipc_backend = TEST_IPC_BACKEND (*state);
    g_object_unref (test_ipc_backend);
}
/*
 * This test relies on the setup / teardown functions to instantiate an
 * instance of the TestIpcBackend. It extracts this object from the state
 * parameter and uses the GObject type macros to ensure that the object
 * system identifies it as both the abstract base type and the derived
 * type.
 */
static void
ipc_backend_type_test (void **state)
{
    assert_non_null (state);
    assert_true (IS_IPC_BACKEND (*state));
    assert_true (IS_TEST_IPC_BACKEND (*state));
}
/*
 * This callback function is used by the ipc_backend_event_test to set a
 * boolean flag when the signal is emitted.
 */
static void
ipc_backend_on_disconnected (IpcBackend *ipc_backend,
                             bool       *called_flag)
{
    *called_flag = true;
}
/*
 * This test exercises the 'disconnected' event emitted by the IpcBackend
 * abstract class.
 */
static void
ipc_backend_event_test (void **state)
{
    IpcBackend     *ipc_backend = NULL;
    bool            called_flag = false;

    ipc_backend      = IPC_BACKEND (*state);
    g_signal_connect (ipc_backend,
                      "disconnected",
                      (GCallback) ipc_backend_on_disconnected,
                      &called_flag);
    /* pickup here and test the signal emission */
    ipc_backend_disconnected_invoke (ipc_backend);
    assert_true (called_flag);
}
/*
 */
static void
ipc_backend_connect_test (void **state)
{
    IpcBackend *ipc_backend = NULL;
    TestIpcBackend *test_ipc_backend = NULL;

    ipc_backend = IPC_BACKEND (*state);
    test_ipc_backend = TEST_IPC_BACKEND (*state);

    ipc_backend_connect (ipc_backend, NULL);
    assert_true (test_ipc_backend->connected);
}
/*
 */
static void
ipc_backend_disconnect_test (void **state)
{
    IpcBackend *ipc_backend = NULL;
    TestIpcBackend *test_ipc_backend = NULL;

    ipc_backend = IPC_BACKEND (*state);
    test_ipc_backend = TEST_IPC_BACKEND (*state);

    ipc_backend_connect (ipc_backend, NULL);
    assert_true (test_ipc_backend->connected);
    ipc_backend_disconnect (ipc_backend);
    assert_false (test_ipc_backend->connected);
}

gint
main (gint     argc,
      gchar   *argv[])
{
    const UnitTest tests[] = {
        unit_test_setup_teardown (ipc_backend_type_test,
                                  ipc_backend_setup,
                                  ipc_backend_teardown),
        unit_test_setup_teardown (ipc_backend_event_test,
                                  ipc_backend_setup,
                                  ipc_backend_teardown),
        unit_test_setup_teardown (ipc_backend_connect_test,
                                  ipc_backend_setup,
                                  ipc_backend_teardown),
        unit_test_setup_teardown (ipc_backend_disconnect_test,
                                  ipc_backend_setup,
                                  ipc_backend_teardown),
    };
    return run_tests (tests);
}
