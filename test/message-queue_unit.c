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
#include <pthread.h>
#include <stdlib.h>

#include <setjmp.h>
#include <cmocka.h>

#include "message-queue.h"
#include "connection.h"
#include "control-message.h"

typedef struct msgq_test_data {
    MessageQueue *queue;
} msgq_test_data_t;

static int
message_queue_setup (void **state)
{
    msgq_test_data_t *data = NULL;

    data = calloc (1, sizeof (msgq_test_data_t));
    assert_non_null (data);
    data->queue = message_queue_new ();
    *state = data;
    return 0;
}

static int
message_queue_teardown (void **state)
{
    msgq_test_data_t *data = (msgq_test_data_t*)*state;

    g_object_unref (data->queue);
    free (data);
    return 0;
}

static void
message_queue_allocate_test (void **state)
{
    message_queue_setup (state);
    message_queue_teardown (state);
}

static void
message_queue_enqueue_dequeue_test (void **state)
{
    msgq_test_data_t *data = (msgq_test_data_t*)*state;
    MessageQueue *queue = data->queue;
    Connection  *obj_in, *obj_out;
    HandleMap    *handle_map;
    gint          client_fd;

    handle_map = handle_map_new (TPM_HT_TRANSIENT, MAX_ENTRIES_DEFAULT);
    obj_in = connection_new (&client_fd, 0, handle_map, NULL);
    message_queue_enqueue (queue, G_OBJECT (obj_in));
    obj_out = CONNECTION (message_queue_dequeue (queue));
    /* ptr != int but they're the same size usually? */
    assert_int_equal (obj_in, obj_out);
    g_object_unref (handle_map);
}

static void
message_queue_dequeue_order_test (void **state)
{
    msgq_test_data_t *data = (msgq_test_data_t*)*state;
    HandleMap    *map_0, *map_1, *map_2;
    MessageQueue *queue = data->queue;
    Connection *obj_0, *obj_1, *obj_2, *obj_tmp;
    gint client_fd;

    map_0 = handle_map_new (TPM_HT_TRANSIENT, MAX_ENTRIES_DEFAULT);
    map_1 = handle_map_new (TPM_HT_TRANSIENT, MAX_ENTRIES_DEFAULT);
    map_2 = handle_map_new (TPM_HT_TRANSIENT, MAX_ENTRIES_DEFAULT);

    obj_0 = connection_new (&client_fd, 0, map_0, NULL);
    obj_1 = connection_new (&client_fd, 0, map_1, NULL);
    obj_2 = connection_new (&client_fd, 0, map_2, NULL);

    message_queue_enqueue (queue, G_OBJECT (obj_0));
    message_queue_enqueue (queue, G_OBJECT (obj_1));
    message_queue_enqueue (queue, G_OBJECT (obj_2));

    obj_tmp = CONNECTION (message_queue_dequeue (queue));
    assert_int_equal (obj_tmp, obj_0);
    obj_tmp = CONNECTION (message_queue_dequeue (queue));
    assert_int_equal (obj_tmp, obj_1);
    obj_tmp = CONNECTION (message_queue_dequeue (queue));
    assert_int_equal (obj_tmp, obj_2);
    g_object_unref (map_0);
    g_object_unref (map_1);
    g_object_unref (map_2);
    g_object_unref (obj_0);
    g_object_unref (obj_1);
    g_object_unref (obj_2);
}
/*
 * This function is used in the thread_unblock_test function as the thread
 * that blocks on the MessageQueue waiting for a message.
 */
void*
thread_func (void* arg)
{
    MessageQueue *queue = MESSAGE_QUEUE (arg);
    GObject *obj;

    obj = message_queue_dequeue (queue);
    assert_true (CONTROL_MESSAGE (obj));
    g_object_unref (obj);

    return NULL;
}

static void
message_queue_thread_unblock_test (void **state)
{
    msgq_test_data_t *data = (msgq_test_data_t*)*state;
    ControlMessage *msg = control_message_new (CHECK_CANCEL);
    pthread_t thread_id;
    int ret;

    ret = pthread_create (&thread_id,
                          NULL,
                          thread_func,
                          data->queue);
    assert_int_equal (ret, 0);
    message_queue_enqueue (data->queue, G_OBJECT (msg));
    g_object_unref (msg);
    ret = pthread_join (thread_id, NULL);
    assert_int_equal (ret, 0);
}

int
main(int argc, char* argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test (message_queue_allocate_test),
        cmocka_unit_test_setup_teardown (message_queue_enqueue_dequeue_test,
                                         message_queue_setup,
                                         message_queue_teardown),
        cmocka_unit_test_setup_teardown (message_queue_dequeue_order_test,
                                         message_queue_setup,
                                         message_queue_teardown),
        cmocka_unit_test_setup_teardown (message_queue_thread_unblock_test,
                                         message_queue_setup,
                                         message_queue_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
