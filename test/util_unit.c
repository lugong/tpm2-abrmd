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
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#include <setjmp.h>
#include <cmocka.h>

#include "util.h"
#include "tpm2-header.h"

#define MAX_BUF 4096
#define READ_SIZE  UTIL_BUF_SIZE
#define WRITE_SIZE 10

ssize_t
__wrap_write (gint         fd,
              const void  *buf,
              size_t       count)
{
    return (ssize_t) mock ();
}

void
write_in_one (void **state)
{
    ssize_t written;

    will_return (__wrap_write, WRITE_SIZE);
    written = write_all (0, NULL, WRITE_SIZE, NULL);
    assert_int_equal (written, WRITE_SIZE);
}

void
write_in_two (void **state)
{
    ssize_t written;

    will_return (__wrap_write, 5);
    will_return (__wrap_write, 5);
    written = write_all (0, NULL, WRITE_SIZE, NULL);
    assert_int_equal (written, WRITE_SIZE);
}

void
write_in_three (void **state)
{
    ssize_t written;

    will_return (__wrap_write, 3);
    will_return (__wrap_write, 3);
    will_return (__wrap_write, 4);
    written = write_all (0, NULL, WRITE_SIZE, NULL);
    assert_int_equal (written, WRITE_SIZE);
}

void
write_error (void **state)
{
    ssize_t written;

    will_return (__wrap_write, -1);
    written = write_all (0, NULL, WRITE_SIZE, NULL);
    assert_int_equal (written, -1);
}

void
write_zero (void **state)
{
    ssize_t written;

    will_return (__wrap_write, 0);
    written = write_all (0, NULL, WRITE_SIZE, NULL);
    assert_int_equal (written, 0);
}
/*
 * mock 'read' function: This function expects 3 things to be on the mock
 * queue:
 *   input buffer
 *   offset into input buffer where read starts
 *   errno
 *   return value
 */
ssize_t
__wrap_read (int     fd,
             void   *buf,
             size_t  count)
{
    uint8_t *buf_in    = mock_type (uint8_t*);
    size_t   buf_index = mock_type (size_t);
    int      errno_in  = mock_type (int);
    ssize_t  ret       = mock_type (ssize_t);

    /* be careful comparint signed to unsigned values */
    if (ret > 0) {
        assert_true (ret <= (ssize_t)count);
        memcpy (buf, &buf_in [buf_index], ret);
    }

    errno = errno_in;
    return ret;
}
/* global static input array used by read_data* tests */
static uint8_t buf_in [MAX_BUF] = {
    /* header */
    0x80, 0x02, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00,
    0x00, 0x00,
    /* body */
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
};
/*
 * Data structure to hold data for read tests.
 */
typedef struct {
    int     fd;
    size_t  index;
    uint8_t buf_out [MAX_BUF];
    size_t  buf_size;
} data_t;

static void
read_data_setup (void **state)
{
    data_t *data;

    data = calloc (1, sizeof (data_t));
    data->buf_size = 26;

    *state = data;
}

static void
read_data_teardown (void **state)
{
    data_t *data = *state;

    if (data != NULL) {
        free (data);
    }
}
/*
 * Simple call to read wrapper function. Returns exactly what we ask for.
 * We check to be sure return value is 0, the index variable is updated
 * properly and that the output data buffer is the same as the input.
 */
static void
read_data_success_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    /* prime the wrap queue for a successful read */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, data->index);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, data->buf_size);

    ret = read_data (data->fd, &data->index, data->buf_out, data->buf_size, NULL);
    assert_int_equal (ret, 0);
    assert_int_equal (data->index, data->buf_size);
    assert_memory_equal (data->buf_out, buf_in, data->buf_size);
}
/*
 * This tests a simple error case where read returns -1 and errno is set to
 * EIO. In this case the index should remain unchanged (0).
 */
static void
read_data_error_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, data->index);
    will_return (__wrap_read, EIO);
    will_return (__wrap_read, -1);

    ret = read_data (data->fd, &data->index, data->buf_out, data->buf_size, NULL);
    assert_int_equal (ret, EIO);
    assert_int_equal (data->index, 0);
}
/*
 * This test covers the 'short read'. A single call to 'read_data' results in
 * a the first read returning half the data (not an error), followed by
 * the second half obtained through a second 'read' call.
 */
static void
read_data_short_success_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    /* prime the wrap queue for a short read (half the requested size) */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, data->index);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, data->buf_size / 2);
    /* do it again for the second half of the read */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, data->buf_size / 2);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, data->buf_size / 2);

    ret = read_data (data->fd, &data->index, data->buf_out, data->buf_size, NULL);
    assert_int_equal (ret, 0);
    assert_int_equal (data->index, data->buf_size);
    assert_memory_equal (data->buf_out, buf_in, data->buf_size);
}
/*
 * This test covers a short read followed by a failing 'read'. NOTE: half of
 * the buffer is filled due to the first read succeeding.
 */
static void
read_data_short_err_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    /*
     * Prime the wrap queue for another short read, again half the requested
     * size.
     */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, data->index);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, data->buf_size / 2);
    /* */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, data->buf_size / 2);
    will_return (__wrap_read, EAGAIN);
    will_return (__wrap_read, -1);
    /* read the second half of the buffer, the index maintains the state */
    ret = read_data (data->fd, &data->index, data->buf_out, data->buf_size, NULL);
    assert_int_equal (ret, EAGAIN);
    assert_int_equal (data->index, data->buf_size / 2);
    assert_memory_equal (data->buf_out, buf_in, data->buf_size / 2);
}
/*
 * This test covers a single call returning EOF. This is signaled to the
 * through the return value which is -1.
 */
static void
read_data_eof_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, data->index);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 0);

    ret = read_data (data->fd, &data->index, data->buf_out, data->buf_size, NULL);
    assert_int_equal (ret, -1);
    assert_int_equal (data->index, 0);
}
/*
 * This test causes the first call to 'read' to result in an error with errno
 * set to EINTR. This is caused by interrupted system calls. The call should
 * be retried. The second read succeeds with the whole of the buffer read.
 */
static void
read_data_eintr_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    /*
     * Prime the wrap queue for another short read, again half the requested
     * size.
     */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, EINTR);
    will_return (__wrap_read, -1);
    /* */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, data->buf_size);
    /* read the second half of the buffer, the index maintains the state */
    ret = read_data (data->fd, &data->index, data->buf_out, data->buf_size, NULL);
    assert_int_equal (ret, 0);
    assert_int_equal (data->index, data->buf_size);
    assert_memory_equal (data->buf_out, buf_in, data->buf_size);
}
/*
 * This test covers the common case when reading a tpm command / response
 * buffer. read_tpm_buffer first reads the header (10 bytes), extracts the
 * size field from the header, and then reads this many bytes into the
 * provided buffer.
 */
static void
read_tpm_buf_success_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    /* prime read to successfully produce the header */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 10);
    /* prime read to successfully produce the rest of the buffer */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 10);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, data->buf_size - 10);

    ret = read_tpm_buffer (data->fd,
                           &data->index,
                           data->buf_out,
                           data->buf_size,
                           NULL);
    assert_int_equal (ret, 0);
    assert_int_equal (data->index, data->buf_size);
    assert_memory_equal (data->buf_out, buf_in, data->buf_size);
}
/*
 * This tests the code path where a header is successfully read and the size
 * field in the header is the size of the header.
 */
static void
read_tpm_buf_header_only_success_test (void **state)
{
    data_t *data = *state;
    int ret = 0;
    uint8_t buf [10] = {
        0x80, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00
    };

    /* prime read to successfully produce the header */
    data->buf_size = 10;
    will_return (__wrap_read, buf);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 10);

    ret = read_tpm_buffer (data->fd,
                           &data->index,
                           data->buf_out,
                           data->buf_size,
                           NULL);
    assert_int_equal (ret, 0);
    assert_int_equal (data->index, data->buf_size);
    assert_memory_equal (data->buf_out, buf, data->buf_size);
}
/*
 * Test the condition where the header read has a size larger than the
 * provided buffer.
 */
static void
read_tpm_buf_lt_header_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    ret = read_tpm_buffer (data->fd, &data->index, data->buf_out, 8, NULL);
    assert_int_equal (ret, EPROTO);
    assert_int_equal (data->index, 0);
}

static void
read_tpm_buf_short_header_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    /*
     * Prime read to successfully produce 4 bytes. This is a short read to
     * exercise the error handling path in the function under test.
     */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 4);

    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 4);
    will_return (__wrap_read, EWOULDBLOCK);
    will_return (__wrap_read, -1);

    ret = read_tpm_buffer (data->fd,
                           &data->index,
                           data->buf_out,
                           data->buf_size,
                           NULL);
    assert_int_equal (ret, EWOULDBLOCK);
    assert_int_equal (data->index, 4);
    assert_memory_equal (data->buf_out, buf_in, data->index);
}
/*
 * Test the condition where the header read has a size larger than the
 * provided buffer.
 */
static void
read_tpm_buf_lt_body_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    /*
     * Prime read to successfully produce 10 bytes. This is the number of
     * bytes that the first 'read' syscall is asked to produce (header).
     */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, data->index);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 10);

    ret = read_tpm_buffer (data->fd, &data->index, data->buf_out, 11, NULL);
    assert_int_equal (ret, EPROTO);
    assert_int_equal (data->index, 10);
    assert_memory_equal (data->buf_out, buf_in, 10);
}
/*
 * Read the header in one go. The second call to 'read' will be an attempt to
 * read the body of the command. We setup the mock stuff such that we get a
 * short read, followed by the rest of the command.
 */
static void
read_tpm_buf_short_body_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    /*
     * Prime read to successfully produce 10 bytes. This is the number of
     * bytes that the first 'read' syscall is asked to produce (header).
     */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 10);
    /* Now cause a short read when getting the body of the buffer. */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 10);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 5);
    /* And then the rest of the buffer */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 15);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, data->buf_size - 15);

    ret = read_tpm_buffer (data->fd,
                           &data->index,
                           data->buf_out,
                           data->buf_size,
                           NULL);
    assert_int_equal (ret, 0);
    assert_int_equal (data->index, data->buf_size);
    assert_memory_equal (data->buf_out, buf_in, data->buf_size);
}
/*
 * The following tests cover cases where the 'read_tpm_buffer' function is
 * called with the tpm buffer is partially populated (from previous calls to
 * same function) with the index value set appropriately.
 */
/*
 * This test sets up a buffer such that the first 4 bytes of the header have
 * already been populated and the index set accordingly. The read_tpm_buffer
 * function is then invoked as though it has bee previously interrupted.
 * This results in the last 6 bytes of the header being read, followed by
 * the rest of the buffer.
 */
static void
read_tpm_buf_populated_header_half_test (void **state)
{
    data_t *data = *state;
    int ret = 0;
    /* buffer already has 4 bytes of data */
    memcpy (data->buf_out, buf_in, 4);

    /* prime read to successfully produce the header */
    data->index = 4;
    /* read the last 6 bytes of the header */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 4);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 6);
    /* read the rest of the body (26 - 10) */
    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 10);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 16);

    ret = read_tpm_buffer (data->fd,
                           &data->index,
                           data->buf_out,
                           data->buf_size,
                           NULL);
    assert_int_equal (ret, 0);
    assert_int_equal (data->index, data->buf_size);
    assert_memory_equal (data->buf_out, buf_in, data->buf_size);
}
/*
 * This test is a bit weird. We pass a buffer that has already had the header
 * populated and the index incremented to the end of the header. The call to
 * read_tpm_buffer is smart enough to know the header has already been read
 * so it extracts the size from the header. This is however the size of the
 * header and so the function returns before any read operation happens.
 */
static void
read_tpm_buf_populated_header_only_test (void **state)
{
    data_t *data = *state;
    int ret = 0;
    uint8_t buf [10] = {
        0x80, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00
    };

    /* prime read to successfully produce the header */
    data->buf_size = 10;
    data->index = 10;
    memcpy (data->buf_out, buf, data->buf_size);

    ret = read_tpm_buffer (data->fd,
                           &data->index,
                           data->buf_out,
                           data->buf_size,
                           NULL);
    assert_int_equal (ret, 0);
    assert_int_equal (data->index, data->buf_size);
    assert_memory_equal (data->buf_out, buf, data->buf_size);
}
/*
 * This test initializes a buffer as though it has already been populated
 * beyond the header (16 bytes) with the index set accordingly. The call to
 * read_tpm_buffer then picks up where it left off filling in the remainder
 * of the buffer.
 */
static void
read_tpm_buf_populated_body_test (void **state)
{
    data_t *data = *state;
    int ret = 0;

    memcpy (data->buf_out, buf_in, 16);

    /* prime read to successfully produce the header */
    data->index = 16;

    will_return (__wrap_read, buf_in);
    will_return (__wrap_read, 16);
    will_return (__wrap_read, 0);
    will_return (__wrap_read, 10);

    ret = read_tpm_buffer (data->fd,
                           &data->index,
                           data->buf_out,
                           data->buf_size,
                           NULL);
    assert_int_equal (ret, 0);
    assert_int_equal (data->index, data->buf_size);
    assert_memory_equal (data->buf_out, buf_in, data->buf_size);
}

gint
main (gint    argc,
      gchar  *argv[])
{
    const UnitTest tests[] = {
        unit_test (write_in_one),
        unit_test (write_in_two),
        unit_test (write_in_three),
        unit_test (write_error),
        unit_test (write_zero),
        /* read_data tests */
        unit_test_setup_teardown (read_data_success_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_data_short_success_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_data_short_err_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_data_error_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_data_eof_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_data_eintr_test,
                                  read_data_setup,
                                  read_data_teardown),
        /* read_tpm_buf tests */
        unit_test_setup_teardown (read_tpm_buf_success_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_tpm_buf_header_only_success_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_tpm_buf_short_header_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_tpm_buf_lt_header_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_tpm_buf_lt_body_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_tpm_buf_short_body_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_tpm_buf_populated_header_half_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_tpm_buf_populated_header_only_test,
                                  read_data_setup,
                                  read_data_teardown),
        unit_test_setup_teardown (read_tpm_buf_populated_body_test,
                                  read_data_setup,
                                  read_data_teardown),
    };
    return run_tests (tests);
}
