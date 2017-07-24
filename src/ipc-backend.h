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
#ifndef IPC_BACKEND_H
#define IPC_BACKEND_H

#include <sapi/tpm20.h>
#include <glib-object.h>

#include "connection.h"

G_BEGIN_DECLS

typedef struct _IpcBackend      IpcBackend;
typedef struct _IpcBackendClass IpcBackendClass;

typedef void (*IpcBackendConnect)    (IpcBackend *self,
                                      GMutex     *mutex);
typedef void (*IpcBackendDisconnect) (IpcBackend *self);

struct _IpcBackend {
    GObject             parent;
    GMutex             *init_mutex;
};

struct _IpcBackendClass {
    GObjectClass         parent;
    IpcBackendConnect    connect;
    IpcBackendDisconnect disconnect;
};

#define TYPE_IPC_BACKEND             (ipc_backend_get_type       ())
#define IPC_BACKEND(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj),   TYPE_IPC_BACKEND, IpcBackend))
#define IS_IPC_BACKEND(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj),   TYPE_IPC_BACKEND))
#define IPC_BACKEND_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST    ((klass), TYPE_IPC_BACKEND, IpcBackendClass))
#define IS_IPC_BACKEND_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE    ((klass), TYPE_IPC_BACKEND))
#define IPC_BACKEND_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS  ((obj),   TYPE_IPC_BACKEND, IpcBackendClass))

GType               ipc_backend_get_type              (void);
void                ipc_backend_connect               (IpcBackend  *self,
                                                       GMutex      *mutex);
void                ipc_backend_disconnect            (IpcBackend  *self);
void                ipc_backend_disconnected_invoke   (IpcBackend  *self);
void                ipc_backend_init_guard            (IpcBackend  *self);

G_END_DECLS
#endif /* IPC_BACKEND_H */
