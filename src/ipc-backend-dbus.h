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
#ifndef IPC_BACKEND_DBUS_H
#define IPC_BACKEND_DBUS_H

#include <glib-object.h>
#include <gio/gio.h>

#include "connection-manager.h"
#include "ipc-backend.h"
#include "random.h"
#include "tabrmd-generated.h"

G_BEGIN_DECLS

#define IPC_BACKEND_DBUS_NAME_DEFAULT "com.intel.tss2.Tabrmd"
#define IPC_BACKEND_DBUS_TYPE_DEFAULT G_BUS_TYPE_SYSTEM

typedef struct _IpcBackendDbusClass {
   IpcBackendClass     parent;
} IpcBackendDbusClass;

typedef struct _IpcBackendDbus
{
    IpcBackend         parent_instance;
    /* data set by GObject properties */
    gchar             *bus_name;
    GBusType           bus_type;
    /* private data */
    guint              dbus_name_owner_id;
    guint              max_transient_objects;
    ConnectionManager *connection_manager;
    GDBusProxy        *dbus_daemon_proxy;
    Random            *random;
    TctiTabrmd        *skeleton;
} IpcBackendDbus;

#define TYPE_IPC_BACKEND_DBUS             (ipc_backend_dbus_get_type       ())
#define IPC_BACKEND_DBUS(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj),   TYPE_IPC_BACKEND_DBUS, IpcBackendDbus))
#define IPC_BACKEND_DBUS_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST    ((klass), TYPE_IPC_BACKEND_DBUS, IpcBackendDbusClass))
#define IS_IPC_BACKEND_DBUS(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj),   TYPE_IPC_BACKEND_DBUS))
#define IS_IPC_BACKEND_DBUS_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE    ((klass), TYPE_IPC_BACKEND_DBUS))
#define IPC_BACKEND_DBUS_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS  ((obj),   TYPE_IPC_BACKEND_DBUS, IpcBackendDbusClass))

GType           ipc_backend_dbus_get_type   (void);

IpcBackendDbus* ipc_backend_dbus_new        (GBusType           bus_type,
                                             gchar const       *bus_name,
                                             ConnectionManager *connection_manager,
                                             guint              max_trans,
                                             Random            *random);
void            ipc_backend_dbus_connect    (IpcBackendDbus    *self,
                                             GMutex            *init_mutex);
void            ipc_backend_dbus_disconnect (IpcBackendDbus    *self);

G_END_DECLS
#endif /* IPC_BACKEND_DBUS_H */
