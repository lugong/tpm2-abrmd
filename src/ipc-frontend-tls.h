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
#ifndef IPC_FRONTEND_TLS_H
#define IPC_FRONTEND_TLS_H

#include <glib-object.h>
#include <gio/gio.h>

#include "connection-manager.h"
#include "ipc-frontend.h"
#include "random.h"
#include "tabrmd-generated.h"

G_BEGIN_DECLS

#define IPC_FRONTEND_SOCKET_IP_DEFAULT "127.0.0.1"
#define IPC_FRONTEND_SOCKET_PORT_DEFAULT 4433
#define IPC_FRONTEND_SOCKET_FAMILY_DEFAULT G_SOCKET_FAMILY_IPV4

typedef struct _IpcFrontendTlsClass {
   IpcFrontendClass     parent;
} IpcFrontendTlsClass;

typedef struct _IpcFrontendTls
{
    IpcFrontend        parent_instance;
    /* data set by GObject properties */
    gchar             *socket_ip;
    guint              socket_port;
    GTlsCertificate   *tls_cert;
    /* private data */
    guint              max_transient_objects;
    ConnectionManager *connection_manager;
    GSocket           *socket;
} IpcFrontendTls;

#define TYPE_IPC_FRONTEND_TLS             (ipc_frontend_tls_get_type       ())
#define IPC_FRONTEND_TLS(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj),   TYPE_IPC_FRONTEND_TLS, IpcFrontendTls))
#define IPC_FRONTEND_TLS_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST    ((klass), TYPE_IPC_FRONTEND_TLS, IpcFrontendTlsClass))
#define IS_IPC_FRONTEND_TLS(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj),   TYPE_IPC_FRONTEND_TLS))
#define IS_IPC_FRONTEND_TLS_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE    ((klass), TYPE_IPC_FRONTEND_TLS))
#define IPC_FRONTEND_TLS_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS  ((obj),   TYPE_IPC_FRONTEND_TLS, IpcFrontendTlsClass))

GType           ipc_frontend_tls_get_type   (void);

IpcFrontendTls* ipc_frontend_tls_new        (const gchar       *socket_ip,
                                             guint              socket_port,
                                             ConnectionManager *connection_manager,
                                             guint              max_trans,
                                             const gchar       *cert_file);
void            ipc_frontend_tls_connect    (IpcFrontendTls    *self,
                                             GMutex            *init_mutex);
void            ipc_frontend_tls_disconnect (IpcFrontendTls    *self);

G_END_DECLS
#endif /* IPC_FRONTEND_TLS_H */
