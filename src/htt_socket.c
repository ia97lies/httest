/**
 * Copyright 2010 Christian Liesch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file
 *
 * @Author christian liesch <liesch@gmx.ch>
 *
 * Implementation of the HTTP Test Tool socket.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <apr.h>
#include <apr_pools.h>
#include <apr_hash.h>

#include "htt_object.h"
#include "htt_socket.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_socket_s {
#define HTT_SOCKET_T 3
  htt_object_t obj;
#define HTT_SOCKET_CLOSED 0
#define HTT_SOCKET_CONNECTED 1
  int state;
  apr_hash_t *config;

};

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Public 
 ***********************************************************************/
htt_socket_t *htt_socket_new(apr_pool_t *pool) {
  apr_pool_t *mypool;
  htt_socket_t *socket;
  apr_pool_create(&mypool, pool);
  socket = apr_pcalloc(mypool, sizeof(*socket));
  socket->obj.type = HTT_SOCKET_T;
  socket->obj.pool = mypool;
  socket->obj.destructor = htt_socket_free;
  socket->obj.clone = htt_socket_clone;
  socket->state = HTT_SOCKET_CLOSED;
  socket->config = apr_hash_make(mypool);
  return socket;
}

void *htt_socket_clone(void *vsocket, apr_pool_t *pool) {
  htt_socket_t *socket = vsocket;
  htt_socket_t *clone = htt_socket_new(pool);
  clone->state = socket->state;
  return clone;
}

int htt_isa_socket(void *type) {
  htt_socket_t *socket = type;
  return (socket && socket->obj.type == HTT_SOCKET_T);
}

void htt_socket_free(void *vsocket) {
  htt_socket_t *socket = vsocket;
  apr_pool_destroy(socket->obj.pool);
}

