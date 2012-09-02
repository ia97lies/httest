/**
 * Copyright 2012 Christian Liesch
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
 * Interface of the HTTP Test Tool socket.
 */

#ifndef HTT_SOCKET_H
#define HTT_SOCKET_H

#include <apr_pools.h>

typedef struct htt_socket_s htt_socket_t;

/**
 * Create a socket variable
 * @param pool IN parent pool for inheritance
 * @param value IN socket to hold in this socket variable
 * @return socket instance 
 */
htt_socket_t *htt_socket_new(apr_pool_t *pool);

/**
 * Clone a socket variable
 * @param socket IN socket to clone
 * @param pool IN parent pool for inheritance
 * @return socket instance 
 */
void *htt_socket_clone(void *socket, apr_pool_t *pool); 

/**
 * Test if a pointer is a socket type
 * @param void IN possible socket pointer
 * @return 1 if it is a socket type
 */
int htt_isa_socket(void *type);

/**
 * Free socket
 * @param socket IN
 */
void htt_socket_free(void *socket); 

#endif
