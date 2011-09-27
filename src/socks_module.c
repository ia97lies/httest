/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. 
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
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
 * Implementation of the HTTP Test Tool socks module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Local 
 ***********************************************************************/

/************************************************************************
 * Commands 
 ***********************************************************************/
static apr_status_t socks_hook_connect(worker_t *worker) {
  return APR_SUCCESS;
}

static apr_status_t ssl_client_port_args(worker_t *worker, char *portinfo, 
                                         char **new_portinfo, char *rest) {
  return APR_SUCCESS;
}
/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t socks_module_init(global_t *global) {
  htt_hook_connect(socks_hook_connect, NULL, NULL, 0);
  htt_hook_client_port_args(socks_client_port_args, NULL, NULL, 0);
  return APR_SUCCESS;
}

