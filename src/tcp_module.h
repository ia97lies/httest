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
 * Interface of the HTTP Test Tool store.
 */

#ifndef HTTEST_TCP_MODULE_H
#define HTTEST_TCP_MODULE_H

apr_status_t tcp_listen(worker_t *worker, char *address, int backlog); 
apr_status_t tcp_connect(worker_t *worker, char *hostname, char *portname);
apr_status_t tcp_accept(worker_t *worker); 
apr_status_t tcp_close(worker_t *worker); 

#endif
