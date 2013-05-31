/**
 * Copyright 2006 Christian Liesch
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
 * Interface of the HTTP Test Tool util.
 */

#ifndef HTTEST_BODY_H
#define HTTEST_BODY_H

apr_status_t worker_body(worker_t **body, worker_t *worker); 
void worker_body_end(worker_t *body, worker_t *worker); 
apr_status_t command_IF(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_LOOP(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_FOR(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_BPS(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_RPS(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_SOCKET(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_ERROR(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_MILESTONE(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 

#endif
