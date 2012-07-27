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
 * Interface of the htt worker.
 */

#ifndef HTT_WORKER_H
#define HTT_WORKER_H

#include "htt_log.h"

typedef struct htt_worker_s htt_worker_t;

htt_worker_t *htt_worker_new(htt_worker_t *parent, htt_log_t *log);
htt_worker_t *htt_worker_get_parent(htt_worker_t *worker);
void htt_worker_set_config(htt_worker_t *worker, const char *key, void *data);
void  *htt_worker_get_config(htt_worker_t *worker, const char *key);
htt_log_t *htt_worker_get_log(htt_worker_t *worker);
apr_pool_t *htt_worker_get_pool(htt_worker_t *worker);
void htt_worker_destroy(htt_worker_t *worker);

#endif

