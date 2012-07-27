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
 * Interface of the htt worker.
 */

#ifndef HTT_WORKER_H
#define HTT_WORKER_H

#include "htt_log.h"
#include "htt_store.h"

typedef struct htt_worker_s htt_worker_t;

/**
 * Create a new worker
 * @param parent IN parent worker
 * @param log IN log instance
 * @return new worker object
 */
htt_worker_t *htt_worker_new(htt_worker_t *parent, htt_log_t *log);

/**
 * Get parent worker
 * @param worker IN worker
 * @return parent worker
 */
htt_worker_t *htt_worker_get_parent(htt_worker_t *worker);

/**
 * Get godfather worker, mean the very first
 * @param worker IN worker
 * @return parent worker
 */
htt_worker_t *htt_worker_get_godfather(htt_worker_t *worker);

/**
 * Worker get log
 * @param worker IN worker
 * @return log
 */
htt_log_t *htt_worker_get_log(htt_worker_t *worker);

/**
 * Worker get pool
 * @param worker IN worker
 * @return pool
 */
apr_pool_t *htt_worker_get_pool(htt_worker_t *worker);

/**
 * Set a named configuration to this worker
 * @param worker IN worker
 * @param name IN name for stored data
 * @param data IN data to store
 */
void htt_worker_set_config(htt_worker_t *worker, const char *name, void *data);

/**
 * Get named configuraion form this worker
 * @param worker IN worker
 * @param name IN name for data
 * @return data
 */
void  *htt_worker_get_config(htt_worker_t *worker, const char *name);

/** 
 * Destroy worker
 * @param worker IN worker
 */
void htt_worker_destroy(htt_worker_t *worker);

/**
 * Return variable store
 * @param worker IN worker
 * @preturn variable store
 */
htt_store_t *htt_worker_get_vars(htt_worker_t *worker);


#endif

