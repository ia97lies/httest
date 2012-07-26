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
 * Implementation of the htt worker.
 */

#include <apr_pools.h>
#include <apr_hash.h>
#include "htt_worker.h"

struct htt_worker_s {
  apr_pool_t *pool;
  htt_worker_t *parent;
  htt_log_t *log;
  apr_hash_t *config;
}; 

/**
 * Create a new worker
 * @param parent IN parent worker
 * @param log IN log instance
 * @return new worker object
 */
htt_worker_t *htt_worker_new(htt_worker_t *parent, htt_log_t *log) {
  apr_pool_t *pool;
  
  apr_pool_create(&pool, parent->pool);
  htt_worker_t *worker = apr_pcalloc(pool, sizeof(*worker));
  worker->pool = pool;
  worker->parent = parent;
  worker->log = log;
  worker->config = apr_hash_make(pool);
  return worker;
}

/**
 * Get parent worker
 * @param worker IN worker
 * @return parent worker
 */
htt_worker_t *htt_worker_get_parent(htt_worker_t *worker) {
  return worker->parent;
}

/**
 * Worker get log instance
 * @param worker IN worker
 * @return log instance
 */
htt_log_t *htt_worker_get_log(htt_worker_t *worker) {
  return worker->log;
}

/**
 * Set a named configuration to this worker
 * @param worker IN worker
 * @param name IN name for stored data
 * @param data IN data to store
 */
void htt_worker_set_config(htt_worker_t *worker, const char *name, void *data) {
  apr_hash_set(worker->config, name, APR_HASH_KEY_STRING, data);
}

/**
 * Get named configuraion form this worker
 * @param worker IN worker
 * @param name IN name for data
 * @return data
 */
void  *htt_worker_get_config(htt_worker_t *worker, const char *name) {
  return apr_hash_get(worker->config, name, APR_HASH_KEY_STRING);
}

/** 
 * Destroy worker
 * @param worker IN worker
 */
void htt_worker_destroy(htt_worker_t *worker) {
  apr_pool_destroy(worker->pool);
}

