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
 * Implementation of the HTTP Test Tool store.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include "htt_store.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_store_s {
  apr_pool_t *pool;
  apr_hash_t *hash;
};

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Public 
 ***********************************************************************/
htt_store_t *htt_store_new(apr_pool_t *pool) {
  apr_pool_t *mypool;
  apr_pool_create(&mypool, pool);
  htt_store_t *store = apr_pcalloc(mypool, sizeof(*store));
  store->pool = mypool;
  store->hash = apr_hash_make(mypool);
  return store;
}

void htt_store_set(htt_store_t *store, const char *key, void *value) {
  apr_hash_set(store->hash, key, APR_HASH_KEY_STRING, value);
}

void *htt_store_get(htt_store_t *store, const char *key) {
  return apr_hash_get(store->hash, key, APR_HASH_KEY_STRING);
}

