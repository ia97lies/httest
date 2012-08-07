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
 * Interface of the HTTP Test Tool store.
 */

#ifndef HTT_STORE_H
#define HTT_STORE_H

#include <apr_pools.h>

typedef struct htt_store_s htt_store_t;

/**
 * Create a store variable
 * @param pool IN parent pool for inheritance
 * @param value IN store to hold in this store variable
 * @return store instance 
 */
htt_store_t *htt_store_new(apr_pool_t *pool);

/**
 * Set a value
 * @param store IN
 * @param key IN
 * @param value IN
 */
void htt_store_set(htt_store_t *store, const char *key, void *value);

/**
 * Get a value
 * @param store IN
 * @param key IN
 * @return value
 */
void *htt_store_get(htt_store_t *store, const char *key);

/**
 * Get a value by index, it is a fifo list
 * @param store IN
 * @param index IN 
 * @return value
 */
void *htt_store_index(htt_store_t *store, int index);

#endif
