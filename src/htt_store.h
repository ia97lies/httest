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
#include <apr_tables.h>

typedef struct htt_store_s htt_store_t;

/**
 * Create store for reusable entries without memory loss
 * @param pool IN pool to alloc this store
 * @return store
 */
htt_store_t *htt_store_new(apr_pool_t *pool);

/**
 * Get value from store
 * @param store IN store hook
 * @param name IN key
 * @return value
 */
const char *htt_store_get(htt_store_t *store, const char *name);

/**
 * Gets a copy of value from store
 * @param store IN store hook
 * @param pool IN pool for value allocation
 * @param name IN key
 * @return value copy from your pool
 */
char *htt_store_get_copy(htt_store_t *store, apr_pool_t *pool, const char *name);

/**
 * Set name value, if allready exist delete old name value and reset them.
 * @param store IN store hook
 * @param name IN key
 * @param value IN
 */
void htt_store_set(htt_store_t *store, const char *name, const char *value);

/**
 * Unset name value.
 * @param store IN store hook
 * @param name IN key
 */
void htt_store_unset(htt_store_t *store, const char *name);

/**
 * Merge a foregin store into my store.
 * @param store IN store hook
 * @param other IN foreign store hook
 */
void htt_store_merge(htt_store_t *store, htt_store_t *other);

/**
 * Get number of key/values.
 * @param store IN store hook
 * @return count
 */
apr_size_t htt_store_get_size(htt_store_t *store);

/**
 * Copy store
 * @param store IN store hook
 * @param pool IN pool for new store 
 * @return new store
 */
htt_store_t *htt_store_copy(htt_store_t *store, apr_pool_t *pool);

/**
 * Get table of key/values for iteration
 * @param store IN store hook
 * @param pool IN to allocate keys table
 * @return table of key/values
 */
apr_table_t *htt_store_get_table(htt_store_t *store, apr_pool_t *pool);

#endif
