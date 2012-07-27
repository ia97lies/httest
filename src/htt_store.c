/**
 * Copyright 2010 Christian Liesch
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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <apr.h>
#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_tables.h>
#include <apr_strings.h>

#include "htt_core.h"
#include "htt_store.h"
#include "htt_log.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_store_s {
  apr_pool_t *pool;
  apr_hash_t *hash;
};

typedef struct htt_store_element_s {
  apr_pool_t *pool;
  const char *value;
} htt_store_element_t;

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Public 
 ***********************************************************************/
/**
 * Create store for reusable entries without memory loss
 * @param pool IN pool to alloc this store
 * @return store
 */
htt_store_t *htt_store_new(apr_pool_t *pool) {
  htt_store_t *store = apr_pcalloc(pool, sizeof(*store));
  store->pool = pool;
  store->hash = apr_hash_make(pool);
  return store;
}

/**
 * Get value from store
 * @param store IN store hook
 * @param name IN key
 * @return value
 */
const char *htt_store_get(htt_store_t *store, const char *name) {
  htt_store_element_t *element = apr_hash_get(store->hash, name, APR_HASH_KEY_STRING);
  if (element) {
    return element->value;
  }
  else {
    return NULL;
  }
}

/**
 * Gets a copy of value from store
 * @param store IN store hook
 * @param pool IN pool for value allocation
 * @param name IN key
 * @return value copy from your pool
 */
char *htt_store_get_copy(htt_store_t *store, apr_pool_t *pool, const char *name) {
  const char *value = htt_store_get(store, name);
  if (value) {
    return apr_pstrdup(pool, value);
  }
  else {
    return NULL;
  }
}

/**
 * Set name value, if allready exist delete old name value and reset them.
 * @param store IN store hook
 * @param name IN key
 * @param value IN
 */
void htt_store_set(htt_store_t *store, const char *name, const char *value) {
  apr_pool_t *pool;
  htt_store_element_t *element = apr_hash_get(store->hash, name, APR_HASH_KEY_STRING);
  if (element) {
    apr_pool_destroy(element->pool);
    apr_pool_create(&element->pool, store->pool);
    apr_hash_set(store->hash, name, APR_HASH_KEY_STRING, NULL);
  }
  else {
    apr_pool_create(&pool, store->pool);
    element = apr_pcalloc(store->pool, sizeof(*element));
    element->pool = pool;
  }
  element->value = apr_pstrdup(element->pool, value);
  apr_hash_set(store->hash, apr_pstrdup(element->pool, name), 
	       APR_HASH_KEY_STRING, element);
}

/**
 * Unset name value.
 * @param store IN store hook
 * @param name IN key
 */
void htt_store_unset(htt_store_t *store, const char *name) {
  htt_store_element_t *element = apr_hash_get(store->hash, name, APR_HASH_KEY_STRING);
  if (element) {
    apr_pool_destroy(element->pool);
    apr_pool_create(&element->pool, store->pool);
    apr_hash_set(store->hash, name, APR_HASH_KEY_STRING, NULL);
  }
}

/**
 * Merge a foregin store into my store.
 * @param store IN store hook
 * @param other IN foreign store hook
 */
void htt_store_merge(htt_store_t *store, htt_store_t *other) {
  apr_hash_index_t *i;
  const void *key;
  void *val;
  htt_store_element_t *element;

  if (!store || !other) {
    return;
  }

  for (i = apr_hash_first(other->pool, other->hash); i; i = apr_hash_next(i)) {
    apr_hash_this(i, &key, NULL, &val);
    element = val;
    htt_store_set(store, key, element->value);
  }
}

/**
 * Get number of key/values.
 * @param store IN store hook
 * @return count
 */
apr_size_t htt_store_get_size(htt_store_t *store) {
  return apr_hash_count(store->hash);
}

/**
 * Copy store
 * @param store IN store hook
 * @param pool IN pool for new store 
 * @return new store
 */
htt_store_t *htt_store_copy(htt_store_t *store, apr_pool_t *pool) {
  htt_store_t *copy = htt_store_new(pool);
  htt_store_merge(copy, store);
  return copy;
}

/**
 * Get table of key/values for iteration
 * @param store IN store hook
 * @param pool IN to allocate keys table
 * @return table of key/values
 */
apr_table_t *htt_store_get_table(htt_store_t *store, apr_pool_t *pool) {
  apr_hash_index_t *i;
  const void *key;
  void *val;
  htt_store_element_t *element;
  apr_table_t *table = apr_table_make(pool, 5);

  for (i = apr_hash_first(pool, store->hash); i; i = apr_hash_next(i)) {
    apr_hash_this(i, &key, NULL, &val);
    element = val;
    apr_table_set(table, key, element->value);
  }
  return table;
}

