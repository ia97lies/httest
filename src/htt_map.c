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
 * Implementation of the HTTP Test Tool map.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include "htt_map.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_map_s {
  apr_pool_t *pool;
  apr_hash_t *hash;
};

typedef struct htt_elem_s {
  htt_destructor_f destructor;
  void *elem;
} htt_elem_t;

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Public 
 ***********************************************************************/
htt_map_t *htt_map_new(apr_pool_t *pool) {
  apr_pool_t *mypool;
  apr_pool_create(&mypool, pool);
  htt_map_t *map = apr_pcalloc(mypool, sizeof(*map));
  map->pool = mypool;
  map->hash = apr_hash_make(mypool);
  return map;
}

void htt_map_set(htt_map_t *map, const char *key, void *value, 
                   htt_destructor_f destructor) {
  htt_elem_t *e = apr_hash_get(map->hash, key, APR_HASH_KEY_STRING);
  
  if (e) {
    e->destructor(e->elem);
    e->elem = value;
    e->destructor = destructor;
  }
  else {
    e = apr_pcalloc(map->pool, sizeof(*e));
    e->elem = value;
    e->destructor = destructor;
    apr_hash_set(map->hash, apr_pstrdup(map->pool, key), 
                 APR_HASH_KEY_STRING, e);
  }
}

void *htt_map_get(htt_map_t *map, const char *key) {
  htt_elem_t *e = apr_hash_get(map->hash, key, APR_HASH_KEY_STRING);
  if (e) {
    return e->elem;
  }
  else {
    return NULL;
  }
}

