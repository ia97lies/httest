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
 * Interface of the HTTP Test Tool map.
 */

#ifndef HTT_MAP_H
#define HTT_MAP_H

#include <apr_pools.h>

typedef struct htt_map_s htt_map_t;

/**
 * Create a map variable
 * @param pool IN parent pool for inheritance
 * @param value IN map to hold in this map variable
 * @return map instance 
 */
htt_map_t *htt_map_new(apr_pool_t *pool);

/**
 * Set a value
 * @param map IN
 * @param key IN
 * @param value IN a subtype of htt_object_t
 */
void htt_map_set(htt_map_t *map, const char *key, void *value);

/**
 * Get a value
 * @param map IN
 * @param key IN
 * @return value
 */
void *htt_map_get(htt_map_t *map, const char *key);

/**
 * Merge maps together
 * @param map IN my map
 * @param add IN new map
 * @param pool IN pool to realloc entries
 */
void htt_map_merge(htt_map_t *map, htt_map_t *add, apr_pool_t *pool); 

#endif
