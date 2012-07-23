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
 * Interface of the HTTP Test Tool store.
 */

#ifndef HTT_STORE_H
#define HTT_STORE_H

#include <apr_pools.h>
#include <apr_tables.h>

typedef struct htt_store_s htt_store_t;

htt_store_t *htt_store_make(apr_pool_t *pool);
const char *htt_store_get(htt_store_t *store, const char *name);
char *htt_store_get_copy(htt_store_t *store, apr_pool_t *pool, const char *name);
void htt_store_set(htt_store_t *store, const char *name, const char *value);
void htt_store_unset(htt_store_t *store, const char *name);
void htt_store_merge(htt_store_t *store, htt_store_t *other); 
apr_size_t htt_store_get_size(htt_store_t *store); 
htt_store_t *htt_store_copy(htt_store_t *store, apr_pool_t *pool);
apr_table_t *htt_store_get_table(htt_store_t *store, apr_pool_t *pool);

#endif
