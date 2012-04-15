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

#ifndef HTTEST_STORE_H
#define HTTEST_STORE_H

#include <apr_pools.h>
#include <apr_tables.h>

typedef struct store_s store_t;

store_t *store_make(apr_pool_t *pool);
const char *store_get(store_t *store, const char *name);
char *store_get_copy(store_t *store, apr_pool_t *pool, const char *name);
void store_set(store_t *store, const char *name, const char *value);
void store_unset(store_t *store, const char *name);
void store_merge(store_t *store, store_t *other); 
apr_size_t store_get_size(store_t *store); 
store_t *store_copy(store_t *store, apr_pool_t *pool);
apr_table_t *store_get_table(store_t *store, apr_pool_t *pool);

#endif
