/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. 
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
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
#include "store.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef struct store_s {
  apr_pool_t *pool;
  apr_hash_t *hash;
} store_t;

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Implementation
 ***********************************************************************/
APR_DECLARE(store_t *)store_make(apr_pool_t *pool) {
  return NULL;
}

APR_DECLARE(const char *)store_get(store_t *store, const char *name) {
  return NULL;
}

APR_DECLARE(char *)store_get_copy(store_t *store, apr_pool_t *pool, 
                                  const char *name) {
  return NULL;
}

APR_DECLARE(void )store_set(store_t *store, const char *name, 
                            const char *value) {
}

