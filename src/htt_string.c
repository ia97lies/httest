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
 * Implementation of the HTTP Test Tool string.
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

#include "htt_string.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_string_s {
#define HTT_STRING_T 1
  int type;
  apr_pool_t *pool;
  const char *value;
};

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Public 
 ***********************************************************************/
htt_string_t *htt_string_new(apr_pool_t *pool, const char *value) {
  apr_pool_t *mypool;
  apr_pool_create(&mypool, pool);
  htt_string_t *string = apr_pcalloc(pool, sizeof(*string));
  string->pool = mypool;
  string->value = apr_pstrdup(mypool, value);
  return string;
}

void htt_string_update(htt_string_t *string, const char *value) {
  apr_pool_t *mypool;
  apr_pool_t *pool = apr_pool_parent_get(string->pool);
  apr_pool_destroy(string->pool);
  apr_pool_create(&mypool, pool);
  string->pool = mypool;
  string->value = apr_pstrdup(mypool, value);
}

const char *htt_string_get(htt_string_t *string) {
  return string->value;
}

const char *htt_string_copy(htt_string_t *string, apr_pool_t *pool) {
  return apr_pstrdup(pool, string->value);
}

int htt_isa_string(void *type) {
  htt_string_t *string = type;
  return (string->type == HTT_STRING_T);
}

