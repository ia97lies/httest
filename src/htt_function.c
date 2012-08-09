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
 * Implementation of the HTTP Test Tool function.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <apr.h>
#include <apr_pools.h>

#include "htt_context.h"
#include "htt_executable.h"
#include "htt_function.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_function_s {
#define HTT_FUNCTION_T 2
  int type;
  apr_pool_t *pool;
  htt_executable_t *executable;
  htt_context_t *context;
};

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Public 
 ***********************************************************************/
htt_function_t *htt_function_new(apr_pool_t *pool, htt_executable_t *executable,
                                 htt_context_t *context) {
  apr_pool_t *mypool;

  apr_pool_create(&mypool, pool);
  htt_function_t *function = apr_pcalloc(mypool, sizeof(*function));
  function->pool = pool;
  function->type = HTT_FUNCTION_T;
  function->executable = executable;
  /* TODO: potential memory loss, do need a reference counter for context */
  function->context = context;
  return function;
}

htt_executable_t *htt_function_get_executable(htt_function_t *function) {
  return function->executable;
}

htt_context_t *htt_function_get_context(htt_function_t *function) {
  return function->context;
}

int htt_isa_function(void *type) {
  htt_function_t *function = type;
  return (function->type == HTT_FUNCTION_T);
}

void htt_function_free(void *vfunction) {
  htt_function_t *function = vfunction;
  apr_pool_destroy(function->pool);
}
