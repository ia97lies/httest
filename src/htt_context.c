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
 * Implementation of the htt context.
 */

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_hash.h>
#include "htt_map.h"
#include "htt_context.h"
#include "htt_replacer.h"
#include "htt_string.h"
#include "htt_function.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_context_s {
  apr_pool_t *pool;
  htt_map_t *vars;
  htt_context_t *parent;
  htt_log_t *log;
  const char *line;
  apr_hash_t *config;
}; 

/************************************************************************
 * Public
 ***********************************************************************/
htt_context_t *htt_context_new(htt_context_t *parent, htt_log_t *log) {
  apr_pool_t *pool;
  
  apr_pool_create(&pool, parent ? parent->pool : NULL);
  htt_context_t *context = apr_pcalloc(pool, sizeof(*context));
  context->pool = pool;
  context->parent = parent;
  context->log = log;
  context->config = apr_hash_make(pool);
  context->vars = htt_map_new(pool);
  return context;
}

htt_context_t *htt_context_get_parent(htt_context_t *context) {
  return context->parent;
}

htt_context_t *htt_context_get_godfather(htt_context_t *context) {
  htt_context_t *cur = context;

  while (cur->parent) {
    cur = cur->parent;
  }
  return cur;
}

htt_log_t *htt_context_get_log(htt_context_t *context) {
  return context->log;
}

apr_pool_t *htt_context_get_pool(htt_context_t *context) {
  return context->pool;
}

void htt_context_set_vars(htt_context_t *context, htt_map_t *vars) {
  context->vars = vars;
}

htt_map_t *htt_context_get_vars(htt_context_t *context) {
  return context->vars;
}

void htt_context_merge_vars(htt_context_t *context, htt_map_t *vars) {
  htt_map_merge(context->vars, vars);
}

void *htt_context_get_var(htt_context_t *context, const char *variable) {
  htt_context_t *top = context;
  void *elem = NULL;

  while (top && !elem) {
    elem = htt_map_get(top->vars, variable);
    top = htt_context_get_parent(top);
  }

  return elem;
}

void htt_context_set_var(htt_context_t *context, const char *variable, 
                         void *value) {
  htt_map_t *vars;
  htt_context_t *cur = context;

  vars = htt_context_get_vars(cur);
  while (cur && !htt_map_get(vars, variable)) {
    cur = htt_context_get_parent(cur);
    if (cur) {
      vars = htt_context_get_vars(cur);
    }
  } 
  if (!cur) {
    cur = htt_context_get_godfather(context);
  }
  if (!vars) {
    vars = htt_context_get_vars(cur);
  }
  htt_map_set(vars, variable, value);
}

void htt_context_set_config(htt_context_t *context, const char *name, void *data) {
  apr_hash_set(context->config, name, APR_HASH_KEY_STRING, data);
}

void  *htt_context_get_config(htt_context_t *context, const char *name) {
  return apr_hash_get(context->config, name, APR_HASH_KEY_STRING);
}

void htt_context_destroy(htt_context_t *context) {
  apr_pool_destroy(context->pool);
}

