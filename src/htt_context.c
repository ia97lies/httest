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
#include "htt_store.h"
#include "htt_context.h"
#include "htt_replacer.h"
#include "htt_string.h"
#include "htt_function.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_context_s {
  apr_pool_t *pool;
  apr_pool_t *tmp_pool;
  htt_store_t *vars;
  htt_context_t *parent;
  htt_log_t *log;
  const char *line;
  apr_hash_t *config;
}; 

/**
 * Replacer to resolve variables in a line
 * @param udata IN context pointer
 * @param name IN name of variable to resolve
 * @return variable value
 */
static const char *_context_replacer(void *udata, const char *name); 

/************************************************************************
 * Public
 ***********************************************************************/
htt_context_t *htt_context_new(htt_context_t *parent, htt_log_t *log) {
  apr_pool_t *pool;
  
  apr_pool_create(&pool, parent ? parent->pool : NULL);
  htt_context_t *context = apr_pcalloc(pool, sizeof(*context));
  apr_pool_create(&context->tmp_pool, pool);
  context->pool = pool;
  context->parent = parent;
  context->log = log;
  context->config = apr_hash_make(pool);
  context->vars = htt_store_new(pool);
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

apr_pool_t *htt_context_get_tmp_pool(htt_context_t *context) {
  return context->tmp_pool;
}

void htt_context_flush_tmp(htt_context_t *context) {
  apr_pool_destroy(context->tmp_pool);
  apr_pool_create(&context->tmp_pool, context->pool);
}

void htt_context_set_vars(htt_context_t *context, htt_store_t *vars) {
  context->vars = vars;
}

void *htt_context_get_var(htt_context_t *context, const char *variable) {
  htt_context_t *top = context;
  void *elem = NULL;

  while (top && !elem) {
    elem = htt_store_get(top->vars, variable);
    top = htt_context_get_parent(top);
  }

  return elem;
}

void htt_context_set_line(htt_context_t *context, const char *signature, 
                          const char *line) {
  char *new_line;
  /** TODO: handle signature and split line with the rule of signature */
  /* if signature is NULL place the hole line in the first  parameter */
  /* resolve it */
  new_line = apr_pstrdup(context->tmp_pool, line);
  context->line = htt_replacer(context->tmp_pool, new_line, context, 
                               _context_replacer);
}

const char *htt_context_get_line(htt_context_t *context) {
  /** TODO: handle signature, maybe this function becoms obsolete */
  return context->line;
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

/************************************************************************
 * Private
 ***********************************************************************/
static const char *_context_replacer(void *udata, const char *name) {
  htt_context_t *context = udata;
  htt_string_t *string;

  string = htt_context_get_var(context, name); 
  if (htt_isa_string(string)) {
    return htt_string_get(string);
  }
  else {
    return NULL;
  }
}
