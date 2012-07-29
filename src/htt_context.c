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
#include <apr_hash.h>
#include "htt_context.h"

struct htt_context_s {
  apr_pool_t *pool;
  htt_context_t *parent;
  htt_log_t *log;
  apr_hash_t *config;
}; 

/**
 * Create a new context
 * @param parent IN parent context
 * @param log IN log instance
 * @return new context object
 */
htt_context_t *htt_context_new(htt_context_t *parent, htt_log_t *log) {
  apr_pool_t *pool;
  
  apr_pool_create(&pool, parent ? parent->pool : NULL);
  htt_context_t *context = apr_pcalloc(pool, sizeof(*context));
  context->pool = pool;
  context->parent = parent;
  context->log = log;
  context->config = apr_hash_make(pool);
  return context;
}

/**
 * Get parent context
 * @param context IN context
 * @return parent context
 */
htt_context_t *htt_context_get_parent(htt_context_t *context) {
  return context->parent;
}

/**
 * Get godfather context, mean the very first
 * @param context IN context
 * @return parent context
 */
htt_context_t *htt_context_get_godfather(htt_context_t *context) {
  htt_context_t *cur = context;

  while (cur->parent) {
    cur = cur->parent;
  }
  return cur;
}

/**
 * Worker get log
 * @param context IN context
 * @return log
 */
htt_log_t *htt_context_get_log(htt_context_t *context) {
  return context->log;
}

/**
 * Worker get pool
 * @param context IN context
 * @return pool
 */
apr_pool_t *htt_context_get_pool(htt_context_t *context) {
  return context->pool;
}

/**
 * Set a named configuration to this context
 * @param context IN context
 * @param name IN name for stored data
 * @param data IN data to store
 */
void htt_context_set_config(htt_context_t *context, const char *name, void *data) {
  apr_hash_set(context->config, name, APR_HASH_KEY_STRING, data);
}

/**
 * Get named configuraion form this context
 * @param context IN context
 * @param name IN name for data
 * @return data
 */
void  *htt_context_get_config(htt_context_t *context, const char *name) {
  return apr_hash_get(context->config, name, APR_HASH_KEY_STRING);
}

/** 
 * Destroy context
 * @param context IN context
 */
void htt_context_destroy(htt_context_t *context) {
  apr_pool_destroy(context->pool);
}


