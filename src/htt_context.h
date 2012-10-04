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
 * Interface of the htt context.
 */

#ifndef HTT_CONTEXT_H
#define HTT_CONTEXT_H

#include "htt_map.h"
#include "htt_log.h"

typedef struct htt_context_s htt_context_t;

/**
 * Create a new context
 * @param parent IN parent context
 * @param log IN log instance
 * @return new context object
 */
htt_context_t *htt_context_new(htt_context_t *parent, htt_log_t *log);

/**
 * Get parent context
 * @param context IN context
 * @return parent context
 */
htt_context_t *htt_context_get_parent(htt_context_t *context);

/**
 * Get godfather context, mean the very first
 * @param context IN context
 * @return parent context
 */
htt_context_t *htt_context_get_godfather(htt_context_t *context);

/**
 * Worker set log
 * @param context IN context
 * @param log IN log
 */
void htt_context_set_log(htt_context_t *context, htt_log_t *log); 

/**
 * Worker get log
 * @param context IN context
 * @return log
 */
htt_log_t *htt_context_get_log(htt_context_t *context);

/**
 * Worker get pool
 * @param context IN context
 * @return pool
 */
apr_pool_t *htt_context_get_pool(htt_context_t *context);

/**
 * Context set variables
 * @param context IN context
 */
void htt_context_set_vars(htt_context_t *context, htt_map_t *vars); 

/**
 * Context get variables
 * @param context IN context
 * @return variables
 */
htt_map_t *htt_context_get_vars(htt_context_t *context); 

/**
 * Merge a given var map to my context
 * @param context IN context
 * @param vars IN vars to merge
 */
void htt_context_merge_vars(htt_context_t *context, htt_map_t *vars);

/**
 * Set variable in the context chain from the top most
 * @param context IN context
 * @param variable IN variable name
 * @param value IN
 */
void htt_context_set_var(htt_context_t *context, const char *variable, 
                         void *value); 

/**
 * Get variable in the context chain from the top most
 * @param context IN context
 * @param variable IN variable name
 * @return variable value or NULL
 */
void *htt_context_get_var(htt_context_t *context, const char *variable); 

/**
 * Set a named configuration to this context
 * @param context IN context
 * @param name IN name for stored data
 * @param data IN data to store
 */
void htt_context_set_config(htt_context_t *context, const char *name, 
                            void *data);

/**
 * Get named configuraion form this context
 * @param context IN context
 * @param name IN name for data
 * @return data
 */
void  *htt_context_get_config(htt_context_t *context, const char *name);

/**
 * From the top config back to the grand grand parents look up a config name
 * @param context IN startpoint
 * @param name IN name of the config
 * @return config if any else NULL
 */
void  *htt_context_lookup_config(htt_context_t *context, const char *name); 

/** 
 * Destroy context
 * @param context IN context
 */
void htt_context_destroy(htt_context_t *context);

#endif

