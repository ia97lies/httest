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

#include "htt_command.h"
#include "htt_executable.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_command_s {
  const char *name;
  const char *signature;
  const char *short_desc;
  const char *desc;
  apr_hash_t *config;
  htt_compile_f compile;
  htt_function_f function;
};

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Public 
 ***********************************************************************/
htt_command_t *htt_command_new(apr_pool_t *pool,  const char *name, 
                               const char *signature, const char *short_desc, 
                               const char *desc, htt_compile_f compile, 
                               htt_function_f function) {
  htt_command_t *command = apr_pcalloc(pool, sizeof(*command));
  command->name = name;
  command->signature = signature;
  command->short_desc = short_desc;
  command->desc = desc;
  command->compile = compile;
  command->function = function;
  command->config = apr_hash_make(pool);
  return command;
}

void htt_command_set_config(htt_command_t *command, const char *name, 
                            void *data) {
  apr_hash_set(command->config, name, APR_HASH_KEY_STRING, data);
}

void *htt_command_get_config(htt_command_t *command, const char *name) {
  return apr_hash_get(command->config, name, APR_HASH_KEY_STRING);
}

const char *htt_command_get_name(htt_command_t *command) {
  return command->name;
}

const char *htt_command_get_signature(htt_command_t *command) {
  return command->signature;
}

const char *htt_command_get_short_desc(htt_command_t *command) {
  return command->short_desc;
}

const char *htt_command_get_desc(htt_command_t *command) {
  return command->desc;
}

htt_function_f htt_command_get_function(htt_command_t *command) {
  return command->function;
}

apr_status_t htt_command_compile(htt_command_t *command, char *args) {
  return command->compile(command, args);
}

