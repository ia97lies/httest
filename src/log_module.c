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
 * Implementation of the HTTP Test Tool log module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <apr_strings.h>
#include "htt_modules.h"
#include "htt_core.h"
#include "htt_string.h"
#include "htt_util.h"
#include "htt_expr.h"
#include "htt_log.h"
#include "htt_log_std_appender.h"
#include "htt_log_simple_appender.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/

/**
 * Define log appender
 * @param command IN command
 * @param args IN argument string
 * @return apr status
 */
static apr_status_t _cmd_log_compile(htt_command_t *command, char *args); 

/************************************************************************
 * Public
 ***********************************************************************/
apr_status_t log_module_init(htt_t *htt) {
  return APR_SUCCESS;
}

apr_status_t log_module_register(htt_t *htt) {
  htt_add_command(htt, "log.appender.add", NULL, "simple|std", 
                  "add log appender", _cmd_log_compile, NULL);
  return APR_SUCCESS;
}

/************************************************************************
 * Private
 ***********************************************************************/

static apr_status_t _cmd_log_compile(htt_command_t *command, char *args) {
  htt_t *htt = htt_command_get_config(command, "htt");
  htt_log_t *log = htt_get_log(htt);
  apr_pool_t *pool = htt_get_pool(htt);
  apr_file_t *out;
  apr_file_t *err;

  apr_file_open_stdout(&out, pool);
  apr_file_open_stderr(&err, pool);
  apr_collapse_spaces(args, args);
  if (strcmp(args, "simple") == 0) {
    htt_log_set_appender(log, htt_log_simple_appender_new(pool, out, err));
  }
  else if (strcmp(args, "std") == 0) {
    htt_log_set_appender(log, htt_log_std_appender_new(pool, out, err));
  }
  else {
    htt_executable_t *executable = htt_get_executable(htt);
    htt_log_error(htt_get_log(htt), APR_EGENERAL, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Unknown log appender \"%s\"", args);
    htt_throw_error();
  }
  return APR_SUCCESS;
}

