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
 * Implementation of the HTTP Test Tool skeleton module 
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

/************************************************************************
 * Definitions 
 ***********************************************************************/

/**
 * Simple exec command 
 * @param executable IN executable
 * @param context IN running context
 * @param ptmp IN pool
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @return apr status
 */
static apr_status_t _cmd_foo_function(htt_executable_t *executable, 
                                      htt_context_t *context,
                                      apr_pool_t *ptmp, htt_map_t *params, 
                                      htt_stack_t *retvars, char *line);

/************************************************************************
 * Public
 ***********************************************************************/
apr_status_t skeleton_module_init(htt_t *htt) {
  htt_add_command(htt, "foo", "p1 p2 : r1", "input: p1 p2, output: r1", 
                  "foo command", htt_cmd_line_compile, _cmd_exec_function);
  return APR_SUCCESS;
}

/************************************************************************
 * Private
 ***********************************************************************/
static apr_status_t _cmd_foo_function(htt_executable_t *executable, 
                                      htt_context_t *context, 
                                      apr_pool_t *ptmp, htt_map_t *params, 
                                      htt_stack_t *retvars, char *line) {
  return APR_SUCCESS;
}

