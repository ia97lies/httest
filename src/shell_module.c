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
 * Implementation of the HTTP Test Tool shell module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <apr_strings.h>
#include "htt_modules.h"
#include "htt_core.h"
#include "htt_string.h"
#include "htt_bufreader.h"
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
static apr_status_t _cmd_exec_function(htt_executable_t *executable, 
                                       htt_context_t *context,
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line);

/************************************************************************
 * Public
 ***********************************************************************/
apr_status_t shell_module_init(htt_t *htt) {
  htt_add_command(htt, "exec", NULL, 
                  "shell command", "execute a shell command", 
                  htt_cmd_line_compile, _cmd_exec_function);
  return APR_SUCCESS;
}

/************************************************************************
 * Private
 ***********************************************************************/
static apr_status_t _cmd_exec_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line) {
  const char * const*args;
  const char *progname;
  apr_status_t status;

  htt_util_to_argv(line, (char ***)&args, ptmp, 1);
  progname = args[0];

  if (progname) {
    apr_procattr_t *attr;
    apr_proc_t proc;
    if ((status = apr_procattr_create(&attr, ptmp)) 
        == APR_SUCCESS &&
        (status = apr_procattr_cmdtype_set(attr, APR_SHELLCMD_ENV)) 
        == APR_SUCCESS &&
        (status = apr_procattr_detach_set(attr, 0)) 
        == APR_SUCCESS && 
        (status = apr_procattr_error_check_set(attr, 1)) 
        == APR_SUCCESS && 
        (status = apr_procattr_io_set(attr,  APR_NO_PIPE, APR_FULL_BLOCK, 
                                      APR_NO_PIPE)) 
        == APR_SUCCESS) {

      if ((status = apr_proc_create(&proc, progname, args, NULL, attr,
                                    ptmp)) != APR_SUCCESS) {
        return status;
      }

      /** TODO: read content and wait termination, need a good concept for this */
      /**       want to use exec also as filters, feeders, etc. */
      {
        htt_bufreader_t *br;
        apr_size_t len = 0;
        char *buf = NULL;
        apr_exit_why_e exitwhy;
        int exitcode;

        br = htt_bufreader_file_new(ptmp, proc.out);
        if (br) {
          status = APR_SUCCESS;
          htt_bufreader_read_eof(br, &buf, &len);
          htt_log_buf(htt_context_get_log(context), HTT_LOG_INFO, buf, len, 
                      "<");
          status = htt_expect_assert(executable, context, "exec", buf, len);
          if (status == APR_SUCCESS) {
            status = htt_expect_check(executable, context);
          }
        }
        else {
          htt_log_error(htt_context_get_log(context), status, 
                        htt_executable_get_file(executable), 
                        htt_executable_get_line(executable), 
                        "Could not read stdout");
          apr_proc_wait(&proc, &exitcode, &exitwhy, APR_WAIT);
          apr_file_close(proc.in);
          apr_file_close(proc.out);
        }
      }
    }
    else {
      htt_log_error(htt_context_get_log(context), status, 
                    htt_executable_get_file(executable), 
                    htt_executable_get_line(executable), 
                    "Could not create execute attributes");
    }
  }
  else {
    status = APR_EGENERAL;
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Need at least a command to execute");
  }
  
  return status;
}

