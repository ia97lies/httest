/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. 
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
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
 * Implementation of the HTTP Test Tool dbg module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "htt_modules.h"
#include "htt_bufreader.h"
#include "htt_string.h"
#include "htt_function.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/

/**
 * Simple dbg interpreter
 * @param executable IN static context 
 * @param context IN dynamic context 
 * @param ptmp IN temporary pool
 * @param params IN unused
 * @param retvars IN unused
 * @param unused
 * @return apr status
 */
static apr_status_t _cmd_bp_function(htt_executable_t *executable, 
                                     htt_context_t *context, 
                                     apr_pool_t *ptmp, htt_map_t *params, 
                                     htt_stack_t *retvars, char *unused); 

/************************************************************************
 * Public
 ***********************************************************************/
apr_status_t dbg_module_init(htt_t *htt) {
  return APR_SUCCESS;
}

apr_status_t dbg_module_command_register(htt_t *htt) {
  htt_add_command(htt, "dbg.bp", NULL, "",
                  "Stop script execution in the given thread at the given point. "
                  "With command 'help' or '?' a help text is displayed",
                  htt_cmd_line_compile, _cmd_bp_function);

  return APR_SUCCESS;
}

/************************************************************************
 * Private
 ***********************************************************************/
static apr_status_t _cmd_bp_function(htt_executable_t *executable, 
                                     htt_context_t *context, 
                                     apr_pool_t *ptmp, htt_map_t *params, 
                                     htt_stack_t *retvars, char *unused) {
  apr_status_t status;
  apr_file_t *input;
  apr_file_t *output;
  htt_bufreader_t *bufreader;
  char *line = "";

  if ((status = apr_file_open_stdout(&output, ptmp)) != APR_SUCCESS) {
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "can not open stdout");
    return status;
  }

  apr_file_printf(output, "\nbreak %s:%d", htt_executable_get_file(executable),
                  htt_executable_get_line(executable));
  apr_file_printf(output, "\n>");
  apr_file_flush(output);

  if ((status = apr_file_open_stdin(&input, ptmp)) != APR_SUCCESS) {
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "can not open stdin");
    return status;
  }

  bufreader = htt_bufreader_file_new(ptmp, input);

  for (;;) {
    char *last;
    char *entry;

    if ((status = htt_bufreader_read_line(bufreader, &line)) != APR_SUCCESS) {
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "can not read line from buffered stdin\n");
      return status;
    }
    if (!line[0]) {
      goto prompt;
    }
    entry = apr_strtok(line, " ", &last);
    if (!entry) {
      apr_file_printf(output, "Parser error\n");
      goto prompt;
    }

    if (strcmp(entry, "cont") == 0 || strcmp(entry, "c") == 0) {
      break;
    }
    else if (strcmp(entry, "quit") == 0 || strcmp(entry, "q") == 0) {
      apr_file_printf(output, "Abort\n");
      exit(0);
    }
    else if (strcmp(entry, "get") == 0 || strcmp(entry, "g") == 0) {
      char *variable;
      const char *value_str;
      htt_string_t *value;
      variable = last;
      if (!variable|| !variable[0]) {
        apr_file_printf(output, "Need a variable name as argument\n");
        goto prompt;
      }
      value = htt_context_get_var(context, variable);
      if (!value) {
        char *env;
        if (apr_env_get(&env, variable, ptmp) == APR_SUCCESS) {
          value_str = env;
        }
        else {
          value_str = "<undef>";
        }
      }
      else if (htt_isa_string(value)) {
        value_str = htt_string_get(value);
      }
      else {
        value_str = "<undef>";
      }

      apr_file_printf(output, "%s\n", value_str ? value_str : "<undef>");
    }
    else if (strcmp(entry, "set") == 0 || strcmp(entry, "s") == 0) {
      char *expr = last;
      char *var;
      char *val;
      htt_string_t *value;
      if (!expr || !strchr(expr, '=')) {
        apr_file_printf(output, "Need an assignment <variable>=<ANY>\n");
        goto prompt;
      }
      var = apr_strtok(expr, "=", &val);
      if (!var || !val || !var[0] || !val[0]) {
        apr_file_printf(output, "Need an assignment <variable>=<ANY>\n");
        goto prompt;
      }
      value = htt_string_new(ptmp, val);
      htt_context_set_var(context, var, value);
    }
    else if (strcmp(entry, "list") == 0 || 
             strcmp(entry, "ls") == 0 || 
             strcmp(entry, "l") == 0) {
      apr_status_t status;
      apr_file_t *fp;
      const char *cur_file = htt_executable_get_file(executable);
      int cur_line = htt_executable_get_line(executable);

      cur_line -= 5;
      if (cur_line < 0) {
        cur_line = 0;
      }

      if ((status = apr_file_open(&fp, cur_file, APR_READ, APR_OS_DEFAULT, 
                                  ptmp)) 
          == APR_SUCCESS) {
        int i;
        char *data;
        htt_bufreader_t *filereader = htt_bufreader_file_new(ptmp, fp);
        for (i = 0; i < cur_line; i++) {
          char * dummy;
          htt_bufreader_read_line(filereader, &dummy);
        }

        for (i = 0; i < 10 && 
             htt_bufreader_read_line(filereader, &data) == APR_SUCCESS; i++) {
          apr_file_printf(output, "> %s\n", data);
        }
      }
      else {
        apr_file_printf(output, "Can not open source file \"%s\"", 
                        htt_executable_get_file(executable));
      }
    }
    else {
      apr_file_printf(output, "\"%s\" unknown command\n", line);
    }

prompt:
    apr_file_printf(output, ">");
    apr_file_flush(output);
  }

  return APR_SUCCESS;
}

