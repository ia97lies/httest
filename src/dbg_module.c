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
#include "store.h"
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Local 
 ***********************************************************************/
/**
 * Simple dbg interpreter
 * @param worker IN callee
 * @param parent IN caller
 * @param pool IN temporary pool
 * @return apr status
 */
static apr_status_t dbg_interpreter(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  apr_file_t *input;
  apr_file_t *output;
  bufreader_t *bufreader;
  char *line = "";

  if ((status = apr_file_open_stdout(&output, ptmp)) != APR_SUCCESS) {
    worker_log_error(worker, "Can not open stdout");
    return status;
  }

  apr_file_printf(output, "\nbreak %s", worker->file_and_line);
  apr_file_printf(output, "\n>");
  apr_file_flush(output);

  if ((status = apr_file_open_stdin(&input, ptmp)) != APR_SUCCESS) {
    worker_log_error(worker, "Can not open stdin");
    return status;
  }

  if ((status = bufreader_new(&bufreader, input, ptmp)) != APR_SUCCESS) {
    worker_log_error(worker, "Can not create buffered reader for stdin");
    return status;
  }

  for (;;) {
    char *last;
    char *entry;

    if ((status = bufreader_read_line(bufreader, &line)) != APR_SUCCESS) {
      worker_log_error(worker, "Can not read line from buffered stdin\n");
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
    else if (strcmp(entry, "get") == 0 || strcmp(entry, "g") == 0 ||
             strcmp(entry, "set") == 0 || strcmp(entry, "s") == 0) {
      store_t *store;
      char *variable;
      variable = last;
      if (!variable|| !variable[0]) {
        apr_file_printf(output, "Need a variable name as argument\n");
        goto prompt;
      }
      if (entry[0] == 'g') {
        const char *value = worker_resolve_var(worker, variable, ptmp);
        apr_file_printf(output, "%s\n", value ? value : "<undef>");
      }
      else {
        if (!last) {
          apr_file_printf(output, "Parser error\n");
          goto prompt;
        }
        store_set(store, variable, last);
      }
    }
    else if (strcmp(entry, "list") == 0 || strcmp(entry, "ls") == 0 || strcmp(entry, "l") == 0) {
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
/************************************************************************
 * Commands 
 ***********************************************************************/
/**
 * Simple break point
 * @param worker IN callee
 * @param parent IN caller
 * @param pool IN temporary pool
 * @return apr status
 */
static apr_status_t block_DBG_BP(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  return dbg_interpreter(worker, parent, ptmp);
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t dbg_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "DBG", "_BP",
	                           "",
	                           "Stop script execution in the given thread at the given point. "
                                   "Continue after typing \"c\"",
	                           block_DBG_BP)) != APR_SUCCESS) {
    return status;
  }
  return APR_SUCCESS;
}

