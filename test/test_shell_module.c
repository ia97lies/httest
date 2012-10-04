/* contributor license agreements. 
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
 * shell module unit test 
 */

/* affects include files on Solaris */
#define BSD_COMP

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <assert.h>
#include "htt_defines.h"

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_thread_proc.h>
#if APR_HAVE_STDLIB_H
#include <stdlib.h> /* for exit() */
#endif

#include "htt_core.h"
#include "htt_log.h"
#include "htt_bufreader.h"
/************************************************************************
 * Defines 
 ***********************************************************************/

/************************************************************************
 * Typedefs 
 ***********************************************************************/

/************************************************************************
 * Implementation 
 ***********************************************************************/
apr_pool_t *pool = NULL;
char *global_buf[10] = { NULL };
  apr_thread_mutex_t *mutex;

static apr_status_t _cmd_mock_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line) {
  int i = 0;
  char *cur;
  char *last;

  apr_thread_mutex_lock(mutex);
  cur = apr_strtok(line, " ", &last);
  assert(cur != NULL);
  assert(cur[0] >= '0' && cur[0] <= '9');
  i = apr_atoi64(cur);
  assert(i < 10);
  if (global_buf[i] != NULL) {
    global_buf[i] = apr_pstrcat(pool, global_buf[i], last, "\n", NULL);
  }
  else {
    global_buf[i] = apr_pstrcat(pool, last, "\n", NULL);
  }
  apr_thread_mutex_unlock(mutex);
  return APR_SUCCESS;
}

static htt_t * _test_reset() {
  htt_t *htt;
  apr_file_t *out;
  apr_file_t *err;
  int i;

  if (pool) {
    /* clean up */
    apr_hook_deregister_all();
    apr_pool_destroy(pool);
  }
  apr_pool_create(&pool, NULL);
  
  for (i = 0; i < 10; i++) {
    global_buf[i] = NULL;
  }

  apr_file_open_stdout(&out, pool);
  apr_file_open_stderr(&err, pool);

  htt = htt_new(pool);
  htt_set_log(htt, out, err, HTT_LOG_NONE);
  htt_add_command(htt, "mock", NULL, "<string>", "put string in a buffer", 
                  htt_cmd_line_compile, _cmd_mock_function);

  apr_thread_mutex_create(&mutex, APR_THREAD_MUTEX_DEFAULT, pool);

  return htt;
}

int main(int argc, const char *const argv[]) {
  htt_t *htt;

  apr_app_initialize(&argc, &argv, NULL);

  htt = _test_reset();
  fprintf(stdout, "exec echo foo expect... ");
  fflush(stdout);
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "expect exec \"foo.*\"\n\
         exec echo foo");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
  }
  fprintf(stdout, "ok\n");
  
  htt = _test_reset();
  fprintf(stdout, "exec echo foo expect twice... ");
  fflush(stdout);
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "expect exec \"foo.*\"\n\
         exec echo foo\n\
         expect exec bar.*\n\
         exec echo barbla");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
  }
  fprintf(stdout, "ok\n");

  return 0;
}

