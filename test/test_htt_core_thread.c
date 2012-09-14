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
 * Core unit test 
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

static apr_status_t _cmd_mock_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line) {
  int i = 0;
  char *cur;
  char *last;

  cur = apr_strtok(line, " ", &last);
  i = apr_atoi64(cur);
  if (global_buf[i] != NULL) {
    global_buf[i] = apr_pstrcat(pool, global_buf[i], last, "\n", NULL);
  }
  else {
    global_buf[i] = apr_pstrcat(pool, last, "\n", NULL);
  }
  return APR_SUCCESS;
}

static htt_t * _test_reset() {
  htt_t *htt;
  apr_file_t *out;
  apr_file_t *err;

  if (pool) {
    /* clean up */
    apr_pool_destroy(pool);
    apr_hook_deregister_all();
  }
  apr_pool_create(&pool, NULL);

  apr_file_open_stdout(&out, pool);
  apr_file_open_stderr(&err, pool);

  htt = htt_new(pool);
  htt_set_log(htt, out, err, HTT_LOG_NONE);
  htt_add_command(htt, "mock", NULL, "<string>", "put string in a buffer", 
                  htt_cmd_line_compile, _cmd_mock_function);
  return htt;
}

int main(int argc, const char *const argv[]) {
  htt_t *htt;

  apr_app_initialize(&argc, &argv, NULL);

  htt = _test_reset();
  fprintf(stdout, "Run one thread... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "thread\n\
           mock 0 foobar\n\
         end");
    global_buf[0] = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf[0], "foobar\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "Run two threads... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "thread\n\
           mock 0 foobar1\n\
         end\n\
         \n\
         thread\n\
           mock 1 foobar2\n\
         end");
    global_buf[0] = NULL;
    global_buf[1] = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf[0], "foobar1\n") == 0);
    assert(strcmp(global_buf[1], "foobar2\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "Run two threads and loop ... ");
  {
    int i;
    htt_bufreader_t *bufreader;
    char *line;
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "thread\n\
           loop 100\n\
             mock 0 foobar1\n\
           end\n\
         end\n\
         \n\
         thread\n\
           loop 100\n\
             mock 1 foobar2\n\
           end\n\
         end");
    global_buf[0] = NULL;
    global_buf[1] = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    bufreader = htt_bufreader_buf_new(pool, global_buf[0], 
                                      strlen(global_buf[0]));
    for (i = 0; i < 100; i++) {
      status = htt_bufreader_read_line(bufreader, &line);
      assert(status == APR_SUCCESS);
      fprintf(stderr, "XXX: |%s|\n", line);
      fflush(stderr);
      assert(strcmp(line, "foobar1") == 0);
    }
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_EOF);
    assert(line[0] == 0);
    bufreader = htt_bufreader_buf_new(pool, global_buf[1], 
                                      strlen(global_buf[1]));
    for (i = 0; i < 100; i++) {
      status = htt_bufreader_read_line(bufreader, &line);
      assert(status == APR_SUCCESS);
      fprintf(stderr, "XXX: |%s|\n", line);
      fflush(stderr);
      assert(strcmp(line, "foobar2") == 0);
    }
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_EOF);
    assert(line[0] == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "Run ten threads... ");
  {
    int i;
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "thread 10 t\n\
           mock $t foobar$t\n\
         end");
    for (i = 0; i < 10; i++) {
      global_buf[i] = NULL;
    }
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    for (i = 0; i <10; i++) {
      assert(strcmp(global_buf[i], apr_psprintf(pool, "foobar%d\n", i)) == 0);
    }
  }
  fprintf(stdout, "ok\n");

  return 0;
}

