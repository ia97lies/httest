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
  fprintf(stdout, "Run one thread... ");
  fflush(stdout);
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "thread\n\
           mock 0 foobar\n\
         end");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf[0], "foobar\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "Run two threads... ");
  fflush(stdout);
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
  fflush(stdout);
  {
    int i;
    htt_bufreader_t *bufreader;
    char *line;
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "thread\n\
           loop 10000\n\
             mock 0 foobar1\n\
           end\n\
         end\n\
         \n\
         thread\n\
           loop 10000\n\
             mock 1 foobar2\n\
           end\n\
         end");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    bufreader = htt_bufreader_buf_new(pool, global_buf[0], 
                                      strlen(global_buf[0]));
    for (i = 0; i < 10000; i++) {
      status = htt_bufreader_read_line(bufreader, &line);
      assert(status == APR_SUCCESS);
      assert(strcmp(line, "foobar1") == 0);
    }
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_EOF);
    assert(line[0] == 0);
    bufreader = htt_bufreader_buf_new(pool, global_buf[1], 
                                      strlen(global_buf[1]));
    for (i = 0; i < 10000; i++) {
      status = htt_bufreader_read_line(bufreader, &line);
      assert(status == APR_SUCCESS);
      assert(strcmp(line, "foobar2") == 0);
    }
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_EOF);
    assert(line[0] == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "Run ten threads... ");
  fflush(stdout);
  {
    int i;
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "thread 10 t\n\
           mock $t foobar$t\n\
         end");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    for (i = 0; i < 10; i++) {
      assert(strcmp(global_buf[i], apr_psprintf(pool, "foobar%d\n", i)) == 0);
    }
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "Run thread in a loop... ");
  fflush(stdout);
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "loop 5 i\n\
           thread\n\
             mock $i foobar$i\n\
           end\n\
         end");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf[0], "foobar0\n") == 0);
    assert(strcmp(global_buf[1], "foobar1\n") == 0);
    assert(strcmp(global_buf[2], "foobar2\n") == 0);
    assert(strcmp(global_buf[3], "foobar3\n") == 0);
    assert(strcmp(global_buf[4], "foobar4\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "Run threads only one init block else -> fail ... ");
  fflush(stdout);
  {
    apr_status_t status;
    apr_proc_t proc;
    if ((status = apr_proc_fork(&proc, pool)) == APR_INCHILD) {
      char *buf = apr_pstrdup(pool, 
          "thread\n\
             mock 0 init\n\
           begin\n\
             mock 0 server\n\
           begin\n\
             mock 0 bla\n\
           end");
      htt_compile_buf(htt, buf, strlen(buf));
      exit(0);
    }
    else if (status == APR_INPARENT) {
      int exitcode;
      apr_exit_why_e exitwhy;
      status = apr_proc_wait(&proc, &exitcode, &exitwhy, APR_WAIT); 
      assert(status == APR_CHILD_DONE);
      assert(exitcode != 0);
    }
    else {
      assert(0);
    }
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "Run threads init block first ... ");
  fflush(stdout);
  {
    htt_bufreader_t *bufreader;
    apr_status_t status;
    char *line;
    char *buf = apr_pstrdup(pool, 
        "thread\n\
           mock 0 client\n\
         end\n\
         thread\n\
           mock 0 client\n\
         end\n\
         thread\n\
           mock 0 client\n\
         end\n\
         thread\n\
           mock 0 init\n\
         begin\n\
           mock 0 server\n\
         end");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    bufreader = htt_bufreader_buf_new(pool, global_buf[0], 
                                      strlen(global_buf[0]));
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_SUCCESS);
    assert(strcmp(line, "init") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "Run a daemon ... ");
  fflush(stdout);
  {
    apr_status_t status;
    apr_proc_t proc;
    if ((status = apr_proc_fork(&proc, pool)) == APR_INCHILD) {
      char *buf = apr_pstrdup(pool, 
          "daemon\n\
             sleep 1000\n\
             exit ok\n\
           end\n\
           sleep 10000\n\
           exit failed");
      htt_compile_buf(htt, buf, strlen(buf));
      htt_run(htt);
      exit(1);
    }
    else if (status == APR_INPARENT) {
      int exitcode;
      apr_exit_why_e exitwhy;
      status = apr_proc_wait(&proc, &exitcode, &exitwhy, APR_WAIT); 
      assert(status == APR_CHILD_DONE);
      assert(exitcode != 1);
    }
    else {
      assert(0);
    }
  }
  fprintf(stdout, "ok\n");

  return 0;
}

