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
#include "defines.h"

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>

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
char *global_buf = NULL;

static apr_status_t _cmd_mock_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line) {
  if (global_buf != NULL) {
    global_buf = apr_pstrcat(pool, global_buf, line, "\n", NULL);
  }
  else {
    global_buf = apr_pstrcat(pool, line, "\n", NULL);
  }
  return APR_SUCCESS;
}

static htt_t * _test_reset() {
  htt_t *htt;
  apr_file_t *out;
  apr_file_t *err;

  if (pool) {
    apr_pool_destroy(pool);
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
  fprintf(stdout, "Run single mock command... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, "mock this line");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this line\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "Run many mock commands... ");
  {
    htt_bufreader_t *bufreader;
    apr_status_t status;
    int i;
    char *line;
    char *buf = apr_pstrdup(pool, 
        "mock this line 0\n\
         mock this line 1\n\
         mock this line 2\n\
         mock this line 3\n");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    bufreader = htt_bufreader_buf_new(pool, global_buf, strlen(global_buf));
    for (i = 0; i < 4; i++) {
      status = htt_bufreader_read_line(bufreader, &line);
      assert(status == APR_SUCCESS);
      assert(strcmp(line, apr_psprintf(pool, "this line %d", i)) == 0);
    }
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_EOF);
    assert(line[0] == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "loop many mock commands... ");
  {
    htt_bufreader_t *bufreader;
    apr_status_t status;
    int i;
    char *line;
    char *buf = apr_pstrdup(pool, 
        "loop 10 \n\
           mock this line\n\
         end");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    bufreader = htt_bufreader_buf_new(pool, global_buf, strlen(global_buf));
    for (i = 0; i < 10; i++) {
      status = htt_bufreader_read_line(bufreader, &line);
      assert(status == APR_SUCCESS);
      assert(strcmp(line, "this line") == 0);
    }
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_EOF);
    assert(line[0] == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "set a variable in the same scope... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set i = foo\n\
         mock this line $i");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this line foo\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "set a variable in foreign scope... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "body\n\
           set i = foo\n\
         end\n\
         mock this line $i");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this line foo\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "set a variable in a function... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "function foo\n\
           set i = foo\n\
         end\n\
         foo\n\
         mock this line $i");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this line foo\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "set a local variable in a function... ");
  {
    apr_status_t status;
    htt_bufreader_t *bufreader;
    char *line;
    char *buf = apr_pstrdup(pool, 
        "function foo\n\
           local i\n\
           set i = foo\n\
           mock local $i\n\
         end\n\
         foo\n\
         mock this line $i\n\
         set i = myfoo\n\
         mock this line $i\n\
         foo\n");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    bufreader = htt_bufreader_buf_new(pool, global_buf, strlen(global_buf));
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_SUCCESS);
    assert(strcmp(line, "local foo") == 0);
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_SUCCESS);
    assert(strcmp(line, "this line $i") == 0);
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_SUCCESS);
    assert(strcmp(line, "this line myfoo") == 0);
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_SUCCESS);
    assert(strcmp(line, "local foo") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "function parameter... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "function foo a b\n\
           mock this: $a $b\n\
         end\n\
         foo hallo velo\n");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this: hallo velo\n") == 0);
  }
  fprintf(stdout, "ok\n");

  return 0;
}

