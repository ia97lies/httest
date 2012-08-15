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
char *global_buf = NULL;

static apr_status_t _cmd_mock_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line) {
  global_buf = apr_pstrcat(htt_context_get_pool(context), global_buf, "\n",
                            line, NULL);
  return APR_SUCCESS;
}

int main(int argc, const char *const argv[]) {
  apr_pool_t *pool;
  apr_file_t *out;
  apr_file_t *err;
  htt_t *htt;

  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  htt = htt_new(pool);

  apr_file_open_stdout(&out, pool);
  apr_file_open_stderr(&err, pool);
  htt_set_log(htt, out, err, HTT_LOG_DEBUG);

  htt_add_command(htt, "mock", NULL, "<string>", "put string in a buffer", 
                  htt_cmd_line_compile, _cmd_mock_function);

  fprintf(stdout, "Run single mock command... ");
  {
    apr_status_t status;
    char *buf = "mock this line";
    global_buf = apr_pstrdup(pool, "");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this line"));
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "Set variable... ");
  {
    apr_status_t status;
    char *buf = 
      "set my_var = foo\n \
       mock this is $my_var";
    global_buf = apr_pstrdup(pool, "");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this is foo"));
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "Set variable inside use it outside... ");
  {
    apr_status_t status;
    char *buf = 
      "body\n \
         set my_var = foo\n \
       end\n \
       mock this is $my_var";
    global_buf = apr_pstrdup(pool, "");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this is foo"));
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "Set variable in function use it outside... ");
  {
    apr_status_t status;
    char *buf = 
      "function set_my_var\n \
         set my_var = foo\n \
       end\n \
       set_my_var\
       mock this is $my_var";
    global_buf = apr_pstrdup(pool, "");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this is foo"));
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "loop 10... ");
  {
    apr_status_t status;
    htt_bufreader_t *bufreader;
    char *line;
    int i;
    char *buf = 
      "loop 10\n \
         mock looping\n \
       end";
    global_buf = apr_pstrdup(pool, "");
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    bufreader = htt_bufreader_buf_new(pool, global_buf, strlen(global_buf)); 
    for (i = 0; i < 10; i++) {
      status = htt_bufreader_read_line(bufreader, &line);
      assert(status == APR_SUCCESS);
    }
      status = htt_bufreader_read_line(bufreader, &line);
      fprintf(stdout, "XXX: %s", global_buf);
      assert(status == APR_EOF);
  }
  fprintf(stdout, "ok\n");

  return 0;
}

