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
  fprintf(stdout, "loop function incr global... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set g = 0\n\
         function foo\n\
           expr $g+1 g\n\
         end\n\
         loop 10 \n\
           foo\n\
         end\n\
         mock $g");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "10\n") == 0);
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
  fprintf(stdout, "set a variable with quotes... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set i = \"foo\"\n\
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
  fprintf(stdout, "set a variable with quotes and spaces... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set i = \"  foo\"\n\
         mock this line $i");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this line   foo\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "set a variable with quotes and escaped quotes... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set i = \"foo\\\"bar\\\"\"\n\
         mock this line $i");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this line foo\"bar\"\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "set a variable with single quotes... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set i = 'foo'\n\
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
  fprintf(stdout, "set a variable with single quotes and escaped quotes... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set i = 'foo\\'bar\\''\n\
         mock this line $i");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "this line foo\'bar\'\n") == 0);
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
  fprintf(stdout, "a function within a function... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "function foo\n\
           function foo2\n\
             set i = foo\n\
           end\n\
           foo2\n\
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
           mock $a $b\n\
         end\n\
         foo hallo velo\n");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "hallo velo\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "function return... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "function foo : a b\n\
           set a = hallo\n\
           set b = velo\n\
         end\n\
         foo c d\n\
         mock $c $d");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "hallo velo\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "function return too many parameter... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "function foo : a b r\n\
           set a = hallo\n\
           set b = velo\n\
           set r = any\n\
         end\n\
         foo c d\n\
         mock $c $d");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "hallo velo\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "function return too many variable... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "function foo : a b\n\
           set a = hallo\n\
           set b = velo\n\
         end\n\
         foo c d e\n\
         mock $c $d $e");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "hallo velo $e\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "function return single parameter single variable... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "function foo : a\n\
           set a = hallo\n\
         end\n\
         foo c\n\
         mock $c");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "hallo\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "function return parameter must be local... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "function foo : a\n\
           set a = hallo\n\
         end\n\
         foo c\n\
         mock $a");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "$a\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "expr simple... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "expr \"1 + 2\" r\n\
         mock $r");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "3\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "function resolve... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set i = $expr(1+2)\n\
         mock $i");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "3\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "function resolve with unresolved parameters... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set i = 1\n\
         set i = $expr($i+2)\n\
         mock $i");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "3\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "loop with index... ");
  {
    int i;
    htt_bufreader_t *bufreader;
    apr_status_t status;
    char *line;
    char *buf = apr_pstrdup(pool, 
        "loop 10 i\n\
           mock $i\n\
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
      assert(strcmp(line, apr_psprintf(pool, "%d", i)) == 0);
    }
    status = htt_bufreader_read_line(bufreader, &line);
    assert(status == APR_EOF);
    assert(line[0] == 0);

  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "if expression... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set i = 0\n\
         if $expr($i==0)\n\
           mock $i==0\n\
         end\n\
         if $expr($i==1)\n\
           mock $i==1\n\
         end");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "0==0\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "if expression 2... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set i = 10\n\
         if $expr($i>0)\n\
           mock $i>0\n\
         end\n\
         if $expr($i>10)\n\
           mock $i>10\n\
         end");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
    assert(strcmp(global_buf, "10>0\n") == 0);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "exit ok ...");
  {
    apr_proc_t proc;
    apr_status_t status;

    if ((status = apr_proc_fork(&proc, pool)) == APR_INCHILD) {
      apr_status_t status;
      char *buf = apr_pstrdup(pool, 
          "exit ok");
      global_buf = NULL;
      status = htt_compile_buf(htt, buf, strlen(buf));
      assert(status == APR_SUCCESS);
      status = htt_run(htt);
      exit(1);
    }
    else if (status == APR_INPARENT) {
      int exitcode;
      apr_exit_why_e exitwhy;
      status = apr_proc_wait(&proc, &exitcode, &exitwhy, APR_WAIT); 
      assert(status == APR_CHILD_DONE);
      assert(exitcode == 0);
    }
    else {
      assert(0);
    }
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "exit fail ...");
  {
    apr_proc_t proc;
    apr_status_t status;

    if ((status = apr_proc_fork(&proc, pool)) == APR_INCHILD) {
      apr_status_t status;
      char *buf = apr_pstrdup(pool, 
          "exit fail");
      global_buf = NULL;
      status = htt_compile_buf(htt, buf, strlen(buf));
      assert(status == APR_SUCCESS);
      status = htt_run(htt);
      exit(0);
    }
    else if (status == APR_INPARENT) {
      int exitcode;
      apr_exit_why_e exitwhy;
      status = apr_proc_wait(&proc, &exitcode, &exitwhy, APR_WAIT); 
      assert(status == APR_CHILD_DONE);
      assert(exitcode == 1);
    }
    else {
      assert(0);
    }
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "exit skip ...");
  {
    apr_proc_t proc;
    apr_status_t status;

    if ((status = apr_proc_fork(&proc, pool)) == APR_INCHILD) {
      apr_status_t status;
      char *buf = apr_pstrdup(pool, 
          "exit skip");
      global_buf = NULL;
      status = htt_compile_buf(htt, buf, strlen(buf));
      assert(status == APR_SUCCESS);
      status = htt_run(htt);
      exit(0);
    }
    else if (status == APR_INPARENT) {
      int exitcode;
      apr_exit_why_e exitwhy;
      status = apr_proc_wait(&proc, &exitcode, &exitwhy, APR_WAIT); 
      assert(status == APR_CHILD_DONE);
      assert(exitcode == 2);
    }
    else {
      assert(0);
    }
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "assert $expr(\"1 == 1\") ...");
  {
    apr_status_t status;

      char *buf = apr_pstrdup(pool, 
          "assert $expr(\"1 == 1\")");
      global_buf = NULL;
      status = htt_compile_buf(htt, buf, strlen(buf));
      assert(status == APR_SUCCESS);
      status = htt_run(htt);
      assert(status == APR_SUCCESS);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "assert $expr(\"1 == 2\") ...");
  {
    apr_status_t status;

      char *buf = apr_pstrdup(pool, 
          "assert $expr(\"1 == 2\")");
      global_buf = NULL;
      status = htt_compile_buf(htt, buf, strlen(buf));
      assert(status == APR_SUCCESS);
      status = htt_run(htt);
      assert(status == APR_EINVAL);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "expect with no params -> fail ...");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "expect\n");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_EGENERAL);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "expect with one params -> fail ...");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "expect foo\n");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_EGENERAL);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "expect wrong regex -> fail...");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "expect . \"[^abcd\"\n");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_EGENERAL);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "expect not used -> fail...");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "expect . \"never used\"\n");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_EINVAL);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "req expect wait -> ok... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set bar=foobar\n\
         req var://bar\n\
         expect . \"foo.*\"\n\
         wait");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "req expect wait -> fail... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set bar=barfoo\n\
         req var://bar\n\
         expect . \"foo.+\"\n\
         wait");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_EINVAL);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "req multiple expect wait -> ok... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set bar=foobar\n\
         req var://bar\n\
         expect . \"foo.*\"\n\
         expect . \".*\"\n\
         expect . \".*bar\"\n\
         expect body \"foo\"\n\
         expect . \"bar\"\n\
         wait");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "req unused expect wait -> fail before next command... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set bar=foobar\n\
         req var://bar\n\
         expect . \"foo.*\"\n\
         expect unused \"foo\"\n\
         wait\n\
         mock error");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_EINVAL);
    assert(global_buf == NULL);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "capsulated req expect wait -> ok... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set bar=foobar\n\
         set foo=blafasel\n\
         req var://bar\n\
         expect . \"foo.*\"\n\
         body\n\
           req var://foo\n\
           expect . \"bla.*\"\n\
           wait\n\
         end\n\
         wait");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "expect variable -> ok... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set bar=foobar\n\
         expect var(bar) \"foo.*\"");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
  }
  fprintf(stdout, "ok\n");

  htt = _test_reset();
  fprintf(stdout, "wait without req -> fail... ");
  {
    apr_status_t status;
    char *buf = apr_pstrdup(pool, 
        "set bar=foobar\n\
         expect var(bar) \"foo.*\"\n\
         wait");
    global_buf = NULL;
    status = htt_compile_buf(htt, buf, strlen(buf));
    assert(status == APR_SUCCESS);
    status = htt_run(htt);
    assert(status == APR_SUCCESS);
  }
  fprintf(stdout, "ok\n");

  return 0;
}

