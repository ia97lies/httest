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
 * Store unit test 
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

#include "htt_eval.h"

/************************************************************************
 * Defines 
 ***********************************************************************/

/************************************************************************
 * Typedefs 
 ***********************************************************************/

/************************************************************************
 * Implementation 
 ***********************************************************************/
int main(int argc, const char *const argv[]) {
  apr_pool_t *pool;
  htt_eval_t *eval;
  char *test_data[50];
  int i;

  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  for (i = 0; i < 50; i++) {
    test_data[i] = apr_psprintf(pool, "%d", i);
  }
  eval = htt_eval_new(pool);

  fprintf(stdout, "1 + 1 ");
  {
    long result;
    htt_eval(eval, "1 + 1", &result);
    assert(result == 2);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "1 * 1 ");
  {
    long result;
    htt_eval(eval, "1 * 1", &result);
    assert(result == 1);
  }

  fprintf(stdout, "99+1*10 ");
  {
    long result;
    htt_eval(eval, "99+1*10", &result);
    assert(result == 109);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "(99+1)*10 ");
  {
    long result;
    htt_eval(eval, "(99+1)*10", &result);
    assert(result == 1000);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "(99+1)*10+1 ");
  {
    long result;
    htt_eval(eval, "(99+1)*10+1", &result);
    assert(result == 1001);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "(99+1)*(10+1) ");
  {
    long result;
    htt_eval(eval, "(99+1)*(10+1)", &result);
    assert(result == 1100);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "((99+1)+1) * 10 ");
  {
    long result;
    htt_eval(eval, "((99+1)+1) * 10", &result);
    assert(result == 1010);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "1 > 0 ");
  {
    long result;
    htt_eval(eval, "1 > 0", &result);
    assert(result == 1);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "1 > 2 ");
  {
    long result;
    htt_eval(eval, "1 > 2", &result);
    assert(result == 0);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "1 != 2 ");
  {
    long result;
    htt_eval(eval, "1 != 2", &result);
    assert(result == 1);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "1 and 1 ");
  {
    long result;
    apr_status_t status;
    status = htt_eval(eval, "1 and 1", &result);
    assert(status == APR_SUCCESS);
    assert(result == 1);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "1 and 0 ");
  {
    long result;
    apr_status_t status;
    status = htt_eval(eval, "1 and 0", &result);
    assert(status == APR_SUCCESS);
    assert(result == 0);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "1 or 0 ");
  {
    long result;
    apr_status_t status;
    status = htt_eval(eval, "1 or 0", &result);
    assert(status == APR_SUCCESS);
    assert(result == 1);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "1 or 1 ");
  {
    long result;
    apr_status_t status;
    status = htt_eval(eval, "1 or 1", &result);
    assert(status == APR_SUCCESS);
    assert(result == 1);
  }
  fprintf(stdout, "ok\n");

  fprintf(stdout, "0 or 0 ");
  {
    long result;
    apr_status_t status;
    status = htt_eval(eval, "0 or 0", &result);
    assert(status == APR_SUCCESS);
    assert(result == 0);
  }
  fprintf(stdout, "ok\n");

  return 0;
}

