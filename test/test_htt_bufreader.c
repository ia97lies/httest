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
int main(int argc, const char *const argv[]) {
  apr_pool_t *pool;
  apr_status_t status;
  htt_bufreader_t *bufreader;

  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  fprintf(stdout, "Read line in small data set\n");
  {
    char *data;
    const char *test_data = "foo bar\nbla bla";
    bufreader = htt_bufreader_buf_new(pool, test_data, strlen(test_data));
    status = htt_bufreader_read_line(bufreader, &data);
    assert(status == APR_SUCCESS);
    assert(strcmp(data, "foo bar") == 0);
    status = htt_bufreader_read_line(bufreader, &data);
    assert(status == APR_EOF);
    assert(strcmp(data, "bla bla") == 0);
    status = htt_bufreader_read_line(bufreader, &data);
    assert(status == APR_EOF);
    assert(data[0] == 0);
  }

  fprintf(stdout, "Read line in big data set\n");
  {
    char *cur;
    char *data;
    char *dyn_data;
    int i;
    char *ref = "hallo welt.........................................................................................";
    cur = dyn_data = apr_pcalloc(pool, 12000);
    for (i = 0; i < 119; i++) {
      strcpy(cur, ref);
      cur += 99;
      *cur = '\n';
      cur += 1;
    }
    strcpy(cur, ref);
    cur += 99;
    bufreader = htt_bufreader_buf_new(pool, dyn_data, 12000);
    for (i = 0; i < 119; i++) {
      status = htt_bufreader_read_line(bufreader, &data);
      assert(status == APR_SUCCESS);
      assert(strcmp(data, ref) == 0);
    }
    status = htt_bufreader_read_line(bufreader, &data);
    assert(status == APR_EOF);
    assert(strcmp(data, ref) == 0);

  }

  return 0;
}

