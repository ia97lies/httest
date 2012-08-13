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

#include "htt_stack.h"

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
  htt_stack_t *stack;
  char *test_data[50];
  char *data;
  int i;

  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  for (i = 0; i < 50; i++) {
    test_data[i] = apr_psprintf(pool, "%d", i);
  }
  stack = htt_stack_new(pool);

  fprintf(stdout, "Push/pop one element\n");
  htt_stack_push(stack, test_data[0]);
  data = htt_stack_top(stack);
  assert(strcmp(data, test_data[0]) == 0);

  return 0;
}

