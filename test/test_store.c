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

#include "store.h"

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
  apr_pool_t *subpool;
  store_t *store;
  int i;
  const char *var;
  const char *val;
  const char *ref;

  /** init store */
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);
  store = store_make(pool);

  fprintf(stdout, "add 1000 items\n");
  for (i = 0; i < 1000; i++) {
    apr_pool_create(&subpool, pool);
    var = apr_psprintf(pool, "myVar%d", i);
    ref = apr_psprintf(pool, "mYvAr%d", i);
    store_set(store, var, ref);
    val = store_get(store, var);
    assert(val != NULL);
    assert(strcmp(val, ref) == 0);
    apr_pool_destroy(subpool);
  } 

  fprintf(stdout, "get all 1000 items\n");
  for (i = 0; i < 1000; i++) {
    apr_pool_create(&subpool, pool);
    var = apr_psprintf(pool, "myVar%d", i);
    ref = apr_psprintf(pool, "mYvAr%d", i);
    val = store_get(store, var);
    assert(val != NULL);
    assert(strcmp(val, ref) == 0);
    apr_pool_destroy(subpool);
  }

  fprintf(stdout, "set all 1000 items to different value\n");
  for (i = 0; i < 1000; i++) {
    apr_pool_create(&subpool, pool);
    var = apr_psprintf(pool, "myVar%d", i);
    ref = apr_psprintf(pool, "MyVaR%d", i);
    store_set(store, var, ref);
    val = store_get(store, var);
    assert(val != NULL);
    assert(strcmp(val, ref) == 0);
    apr_pool_destroy(subpool);
  } 

  fprintf(stdout, "get all 1000 items with different value\n");
  for (i = 0; i < 1000; i++) {
    apr_pool_create(&subpool, pool);
    /* name case sensitive */
    var = apr_psprintf(pool, "MYvAR%d", i);
    val = store_get(store, var);
    assert(val == NULL);
    /* value case sensitive */
    var = apr_psprintf(pool, "myVar%d", i);
    ref = apr_psprintf(pool, "mYvAr%d", i);
    val = store_get(store, var);
    assert(val != NULL);
    assert(strcmp(val, ref) != 0);
    /* get it */
    var = apr_psprintf(pool, "myVar%d", i);
    ref = apr_psprintf(pool, "MyVaR%d", i);
    val = store_get(store, var);
    assert(val != NULL);
    assert(strcmp(val, ref) == 0);
    apr_pool_destroy(subpool);
  }

  return 0;
}

