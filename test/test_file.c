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
#include <apr_file_io.h>

#include "file.h"
#include "util.h"

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
  apr_status_t status;
  apr_pool_t *pool;
  apr_file_t *file;
  bufreader_t *bufreader;

  /** init store */
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  fprintf(stdout, "Prepare test file...");
  {
    char *tmpl;
    int i;
    apr_off_t offset = 0;

    tmpl = apr_pstrdup(pool, "testXXXXXX");
    if ((status = apr_file_mktemp(&file, tmpl, 0, pool)) != APR_SUCCESS) {
      fprintf(stderr, "\nCould not open temp file: %s(%d)\n", 
              my_status_str(pool, status), status);
      return 1;
    }

    for (i = 0; i < 10000; i++) {
      apr_file_printf(file, "test string test string %d\n", i);
    }
    apr_file_flush(file);

    if ((status = apr_file_seek(file, APR_SET, &offset)) != APR_SUCCESS) {
      fprintf(stderr, "\nCould not set read/write pointer to start: %s(%d)\n", 
              my_status_str(pool, status), status);
      return 1;
    }
    
  }
  fprintf(stdout, "OK\n");

  fprintf(stdout, "Read from bufreader...");
  {
    char *line;
    int i;

    if ((status = bufreader_new(&bufreader, file, pool)) != APR_SUCCESS) {
      fprintf(stderr, "\nCould not create bufreader: %s(%d)\n", 
              my_status_str(pool, status), status);
      return 1;
    }

    for (i = 0; i < 10000; i++) {
      if ((status = bufreader_read_line(bufreader, &line)) != APR_SUCCESS) {
        fprintf(stderr, "\nCould not read line %d: %s(%d)\n", 
                i, my_status_str(pool, status), status);
        return 1;
      }
      if (strcmp(line, apr_psprintf(pool, "test string test string %d", i)) 
          != 0) {
        fprintf(stderr, "\nline %d, do not match and is '%s'\n", i, line);
        return 1;
      }
    }

    if ((status = bufreader_read_line(bufreader, &line)) != APR_EOF) {
      fprintf(stderr, "\nAPR_EOF expected: %s(%d)\n", 
              my_status_str(pool, status), status);
      return 1;
    }
  }
  fprintf(stdout, "OK\n");

  fprintf(stdout, "Read until eof...");
  {
    char *buf;
    apr_size_t len;
    apr_off_t offset = 0;

    if ((status = apr_file_seek(file, APR_SET, &offset)) != APR_SUCCESS) {
      fprintf(stderr, "\nCould not set read/write pointer to start: %s(%d)\n", 
              my_status_str(pool, status), status);
      return 1;
    }
    
    if ((status = bufreader_new(&bufreader, file, pool)) != APR_SUCCESS) {
      fprintf(stderr, "\nCould not create bufreader: %s(%d)\n", 
              my_status_str(pool, status), status);
      return 1;
    }

    if ((status = bufreader_read_eof(bufreader, &buf, &len)) != APR_SUCCESS) {
      fprintf(stderr, "\nCould not read until eof: %s(%d)\n", 
              my_status_str(pool, status), status);
    }
    fprintf(stdout, "\nXXX%d\n", len);
  }
  fprintf(stdout, "OK\n");

  apr_file_close(file);
  return 0;
}

