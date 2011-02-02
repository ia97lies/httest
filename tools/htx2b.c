/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. 
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
 * Implementation of the hex to binary converter
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <apr.h>
#include <apr_general.h>
#include <apr_strings.h>
#include <apr_signal.h>
#include <apr_file_io.h>
#include "../src/defines.h"

int main(int argc, const char * const argv[]) {
  apr_pool_t *pool;
  apr_file_t *in;
  apr_file_t *out;
  apr_status_t status;
  char buf[3];
  char *bin;
  char *end;
  apr_size_t len;
  apr_size_t i;
 
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  /* block broken pipe signal */
#if !defined(WIN32)
  apr_signal_block(SIGPIPE);
#endif

  if (argc > 1 && strcmp(argv[1], "--help") == 0) {
    fprintf(stdout, "%s reads hex digits from stdin and write binary to stdout\n", argv[0]);
    return 0; 
  }
  else if (argc > 1 && strcmp(argv[1], "--version") == 0) {
    fprintf(stdout, "%s " VERSION "\n", argv[0]);
    return 0; 
  }
  
  /* read from stdin */
  if ((status = apr_file_open_stdin(&in, pool)) != APR_SUCCESS) {
    fprintf(stderr, "Could not open stdin: %d\n", status);
    return status;
  }

  /* write binary to stdout */
  if ((status = apr_file_open_stdout(&out, pool)) != APR_SUCCESS) {
    fprintf(stderr, "Could not open stdout: %d\n", status);
    return status;
  }

  i = 0;
  bin = apr_pcalloc(pool, 8192);
  do {
    len = 2;
    if (status == APR_SUCCESS && (status = apr_file_read(in, buf, &len)) == APR_SUCCESS) {
      buf[len] = 0;
      bin[i] = apr_strtoi64(buf, &end, 16);
      if (i < 8192) {
	++i;
      }
      else {
	apr_file_write(out, bin, &i);
	i = 0;
      }
    }
    len = 1;
    status = apr_file_read(in, buf, &len);
  } while (status == APR_SUCCESS);
  if (i) { 
    apr_file_write(out, bin, &i);
  }
  apr_file_flush(out);
  return 0;
}
