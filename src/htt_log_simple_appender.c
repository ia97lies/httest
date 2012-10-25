/**
 * Copyright 2006 Christian Liesch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
 * Implementation of htt log simple appender.
 */

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include "htt_util.h"
#include "htt_log.h"
#include "htt_log_appender.h"

typedef struct _simple_appender_s {
  apr_file_t *out;
  apr_file_t *err;
} _simple_appender_t;

/**
 * Simple appender print method
 * @param appender IN
 * @param level IN no of concurren threads
 * @param direction IN <,>,=
 * @param id IN unique id
 * @param mode IN ERROR; WARN, INFO; ...
 * @param custom IN custom tag
 * @param buf IN buffer to log
 * @param len IN buffer length
 */
void _simple_appender_print(htt_log_appender_t *appender, int level, 
                            char direction, long unsigned int id, 
                            int mode, const char *custom, 
                            const char *buf, apr_size_t len);

/************************************************************************
 * Pupblic
 ***********************************************************************/
htt_log_appender_t *htt_log_simple_appender_new(apr_pool_t *pool, 
                                                apr_file_t *out,
                                                apr_file_t *err) {
  htt_log_appender_t *appender;
  _simple_appender_t *simple = apr_pcalloc(pool, sizeof(*simple));
  simple->out = out;
  simple->err = err;

  appender = htt_log_appender_new(pool, _simple_appender_print, simple);
  return appender;
}

/************************************************************************
 * Private
 ***********************************************************************/
void _simple_appender_print(htt_log_appender_t *appender, int level, 
                            char direction, long unsigned int id, 
                            int mode, const char *custom, 
                            const char *buf, apr_size_t len) {
  apr_size_t total = len;
  apr_size_t cur_pos = 0;
  _simple_appender_t *simple = htt_log_appender_get_user_data(appender);
  apr_file_t *out = simple->out;
  if (mode == HTT_LOG_ERROR) {
    out = simple->err;
  }

  apr_file_printf(out, "\n%c,id=%lu,mode=%d,custom=%s,msg=", direction, id, mode,
                  custom?custom:"null");
  while (total) {
    apr_size_t tmp_len = total;
    apr_file_write(out, &buf[cur_pos], &tmp_len);
    total -= tmp_len;
    cur_pos += tmp_len;
  }
}


