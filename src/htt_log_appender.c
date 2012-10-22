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
 * Implementation of htt log appender.
 */

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include "htt_util.h"
#include "htt_log_appender.h"

struct htt_log_appender_s {
  void *user_data;
  htt_print_f print;
};

htt_log_appender_t *htt_log_appender_new(apr_pool_t *pool, htt_print_f print, 
                                         void *user_data) {
  htt_log_appender_t *appender = apr_pcalloc(pool, sizeof(*appender));
  appender->print = print;
  appender->user_data = user_data;
  return appender;
}

void *htt_log_appender_get_user_data(htt_log_appender_t *appender) {
  return appender->user_data;
}

void htt_log_appender_print(htt_log_appender_t *appender, int level, 
                            char direction, long unsigned int id, int mode, 
                            const char *custom, const char *buf, 
                            apr_size_t len) {
  if (appender->print) {
    appender->print(appender, level, direction, id, mode, custom, buf, len);
  }
}


