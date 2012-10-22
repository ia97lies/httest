/**
 * Copyright 2012 Christian Liesch
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
 * Interface of the htt log appender interface.
 */

#ifndef HTT_LOG_APPENDER_H
#define HTT_LOG_APPENDER_H

typedef struct htt_log_appender_s htt_log_appender_t;

typedef apr_status_t(*htt_print_f)(htt_log_appender_t *appender, int level, 
                                   char direction, long unsigned int id, 
                                   int mode, const char *custom, 
                                   const char *buf, apr_size_t len);

htt_log_appender_t *htt_log_appender_new(htt_print_f print, void *user_data);

void *htt_log_appneder_get_user_data(htt_log_appender *appender);

#endif

