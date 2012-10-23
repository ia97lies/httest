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

#define HTT_LOG_NONE 0
#define HTT_LOG_ERROR 1
#define HTT_LOG_WARN 2
#define HTT_LOG_INFO 3
#define HTT_LOG_CMD 4
#define HTT_LOG_DEBUG 5

typedef struct htt_log_appender_s htt_log_appender_t;

typedef void(*htt_print_f)(htt_log_appender_t *appender, int level, 
                           char direction, long unsigned int id, 
                           int mode, const char *custom, 
                           const char *buf, apr_size_t len);

/**
 * Create a new appender
 * @param pool IN 
 * @param print IN implemented print method
 * @param user_data IN user data for print method
 * @return appender instance
 */
htt_log_appender_t *htt_log_appender_new(apr_pool_t *pool, htt_print_f print, 
                                         void *user_data);

/**
 * Get user data registered to appender
 * @param appender IN
 * @return registered user data
 */
void *htt_log_appender_get_user_data(htt_log_appender_t *appender);

/**
 * Print with the implemented print method
 * @param appender IN
 * @param level IN concurrent threads
 * @param direction IN <,>,= (in, out, else)
 * @param id IN thread id
 * @param mode IN ERROR, WARN, INFO, ...
 * @param custom IN custom string
 * @param buf IN buffer to print
 * @param len IN buffer lenght or 0 if null terminated string
 */
void htt_log_appender_print(htt_log_appender_t *appender, int level, 
                            char direction, long unsigned int id, 
                            int mode, const char *custom, 
                            const char *buf, apr_size_t len);

#endif

