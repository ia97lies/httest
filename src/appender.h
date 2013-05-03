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
 * Interface of the HTTP Test Tool log appender
 */

#ifndef HTTEST_APPENDER_H
#define HTTEST_APPENDER_H

typedef struct appender_s appender_t;
typedef void (*printer_f)(appender_t *appender, int mode, const char *pos, 
                          int thread, int group, char dir, const char *custom, 
                          const char *buf, apr_size_t len);

appender_t *appender_new(apr_pool_t *pool, printer_f printer, void *user_data);
void *appender_get_user_data(appender_t *appender);
void appender_print(appender_t *appender, int mode, const char *pos, 
                    int thread, int group, char dir, const char *custom, 
                    const char *buf, apr_size_t len);

#endif
