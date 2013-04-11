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
 * Interface of the HTTP Test Tool logger
 */

#ifndef HTTEST_LOGGER_H
#define HTTEST_LOGGER_H

typedef struct logger_s logger_t;

void worker_log_va(worker_t * worker, int log_mode, char *fmt, va_list va);
void worker_log(worker_t * worker, int log_mode, char *fmt, ...);
void worker_log_error(worker_t * worker, char *fmt, ...);
void worker_log_buf(worker_t * worker, int log_mode, const char *buf,
                    char *prefix, apr_size_t len);


#endif
