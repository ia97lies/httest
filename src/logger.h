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

#define LOG_NONE 0
#define LOG_ERR 1
#define LOG_WARN 2
#define LOG_INFO 3
#define LOG_CMD 4
#define LOG_ALL_CMD 5
#define LOG_DEBUG 6

#include "appender.h"

typedef struct logger_s logger_t;

logger_t *logger_new(apr_pool_t *pool, int mode, int id);
logger_t *logger_clone(apr_pool_t *pool, logger_t *origin, int id);
void logger_add_appender(logger_t *logger, appender_t *appender); 
void logger_set_group(logger_t *logger, int group);
void logger_update(logger_t *logger, const char *file_and_line);

void logger_log_va(logger_t *logger, int log_mode, char *fmt, va_list va);
void logger_log(logger_t * logger, int log_mode, char *fmt, ...);
void logger_log_error(logger_t * logger, char *fmt, ...);
void logger_log_buf(logger_t * logger, int mode, char dir, const char *buf,
                    apr_size_t len); 
void logger_set_mode(logger_t *logger, int mode);
int logger_get_mode(logger_t *logger);


#endif
