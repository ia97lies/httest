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
 * Interface of the htt log.
 */

#ifndef HTT_LOG_H
#define HTT_LOG_H

#include <apr_file_io.h>
#include "htt_log_appender.h"

typedef struct htt_log_s htt_log_t;

/**
 * Create a new log instance
 * @param pool IN
 * @param out IN file desc for stdout
 * @param err IN file desc for errout
 * @param id IN unique id for thread
 * @return htt log instance
 */
htt_log_t * htt_log_new(apr_pool_t *pool, long unsigned int id);

/**
 * Clone a log instance from a given one
 * @param pool IN
 * @param log IN 
 * @param id IN unique id for thread
 * @return htt log instance
 */
htt_log_t * htt_log_clone(apr_pool_t *pool, htt_log_t *log, 
                          long unsigned int id); 

/**
 * Set an appender to print infos
 * @param log IN
 * @param appender IN
 */
void htt_log_set_appender(htt_log_t *log, htt_log_appender_t *appender); 

/**
 * Set logger mode
 * @param log IN instance
 * @param mode IN 
 */
void htt_log_set_mode(htt_log_t *log, int mode);

/**
 * Unset logger mode, take the old value
 * @param log IN instance
 * @param mode IN 
 */
void htt_log_unset_mode(htt_log_t *log, int mode);

/**
 * Set level for indention
 * @param log IN log
 * @param level IN level of indention
 */
void htt_log_set_level(htt_log_t *log, int level); 

/**
 * Log formated text
 * @param log IN instance
 * @param mode IN log mode
 * @param direction IN =,>,<
 * @param custom IN custom category
 * @param fmt IN format
 * @param ... IN format parameters
 */
void htt_log(htt_log_t *log, int mode, char direction, const char *custom, 
             char *fmt, ...);

/**
 * Log formated text
 * @param log IN instance
 * @param mode IN log mode
 * @param direction IN =,>,<
 * @param custom IN custom category
 * @param fmt IN format
 * @param va IN va args
 */
void htt_log_va(htt_log_t *log, int mode, char direction, const char *custom, 
                char *fmt, va_list va); 

/**
 * Log formated buffer
 * @param log IN instance
 * @param mode IN log mode
 * @param direction IN =,>,<
 * @param custom IN custom category
 * @param fmt IN format
 * @param buf IN buffer to log
 * @param len IN buffer len to log 
 */
void htt_log_buf(htt_log_t *log, int mode, char direction, const char *custom,
                 const char *buf, int len); 

/**
 * Log error
 * @param log IN instance
 * @param position IN file and line
 * @param fmt IN format
 * @param ... IN format parameters
 */

void htt_log_error(htt_log_t *log, apr_status_t status, const char *file, 
                   int pos, const char *fmt, ...);

#endif

