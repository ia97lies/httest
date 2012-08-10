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

typedef struct htt_log_s htt_log_t;

#define HTT_LOG_NONE 0
#define HTT_LOG_ERROR 1
#define HTT_LOG_WARN 2
#define HTT_LOG_INFO 3
#define HTT_LOG_CMD 4
#define HTT_LOG_ALL_CMD 5
#define HTT_LOG_DEBUG 6

/**
 * Create a new log instance
 * @param pool IN
 * @param out IN file desc for stdout
 * @param err IN file desc for errout
 * @return htt log instance
 */
htt_log_t * htt_log_new(apr_pool_t *pool, apr_file_t *out, apr_file_t *err);

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
 * Log formated text
 * @param log IN instance
 * @param prefix IN prefix i.e. spaces
 */
void htt_log_set_prefix(htt_log_t *log, const char *prefix);

/**
 * Log formated text
 * @param log IN instance
 * @param mode IN log mode
 * @param fmt IN format
 * @param ... IN format parameters
 */
void htt_log(htt_log_t *log, int mode, char *fmt, ...);

/**
 * Log formated buffer
 * @param log IN instance
 * @param mode IN log mode
 * @param buf IN buffer to log
 * @param len IN buffer len to log 
 * @param prefix IN for input/output buffer
 */
void htt_log_buf(htt_log_t *log, int mode, const char *buf, int len, 
                 char *prefix);

/**
 * Log formated output buffer
 * @param log IN instance
 * @param mode IN log mode
 * @param buf IN buffer to log
 * @param len IN buffer len to log 
 */
void htt_log_outbuf(htt_log_t *log, int mode, const char *buf, int len);

/**
 * Log formated input buffer
 * @param log IN instance
 * @param mode IN log mode
 * @param buf IN buffer to log
 * @param len IN buffer len to log 
 */
void htt_log_inbuf(htt_log_t *log, int mode, const char *buf, int len);

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

