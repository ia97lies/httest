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
 * Interface of the htt log.
 */

#ifndef HTT_LOG_H
#define HTT_LOG_H

#include <apr_file_io.h>

typedef struct htt_log_s htt_log_t;

#define LOG_NONE 0
#define LOG_ERR 1
#define LOG_WARN 2
#define LOG_INFO 3
#define LOG_CMD 4
#define LOG_ALL_CMD 5
#define LOG_DEBUG 6

htt_log_t * htt_log_make(apr_pool_t *pool, FILE *std, FILE *err, 
                         int mode, const char *prefix); 
void htt_log(htt_log_t *log, int log_mode, char *fmt, ...); 
void htt_log_buf(htt_log_t *log, int mode, const char *buf, int len, 
                 char *prefix); 
void htt_log_outbuf(htt_log_t *log, int mode, const char *buf, int len); 
void htt_log_inbuf(htt_log_t *log, int mode, const char *buf, int len); 
void htt_log_error(htt_log_t *log, char *position, char *fmt, ...); 

#endif
