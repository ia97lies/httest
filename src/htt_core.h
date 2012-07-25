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

#ifndef HTT_CORE_H
#define HTT_CORE_H

typedef struct htt_s htt_t;
typedef struct htt_command_s htt_command_t; 

typedef apr_status_t(*htt_compile_f)(htt_command_t *command, htt_t *htt, char *params);
typedef apr_status_t(*htt_function_f)();

void htt_exit(); 
void htt_no_output_exit(); 
void htt_throw_error(); 
void htt_throw_skip(); 
htt_t *htt_new(apr_pool_t *pool); 
void htt_set_log(htt_t *htt, FILE *std, FILE *err); 
void htt_add_value(htt_t *htt, const char *key, const char *val); 
void htt_set_cur_file_name(htt_t *htt, const char *name); 
const char *htt_get_cur_file_name(htt_t *htt); 
apr_status_t htt_compile_line(htt_t *htt, htt_function_f function, char *args); 
apr_status_t htt_compile_body(htt_t *htt, htt_function_f function, char *args); 
void htt_add_command(htt_t *htt, const char *name, const char *signature, 
                     const char *short_desc, const char *desc, int type,
                     htt_compile_f compile, htt_function_f function); 
apr_status_t htt_interpret_fp(htt_t *htt, apr_file_t *fp); 

#endif
