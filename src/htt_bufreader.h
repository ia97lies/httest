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
 * Interface of the HTTP Test Tool file.
 */

#ifndef HTT_BUFREADER_H
#define HTT_BUFREADER_H

typedef struct htt_bufreader_s htt_bufreader_t;

htt_bufreader_t *htt_bufreader_file_new(apr_pool_t * pool, apr_file_t * fp);
apr_status_t htt_bufreader_read_line(htt_bufreader_t * bufreader, char **line); 
apr_status_t htt_bufreader_read_eof(htt_bufreader_t * bufreader, char **buf, 
                                    apr_size_t *len); 

#endif
