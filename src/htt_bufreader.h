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
 * Interface of the HTTP Test Tool file.
 */

#ifndef HTT_BUFREADER_H
#define HTT_BUFREADER_H

typedef struct htt_bufreader_s htt_bufreader_t;

/**
 * New htt_bufreader object 
 *
 * @param self OUT htt_bufreader object
 * @param fp IN an open file to read
 * @param p IN pool
 *
 * @return an apr status
 */
htt_bufreader_t *htt_bufreader_file_new(apr_pool_t * pool, apr_file_t * fp);

/**
 * read line from file 
 *
 * @param self IN htt_bufreader object
 * @param line OUT read line
 *
 * @return an apr status
 */
apr_status_t htt_bufreader_read_line(htt_bufreader_t * self, char **line);

/**
 * Read specifed block
 *
 * @param self IN htt_bufreader object
 * @param block IN a block to fill up
 * @param length INOUT length of block, on return length of filled bytes
 *
 * @return APR_SUCCESS else APR error
 */
apr_status_t htt_bufreader_read_block(htt_bufreader_t * self, char *block,
                                  apr_size_t *length);

/**
 * eof reader
 *
 * @param self IN htt_bufreader object
 * @param buf OUT data 
 * @param len OUT data len
 *
 * @return APR_SUCCESS else an APR error
 */
apr_status_t htt_bufreader_read_eof(htt_bufreader_t * self,
                                char **buf, apr_size_t *len);

#endif
