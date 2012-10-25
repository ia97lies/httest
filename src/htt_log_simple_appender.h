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
 * Interface of the htt simple log appender.
 */

#ifndef HTT_LOG_SIMPLE_APPENDER_H
#define HTT_LOG_SIMPLE_APPENDER_H

/**
 * Create a new appender
 * @param pool IN 
 * @param out IN file for general log output
 * @param err IN file for error output
 * @return appender instance
 */
htt_log_appender_t *htt_log_simple_appender_new(apr_pool_t *pool, 
                                                apr_file_t *out,
                                                apr_file_t *err); 

#endif
