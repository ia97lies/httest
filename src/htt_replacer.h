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
 * Interface of the HTTP Test Tool replacer.
 */

#ifndef HTT_REPLACER_H
#define HTT_REPLACER_H

typedef const char *htt_replacer_f(void *udata, const char *name);

/**
 * replace vars and functions in given line 
 * @param p IN pool
 * @param line IN line where to replace the vars with values
 * @param udata IN user data
 * @param replacer IN replacer function
 * @return new line
 */
char *htt_replacer(apr_pool_t * p, char *line, void *udata, 
                   htt_replacer_f replace);

#endif
