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
 * Interface of the HTTP Test Tool string.
 */

#ifndef HTT_STRING_H
#define HTT_STRING_H

#include <apr_pools.h>

typedef struct htt_string_s htt_string_t;

/**
 * Create a string variable
 * @param pool IN parent pool for inheritance
 * @param value IN string to hold in this string variable
 * @return string instance 
 */
htt_string_t *htt_string_new(apr_pool_t *pool, const char *value);

/**
 * Update string value
 * @param string IN
 * @param value IN new string, replace the old, no memory loss 
 * @return value
 */
const char *htt_string_update(htt_string_t *string, const char *value);

/**
 * Get string value
 * @param string IN
 * @return value
 */
const char *htt_string_get(htt_string_t *string);

/**
 * Get a copy of string value
 * @param string IN
 * @param pool IN
 * @return a copy of the string
 */
const char *htt_string_copy(htt_string_t *string);

#endif
