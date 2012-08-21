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
 * Clone a string variable
 * @param string IN string to clone
 * @param pool IN parent pool for inheritance
 * @return string instance 
 */
void *htt_string_clone(void *string, apr_pool_t *pool); 

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
const char *htt_string_copy(htt_string_t *string, apr_pool_t *pool);

/**
 * Test if a pointer is a string type
 * @param void IN possible string pointer
 * @return 1 if it is a string type
 */
int htt_isa_string(void *type);

/**
 * Free string
 * @param string IN
 */
void htt_string_free(void *string); 

#endif
