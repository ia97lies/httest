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
 * Interface of the HTTP Test Tool util.
 */

#ifndef HTT_UTIL_H
#define HTT_UTIL_H

#include "htt_store.h"

#define swap16(x) \
  ((((x) & 0x00ffU) << 8)| \
   (((x) & 0xff00U) >> 8))

#define swap32(x) \
  ((((x) & 0x000000ffUL) << 24)| \
   (((x) & 0x0000ff00UL) <<  8)| \
   (((x) & 0x00ff0000UL) >>  8)| \
   (((x) & 0xff000000UL) >> 24))

#define swap64(x) \
  ((((x) & 0xff00000000000000ULL) >> 56)| \
   (((x) & 0x00ff000000000000ULL) >> 40)| \
   (((x) & 0x0000ff0000000000ULL) >> 24)| \
   (((x) & 0x000000ff00000000ULL) >>  8)| \
   (((x) & 0x00000000ff000000ULL) <<  8)| \
   (((x) & 0x0000000000ff0000ULL) << 24)| \
   (((x) & 0x000000000000ff00ULL) << 40)| \
   (((x) & 0x00000000000000ffULL) << 56))

#if APR_IS_BIGENDIAN
# define hton16(x) swap16(x)
# define hton32(x) swap32(x)
# define hton64(x) swap64(x)
# define ntoh16(x) swap16(x)
# define ntoh32(x) swap32(x)
# define ntoh64(x) swap64(x)
#else
# define hton16(x) (x)
# define hton32(x) (x)
# define hton64(x) (x)
# define ntoh16(x) (x)
# define ntoh32(x) (x)
# define ntoh64(x) (x)
#endif

/**
 * This function is taken from apr. The apr_tokenize_to_argv do remove
 * all leftover "\", but this breaks up my httest completly.
 *
 * @param pool IN Context from which pool allocations will occur.
 * @arg_str IN Input argument string for conversion to argv[].
 * @argv_out IN Output location. This is a pointer to an array
 *              of pointers to strings (ie. &(char *argv[]).
 *              This value will be allocated from the contexts
 *              pool and filled in with copies of the tokens
 *              found during parsing of the arg_str. 
 * @param with_quotes IN do not strip quotes from quoted string
 *
 * @return SUCCESS
 */
apr_status_t htt_tokenize_to_argv(const char *arg_str, char ***argv_out,
                                 apr_pool_t *pool, int with_quotes);

/**
 * get the status string
 *
 * @param p IN pool
 * @param rc IN status to print
 *
 * @return status string
 */
char *htt_status_str(apr_pool_t * p, apr_status_t rc);


/**
 * splits arguments into a table
 *
 * @param line IN string of params
 * @param params INOUT table to store params
 */
void htt_get_args(char *line, htt_store_t *params, apr_pool_t *pool);

/**
 * display copyright information
 *
 * @param program name
 */
void htt_copyright(const char *progname);

/**
 * 2 hex digit number to char borowed from apache sourc
 *
 * @param what IN hex to convert
 *
 * @return char
 */
char htt_x2c(const char *what);

#endif
