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

#ifndef HTTEST_UTIL_H
#define HTTEST_UTIL_H

#include "store.h"

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

char *my_unescape(char *string, char **last); 
apr_table_t *my_table_deep_copy(apr_pool_t *p, apr_table_t *orig); 
apr_table_t *my_table_swallow_copy(apr_pool_t *p, apr_table_t *orig); 
char *my_status_str(apr_pool_t * p, apr_status_t rc); 
void copyright(const char *progname); 
const char *filename(apr_pool_t *pool, const char *path); 
char x2c(const char *what); 
void my_get_args(char *line, store_t *params, apr_pool_t *pool); 

#endif
