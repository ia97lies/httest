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
 * Interface for HTTP Test Tool dso objects.
 */

#ifndef HTT_DSO_H
#define HTT_DSO_H

#include <apr.h>
#include <apr_lib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return a custom handle, will be called befor every configure/read/write call, allways.
 * @return a handle which will be passed to configure/read/write
 */
typedef void* (*custom_handle_f)();

/**
 * Contains the configuration in one 0 terminated string
 * @param custom IN custom handle returned by custom_handle_f
 * @param config IN 0 terminated string with the configuration
 * @return APR_SUCCESS on success else APR_EINVAL
 */
typedef apr_status_t (*configure_f)(void *custom, const char *config);

/**
 * Contains the configuration in one 0 terminated string
 * @param custom IN custom handle returned by custom_handle_f
 * @param buf IN buffer to fill with bytes not longer than specified by len
 * @param len INOUT len must be set to the buf length, and returns the actual read bytes
 * @return APR_SUCCESS on success else APR_EINVAL
 */
typedef apr_status_t (*read_f)(void *custom, char *buf, apr_size_t *len);

/**
 * Contains the configuration in one 0 terminated string
 * @param custom IN custom handle returned by custom_handle_f
 * @param buf IN buffer to fill with bytes not longer than specified by len
 * @param len IN len must be set to the buf length
 * @return APR_SUCCESS on success else APR_EINVAL
 */
typedef apr_status_t (*write_f)(void *custom, const char *buf, apr_size_t len);

typedef struct transport_dso_s {
  custom_handle_f custom_handle; 
  configure_f configure; 
  read_f read; 
  write_f write; 
} transport_dso_t;

typedef apr_status_t (*func_dso_f)(const char *string);

#ifdef __cplusplus
}
#endif

#endif
