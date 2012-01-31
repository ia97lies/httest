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
 * Implementation of the HTTP Test Tool config reader.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <apr.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_file_io.h>

#include "defines.h"
#include "file.h"
#include "util.h"
#include "conf.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/


/************************************************************************
 * Forward declaration 
 ***********************************************************************/


/************************************************************************
 * Implementation 
 ***********************************************************************/

apr_table_t *conf_reader(apr_pool_t *pool, const char *file) {
  apr_status_t status;
  apr_file_t *fp;
  bufreader_t *br;
  char *line;
  char *name;
  char *value;

  apr_table_t *conf = NULL;
    
  if ((status = apr_file_open(&fp, file, APR_READ, APR_OS_DEFAULT,
                              pool)) != APR_SUCCESS) {
    fprintf(stderr, "\nCould not open configuration file %s: %s (%d)", file,
	    my_status_str(pool, status), status);
    goto error;
  }

  conf = apr_table_make(pool, 5);
  
  if ((status = bufreader_new(&br, fp, pool)) != APR_SUCCESS) {
    fprintf(stderr, "\nCould not open configuration file bufreader %s: %s (%d)\n", 
	    file, my_status_str(pool, status), status);
    goto error2;
  }

  while (bufreader_read_line(br, &line) == APR_SUCCESS) {
    if (line[0] != 0 && line[0] != '#') {
      name = apr_strtok(line, " ", &value);
      apr_collapse_spaces(value, value);
      apr_table_set(conf, name, value);
    }
  }
  
error2:
  apr_file_close(fp);
  
error:
  return conf;
}

