/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. 
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
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
 * Implementation of the HTTP Test Tool util.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <config.h>
#include <apr.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_env.h>

#include "defines.h"
#include "replacer.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/

/************************************************************************
 * Forward declaration 
 ***********************************************************************/

/************************************************************************
 * Implementation
 ***********************************************************************/

static int my_enhanced_function_detection(char *line, int i) {
  if (line[i] == ':') {
    int j = i;
    ++j;
    if (strchr(VAR_ALLOWED_CHARS, line[j])) {
      while (line[j] != 0 && strchr(VAR_ALLOWED_CHARS, line[j])) {
	++j;
      }
      if (line[j] == '(') {
	while (line[j] != 0 && line[j] != ')') {
	  ++j;
	}
	if (line[j] == ')') {
	  ++j;
	}
	i = j;
      }
    }
  }
  else if (line[i] == '(') {
    while (line[i] != 0 && line[i] != ')') {
      ++i;
    }
    if (line[i] == ')') {
      ++i;
    }
  }
  return i;
}

/**
 * replace vars and functions in given line 
 * @param p IN pool
 * @param line IN line where to replace the vars with values
 * @param udata IN user data
 * @param replacer IN replacer function
 * @return new line
 */
char *replacer(apr_pool_t * p, char *line, void *udata, replacer_f replace) {
  int i;
  int start;
  int line_end;
  char *var_name;
  char *new_line;
  const char *val;
  char open_curly_brace;

  new_line = line;

once_again:
  i = 0;
  while (line[i] != 0) {
    if (line[i] == '$') {
      line_end = i;
      ++i;
      if ((open_curly_brace = line[i]) == '{') {
        ++i;
	start = i;
	while(line[i] != 0 && line[i] != '}') {
	  ++i;
	}
      }
      else {
        start = i;
        while (line[i] != 0 && strchr(VAR_ALLOWED_CHARS, line[i])) {
          ++i;
        }
	i = my_enhanced_function_detection(line, i);
      }
      var_name = apr_pstrndup(p, &line[start], i - start);
      val = replace(udata, var_name);
      if (val) {
        line[line_end] = 0;
        if (open_curly_brace == '{' && line[i] == '}') {
          ++i;
        }
        new_line = apr_pstrcat(p, line, val, &line[i], NULL);
        line = new_line;
        goto once_again;
      }
    }
    ++i;
  }
  return new_line;
}

