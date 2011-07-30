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
 * Implementation of the HTTP Test Tool coder module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef struct url_escape_seq {
  char c;
  char *esc;
  apr_size_t len;
} url_escape_seq_t;

/************************************************************************
 * Globals 
 ***********************************************************************/
static url_escape_seq_t url_escape_seq[] = {
  { '?', "%3F", 3 },
  { '\n', "%0D", 3 },
  { ' ', "+", 1 },
  { '/', "%2F", 3 },
  { ';', "%3B", 3 },
  { '%', "%25", 3 },
  { '=', "%3D", 3 },
  { '"', "%22", 3 },
  { '\'', "%2C", 3 },
  { '.', "%2E", 3 },
  { ':', "%3A", 3 },
  { '@', "%40", 3 },
  { '\\', "%5C", 3 },
  { '&', "%26", 3 },
  { '+', "%2B", 3 },
};

/************************************************************************
 * Local
 ***********************************************************************/
/**
 * Get index of url escape sequenze array 
 *
 * @param c IN char for lookup
 *
 * @return index of url escape sequenz array
 */
static int get_url_escape_index(char c) {
  int i;
  for (i = 0; i < sizeof(url_escape_seq)/sizeof(url_escape_seq_t); i++) {
    if (url_escape_seq[i].c == c) {
      return i;
    }
  }
  return -1;
}

/************************************************************************
 * Commands 
 ***********************************************************************/
static apr_status_t block_CODER_DUMMY(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  return APR_SUCCESS;
}

/**
 * URLENC command
 *
 * @param worker IN command
 * @param worker IN thread data object
 * @param data IN string and variable name
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t block_CODER_URLENC(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  /* do this the old way, becaus argv tokenizer removes all "\" */
  const char *string;
  const char *var;
  char *result;
  int i;
  int j;
  int k;
  apr_size_t len;

  string = store_get(worker->params, "1");
  var = store_get(worker->params, "2");

  if (!string) {
    worker_log(worker, LOG_ERR, "Nothing to decode");
    return APR_EGENERAL;
  }
  if (!var) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }

  len = strlen(string);
  /* allocate worste case -> every char enc with pattern %XX */
  result = apr_pcalloc(worker->pbody, 3 * len + 1);

  /** do the simple stuff */
  for (j = 0, i = 0; string[i]; i++) {
    k = get_url_escape_index(string[i]);
    if (k != -1) {
      strncpy(&result[j], url_escape_seq[k].esc, url_escape_seq[k].len);
      j += url_escape_seq[k].len;
    }
    else {
      result[j++] = string[i];
    }
  }

  worker_var_set(worker, var, result);

  return APR_SUCCESS;

}

/**
 * URLDEC command
 *
 * @param worker IN command
 * @param worker IN thread data object
 * @param data IN string and variable name
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t block_CODER_URLDEC(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  /* do this the old way, becaus argv tokenizer removes all "\" */
  const char *string;
  const char *var;
  char c;
  int i;
  int j;
  apr_size_t len;
  char *inplace;

  string = store_get(worker->params, "1");
  var = store_get(worker->params, "2");

  if (!string) {
    worker_log(worker, LOG_ERR, "Nothing to decode");
    return APR_EGENERAL;
  }
  if (!var) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }

  inplace = apr_pstrdup(worker->pbody, string);
  len = strlen(string);
  for (i = 0, j = 0; i < len; i++, j++) {
    c = string[i];
    if (string[i] == '+') {
      c = 32;
    }
    else if (string[i] == '%') {
      if (i + 2 < len) {
        c = x2c(&string[i + 1]);
	i += 2;
      }
    }
    else if (string[i] == '\\' && i + 1 < len && string[i + 1] == 'x') {
      if (i + 3 < len) {
        c = x2c(&string[i + 2]);
	i += 3;
      }
    }
    inplace[j] = c;
  }
  inplace[j] = 0;

  worker_var_set(worker, var, inplace);

  return APR_SUCCESS;
}

/**
 * HTMLDEC command
 *
 * @param worker IN command
 * @param worker IN thread data object
 * @param data IN string and variable name
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t block_CODER_HTMLDEC(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *string;
  const char *var;
  char c;
  int i;
  int j;
  apr_size_t len;
  char *inplace;

  string = store_get(worker->params, "1");
  var = store_get(worker->params, "2");

  if (!string) {
    worker_log(worker, LOG_ERR, "Nothing to decode");
    return APR_EGENERAL;
  }
  if (!var) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }

  inplace = apr_pstrdup(worker->pbody, string);
  len = strlen(string);
  for (i = 0, j = 0; i < len; i++, j++) {
      c = string[i];
      if (string[i] == '&' && i + 2 < len && string[i + 1] == '#' && 
	  string[i + 2] == 'x') {
	/* hex */
      }
      else if (string[i] == '&' && i + 1 < len && string[i + 1] == '#') {
	/* decimal */
      }
      inplace[j] = c;
    }
  inplace[j] = 0;

  worker_var_set(worker, var, inplace);

  return APR_SUCCESS;
}

/**
 * B64ENC command
 *
 * @param worker IN command
 * @param worker IN thread data object
 * @param data IN string and variable name
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t block_CODER_B64ENC(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *string;
  const char *var;
  apr_size_t len;
  char *base64;

  string = store_get(worker->params, "1");
  var = store_get(worker->params, "2");

  if (!string) {
    worker_log(worker, LOG_ERR, "Nothing to decode");
    return APR_EGENERAL;
  }
  if (!var) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }

  len = apr_base64_encode_len(strlen(string));
  base64 = apr_pcalloc(worker->pbody, len + 1);
  apr_base64_encode(base64, string, strlen(string));
  
  worker_var_set(worker, var, base64);

  return APR_SUCCESS;
}

/**
 * BASE64DEC command
 *
 * @param worker IN command
 * @param worker IN thread data object
 * @param data IN string and variable name
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t block_CODER_B64DEC(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *string;
  const char *var;
  apr_size_t len;
  char *plain;

  string = store_get(worker->params, "1");
  var = store_get(worker->params, "2");

  if (!string) {
    worker_log(worker, LOG_ERR, "Nothing to decode");
    return APR_EGENERAL;
  }
  if (!var) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }

  len = apr_base64_decode_len(string);
  plain = apr_pcalloc(worker->pbody, len + 1);
  apr_base64_decode(plain, string);
  
  worker_var_set(worker, var, plain);

  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t coder_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "CODER", "_URLENC",
	                           "<string> <var>",
	                           "Url encode <string> and store it into a <var>",
	                           block_CODER_URLENC)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "CODER", "_URLDEC",
	                           "<string> <var>",
	                           "Url decode <string> and store it into a <var>",
	                           block_CODER_URLDEC)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "CODER", "_HTMLDEC",
	                           "<string> <var>",
	                           "Html decode <string> and store it into a <var>",
	                           block_CODER_HTMLDEC)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "CODER", "_B64ENC",
	                           "<string> <var>",
	                           "Base64 encode <string> and store it into a <var>",
	                           block_CODER_B64ENC)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "CODER", "_B64DEC",
	                           "<string> <var>",
	                           "Base64 decode <string> and store it into a <var>",
	                           block_CODER_B64DEC)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

