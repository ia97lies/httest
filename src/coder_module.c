/**
 * Copyright 2010 Christian Liesch
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

#define HTTEST_PCRE_RESERVED      "{}[]()^$.|*+?\\-"

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Local
 ***********************************************************************/

/************************************************************************
 * Commands 
 ***********************************************************************/
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
  const unsigned char *string;
  const char *var;
  unsigned char *result;
  int i;
  int j;
  apr_size_t len;

  string = (const unsigned char *)store_get(worker->params, "1");
  var = store_get(worker->params, "2");

  if (!string) {
    worker_log(worker, LOG_ERR, "Nothing to decode");
    return APR_EGENERAL;
  }
  if (!var) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }

  len = strlen((const char *)string);
  /* allocate worste case -> every char enc with pattern %XX */
  result = apr_pcalloc(ptmp, 3 * len + 1);

  /** do the simple stuff */
  for (j = 0, i = 0; string[i]; i++) {
    if ((string[i] >= 'a' && string[i] <= 'z') ||
        (string[i] >= 'A' && string[i] <= 'Z') ||
        (string[i] >= '0' && string[i] <= '9') ||
        string[i] == '-' || string[i] == '_' || string[i] == '~') {
      result[j++] = string[i];
    }
    else if (string[i] == ' ') {
      result[j++] = '+';
    }
    else {
	  strncpy((char *)&result[j], apr_psprintf(ptmp, "%%%2X", string[i]), 3);
	  j += 3;
    }
  }

  worker_var_set(parent, var, (char *)result);

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

  inplace = apr_pstrdup(ptmp, string);
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

  worker_var_set(parent, var, inplace);

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

  inplace = apr_pstrdup(ptmp, string);
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

  worker_var_set(parent, var, inplace);

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
  base64 = apr_pcalloc(ptmp, len + 1);
  apr_base64_encode(base64, string, strlen(string));
  
  worker_var_set(parent, var, base64);

  return APR_SUCCESS;
}

/**
 * REGEXENC command
 *
 * @param worker IN command
 * @param worker IN thread data object
 * @param data IN string and variable name
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t block_CODER_REGEXENC(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *string;
  const char *var;
  apr_size_t len;
  int i = 0;              // position in source
  int d = 0;              // position in destination
  char *inplace;          // escaped string
  unsigned char prev = 0; // previous character

  string = store_get(worker->params, "1");
  var = store_get(worker->params, "2");

  if (!string) {
    worker_log(worker, LOG_ERR, "Nothing to escape");
    return APR_EGENERAL;
  }
  if (!var) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }

  len = strlen(string);
  inplace = apr_pcalloc(ptmp, len * 4);
  
  while(string[i]) {
    if(strchr(HTTEST_PCRE_RESERVED, string[i]) != NULL) {
      if(prev && (prev == '\\')) {
        /* already escaped */
        inplace[d] = string[i];
        d++;
      } else if(prev && 
		(string[i] == '\\') && 
		(strchr(HTTEST_PCRE_RESERVED, string[i+1]) != NULL)) {
        /* escape char */
        inplace[d] = string[i];
        d++;
      } else {
        inplace[d] = '\\';
        d++;
        inplace[d] = string[i];
        d++;
      }
    } else if((string[i] < ' ') || (string[i]  > '~')) {
      /* hex representation for non-printable chars */
      sprintf(&inplace[d], "\\x%02x", string[i]);
      d = d + 4;
    } else {
      /* regular char - nothing to do */
      inplace[d] = string[i];
      d++;
    }
    prev = string[i];
    i++;
  }
  worker_var_set(parent, var, inplace);

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
  plain = apr_pcalloc(ptmp, len + 1);
  apr_base64_decode(plain, string);
  
  worker_var_set(parent, var, plain);

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
  if ((status = module_command_new(global, "CODER", "_REGEXENC",
	                           "<string> <var>",
	                           "Escapes the <string> and stores into <var> "
				   "to be used within "
				   "regular expression like a literal string",
	                           block_CODER_REGEXENC)) != APR_SUCCESS) {
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

