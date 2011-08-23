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
 *
 * REMARK
 * Original Copyright 1991 by Bob Stout as part of
 * the MicroFirm Function Library (MFL)
 * 
 * This subset* version is hereby donated to the public domain.
 */

/**
 * @file
 *
 * @Author christian liesch <liesch@gmx.ch>
 *
 * Implementation of the HTTP Test Tool math module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include "eval.h"

#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/

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
 * Evaluate a math expression, should be extended with >, <, >=,<=, == and !
 * @param worker IN worker instance
 * @param parent IN caller
 * @param ptmp IN temporary pool for this function
 * @return APR_SUCCESS or APR_EINVAL if expression is incorrect
 */
static apr_status_t block_MATH_EVAL(worker_t *worker, worker_t *parent, 
                                    apr_pool_t *ptmp) {
  apr_status_t status;
  long val;
  const char *value = store_get(worker->params, "1");
  const char *var = store_get(worker->params, "2");
  char *expr = apr_pstrdup(ptmp, value);
  math_eval_t *eval_hook = math_eval_make(ptmp);

  if (!value) {
    worker_log_error(worker, "Missing expression");
    return APR_EINVAL;
  }

  if (!var) {
    worker_log_error(worker, "Missing variable");
    return APR_EINVAL;
  }

  if ((status = math_evaluate(eval_hook, expr, &val)) != APR_SUCCESS) {
    worker_log_error(worker, "Expression \"%s\" not valid", expr);
    return status;
  }

  worker_var_set(parent, var, apr_ltoa(ptmp, val));
  return APR_SUCCESS;
}

/**
 * Legacy simple math evaluator us block_MATH_EVAL instead 
 * @param worker IN worker instance
 * @param parent IN caller
 * @param ptmp IN temporary pool for this function
 * @return APR_SUCCESS or APR_EINVAL if expression is incorrect
 */
static apr_status_t block_MATH_OP(worker_t *worker, worker_t *parent, 
                                  apr_pool_t *ptmp) {
  const char *param;
  const char *op;
  apr_int64_t ileft;
  apr_int64_t iright;
  apr_int64_t result;

  param = store_get(worker->params, "1");
  if (param == NULL) {
    worker_log(worker, LOG_ERR, "<left> value expected");
    return APR_EINVAL;
  }
  ileft = apr_atoi64(param);

  op = store_get(worker->params, "2");
  if (op == NULL) {
    worker_log(worker, LOG_ERR, "ADD, SUB, MUL or DIV expected");
    return APR_EINVAL;
  }

  param = store_get(worker->params, "3");
  if (param == NULL) {
    worker_log(worker, LOG_ERR, "<right> value expected");
    return APR_EINVAL;
  }
  iright = apr_atoi64(param);

  param = store_get(worker->params, "4");
  if (param == NULL) {
    worker_log(worker, LOG_ERR, "<var> expected");
    return APR_EINVAL;
  }

  /* do operation */
  if (strcasecmp(op, "ADD") == 0) {
    result = ileft + iright;
  }
  else if (strcasecmp(op, "SUB") == 0) {
    result = ileft - iright;
  }
  else if (strcasecmp(op, "MUL") == 0) {
    result = ileft * iright;
  }
  else if (strcasecmp(op, "DIV") == 0) {
    if (iright == 0) {
      worker_log(worker, LOG_ERR, "Division by zero");
      return APR_EINVAL;
    }
    result = ileft / iright;
  }
  else {
    worker_log(worker, LOG_ERR, "Unknown operant %s", op);
    return APR_ENOTIMPL;
  }

  /* store it do var */
  worker_var_set(parent, param, apr_off_t_toa(ptmp, result));
  
  return APR_SUCCESS;
}

/**
 * Generate a random number.
 * @param worker IN worker instance
 * @param parent IN caller
 * @param ptmp IN temporary pool for this function
 * @return APR_SUCCESS or APR_EINVAL if expression is incorrect
 */
static apr_status_t block_MATH_RAND(worker_t *worker, worker_t *parent, 
                                    apr_pool_t *ptmp) {
  int start;
  int end;
  int result;

  const char *val = store_get(worker->params, "1");
  if (val == NULL) {
    worker_log(worker, LOG_ERR, "No start defined");
    return APR_EINVAL;
  }
  start = apr_atoi64(val);

  val = store_get(worker->params, "2");
  if (val == NULL) {
    worker_log(worker, LOG_ERR, "No end defined");
    return APR_EINVAL;
  }
  end = apr_atoi64(val);

  val = store_get(worker->params, "3");
  if (val == NULL) {
    worker_log(worker, LOG_ERR, "No variable name specified");
    return APR_EINVAL;
  }
  
  result = start + (rand() % (end - start)); 

  worker_var_set(parent, val, apr_itoa(ptmp, result));

  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t math_module_init(global_t * global) {
  apr_status_t status;
  if ((status =
       module_command_new(global, "MATH", "_EVAL", "<expression> <var>",
                          "callculates <expression> and stores it in <var>",
                          block_MATH_EVAL)) != APR_SUCCESS) {
    return status;
  }

  if ((status =
       module_command_new(global, "MATH", "_OP", "<left> ADD|SUB|DIV|MUL <right> <variable>",
                          "Legacy math evaluator use _MATH:EVAL instead",
                          block_MATH_OP)) != APR_SUCCESS) {
    return status;
  }

  if ((status =
       module_command_new(global, "MATH", "_RAND", "<start> <end> <var>",
                          "Generates a number between <start> and <end> and stores result in"
			  "<var>",
                          block_MATH_RAND)) != APR_SUCCESS) {
    return status;
  }
  return APR_SUCCESS;
}
