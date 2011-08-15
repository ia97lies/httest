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

#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
#define NUL '\0'

typedef enum
{ R_ERROR = -2 /* range */ , ERROR /* syntax */ , SUCCESS } STATUS;

typedef struct math_eval_s
{
  char *delims;                 /* Tokens               */
  char op_stack[256];           /* Operator stack       */
  long arg_stack[256];          /* Argument stack       */
  char token[256];              /* Token buffer         */
  int op_sptr;                  /* op_stack pointer     */
  int arg_sptr;                 /* arg_stack pointer    */
  int parens;                   /* Nesting level        */
  int state;                    /* 0 = Awaiting expression
                                   1 = Awaiting operator
                                 */
} math_eval_t;

static int math_eval_op(math_eval_t * hook);
static int math_eval_paren(math_eval_t * hook);
static void math_eval_push_op(math_eval_t * hook, char op);
static void math_eval_push_arg(math_eval_t * hook, long arg);
static STATUS math_eval_pop_arg(math_eval_t * hook, long *arg);
static STATUS math_eval_pop_op(math_eval_t * hook, int *arg);
static char *math_eval_getexp(math_eval_t * hook, char *exp);
static char *math_eval_getop(math_eval_t * hook, char *op);
static void math_eval_pack(math_eval_t * hook, char *);


/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Local 
 ***********************************************************************/
static math_eval_t *math_eval_make(apr_pool_t * pool) {
  math_eval_t *hook = apr_pcalloc(pool, sizeof(*hook));

  hook->delims = apr_pstrdup(pool, "+-*/^)(");
  hook->state = 0;

  return hook;
}

/*
**  Evaluate a mathematical expression
*/
int evaluate(math_eval_t * hook, char *line, long *val) {
  long arg;
  char *ptr = line, *str, *endptr;
  int ercode;

  math_eval_pack(hook, line);

  while (*ptr) {
    switch (hook->state) {
    case 0:
      if (NULL != (str = math_eval_getexp(hook, ptr))) {
        if ('(' == *str) {
          math_eval_push_op(hook, *str);
          ptr += strlen(str);
          break;
        }

        if (0.0 == (arg = strtod(str, &endptr)) && NULL == strchr(str, '0')) {
          return ERROR;
        }
        math_eval_push_arg(hook, arg);
        ptr += strlen(str);
      }
      else
        return ERROR;

      hook->state = 1;
      break;

    case 1:
      if (NULL == (str = math_eval_getop(hook, ptr)))
        return ERROR;

      if (strchr(hook->delims, *str)) {
        if (')' == *str) {
          if (SUCCESS > (ercode = math_eval_paren(hook)))
            return ercode;
        }
        else {
          math_eval_push_op(hook, *str);
          hook->state = 0;
        }

        ptr += strlen(str);
      }
      else
        return ERROR;

      break;
    }
  }

  while (1 < hook->arg_sptr) {
    if (SUCCESS > (ercode = math_eval_op(hook)))
      return ercode;
  }
  if (!hook->op_sptr)
    return math_eval_pop_arg(hook, val);
  else
    return ERROR;
}

/*
**  Evaluate stacked arguments and operands
*/
static int math_eval_op(math_eval_t * hook) {
  long arg1, arg2;
  int op;

  if (ERROR == math_eval_pop_op(hook, &op))
    return ERROR;

  math_eval_pop_arg(hook, &arg1);
  math_eval_pop_arg(hook, &arg2);

  switch (op) {
  case '+':
    math_eval_push_arg(hook, arg2 + arg1);
    break;

  case '-':
    math_eval_push_arg(hook, arg2 - arg1);
    break;

  case '*':
    math_eval_push_arg(hook, arg2 * arg1);
    break;

  case '/':
    if (0.0 == arg1)
      return R_ERROR;
    math_eval_push_arg(hook, arg2 / arg1);
    break;

  case '^':
    if (0.0 > arg2)
      return R_ERROR;
    math_eval_push_arg(hook, pow(arg2, arg1));
    break;

  case '(':
    hook->arg_sptr += 2;
    break;

  default:
    return ERROR;
  }
  if (1 > hook->arg_sptr)
    return ERROR;
  else
    return op;
}

/*
**  Evaluate one level
*/
static int math_eval_paren(math_eval_t * hook) {
  int op;

  if (1 > hook->parens--)
    return ERROR;
  do {
    if (SUCCESS > (op = math_eval_op(hook)))
      break;
  } while ('(' != op);
  return op;
}

/*
**  Stack operations
*/
static void math_eval_push_op(math_eval_t * hook, char op) {
  if ('(' == op)
    ++hook->parens;
  hook->op_stack[hook->op_sptr++] = op;
}

static void math_eval_push_arg(math_eval_t * hook, long arg) {
  hook->arg_stack[hook->arg_sptr++] = arg;
}

static STATUS math_eval_pop_arg(math_eval_t * hook, long *arg) {
  *arg = hook->arg_stack[--hook->arg_sptr];
  if (0 > hook->arg_sptr)
    return ERROR;
  else
    return SUCCESS;
}

static STATUS math_eval_pop_op(math_eval_t * hook, int *op) {
  if (!hook->op_sptr)
    return ERROR;
  *op = hook->op_stack[--hook->op_sptr];
  return SUCCESS;
}

/*
**  Get an expression
*/
static char *math_eval_getexp(math_eval_t * hook, char *str) {
  char *ptr = str, *tptr = hook->token;

  while (*ptr) {
    if (strchr(hook->delims, *ptr)) {
      if ('-' == *ptr) {
        if (str != ptr && 'E' != ptr[-1])
          break;
      }

      else if (str == ptr)
        return math_eval_getop(hook, str);

      else if ('E' == *ptr) {
        if (!isdigit(ptr[1]) && '-' != ptr[1])
          return NULL;
      }
      else
        break;
    }

    *tptr++ = *ptr++;
  }
  *tptr = NUL;

  return hook->token;
}

/*
**  Get an operator
*/
static char *math_eval_getop(math_eval_t * hook, char *str) {
  *hook->token = *str;
  hook->token[1] = NUL;
  return hook->token;
}

/*
**  Remove whitespace & capitalize
*/
static void math_eval_pack(math_eval_t * hook, char *str) {
  char *ptr = str, *p;

  //toupper(str);

  for (; *ptr; ++ptr) {
    p = ptr;
    while (*p && isspace(*p))
      ++p;
    if (ptr != p)
      strcpy(ptr, p);
  }
}

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

  if (evaluate(eval_hook, expr, &val)) {
    worker_log_error(worker, "Expression \"%s\" not valid", expr);
    return APR_EINVAL;
  }

  worker_var_set(worker, var, apr_ltoa(ptmp, val));
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
  worker_var_set(worker, param, apr_off_t_toa(ptmp, result));
  
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

  worker_var_set(worker, val, apr_itoa(ptmp, result));

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
