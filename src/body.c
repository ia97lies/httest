/**
 * Copyright 2006 Christian Liesch
 *
 * fooLicensed under the Apache License, Version 2.0 (the "License");
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
 * Implementation of the HTTP Test Tool body
 */

/* affects include files on Solaris */
#define BSD_COMP

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "defines.h"

#include <apr.h>
#include <apr_signal.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <apr_time.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_support.h>

#include <pcre.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#include "worker.h"
#include "eval.h"
#include "regex.h"
#include "util.h"
#include "body.h"
#include "module.h"

/************************************************************************
 * Defines 
 ***********************************************************************/

/************************************************************************
 * Structurs
 ***********************************************************************/
typedef struct milestone_s {
  int failures;
  int milestones;
  apr_status_t status;
} milestone_t;

/************************************************************************
 * Globals 
 ***********************************************************************/
extern command_t global_commands[];
extern command_t local_commands[]; 
     
/************************************************************************
 * Private 
 ***********************************************************************/
/**
 * Lookup function
 *
 * @param line IN line where the command resides
 *
 * @return command index
 */
static command_t *lookup_command(command_t *commands, const char *line) {
  int k;
  apr_size_t len;

  k = 0;
  /* lookup command function */
  while (commands[k].name) {
    len = strlen(commands[k].name);
    if (len <= strlen(line)
	&& strncmp(line, commands[k].name, len) == 0) {
      break;
    }
    ++k;
  }

  return &commands[k];
}

/**
 * Clone and copy a body of lines
 *
 * @param body OUT body which has been copied
 * @param worker IN  worker from which we copy the lines for body
 * @param end IN this bodys terminate string
 *
 * @return APR_SUCCESS
 */
static apr_status_t worker_body(worker_t **body, worker_t *worker) {
  char *file_and_line;
  char *line = "";
  apr_table_entry_t *e; 
  apr_pool_t *p;
  char *end;
  int ends;
  int end_len;

  apr_pool_create(&p, NULL);
  end = apr_pstrdup(p, "_END");
  end_len = strlen(end);
  ends = 1;
  (*body) = apr_pcalloc(p, sizeof(worker_t));
  memcpy(*body, worker, sizeof(worker_t));
  (*body)->heartbeat = p;

  /* fill lines */
  (*body)->lines = apr_table_make(p, 20);
  e = (apr_table_entry_t *) apr_table_elts(worker->lines)->elts;
  for (worker->cmd += 1; worker->cmd < apr_table_elts(worker->lines)->nelts; worker->cmd++) {
    command_t *command;
    file_and_line = e[worker->cmd].key;
    line = e[worker->cmd].val;
    command = lookup_command(local_commands, line);

    if (command && command->flags & COMMAND_FLAGS_BODY) {
      ++ends;
      worker_log(worker, LOG_DEBUG, "Increment bodies: %d for line %s", ends, line);
    }
    if (ends == 1 && strlen(line) >= end_len && strncmp(line, end, end_len) == 0) {
      break;
    }
    else if (strlen(line) >= end_len && strncmp(line, end, end_len) == 0) {
      --ends;
      worker_log(worker, LOG_DEBUG, "Decrement bodies: %d for line %s", ends, line);
    }
    apr_table_addn((*body)->lines, file_and_line, line);
  }
  /* check for end */
  if (strlen(line) < end_len || strncmp(line, end, end_len) != 0) {
    worker_log(worker, LOG_ERR, "Interpreter failed: no %s found", end);
    return APR_EGENERAL;
  }

  return APR_SUCCESS;
}
 
/**
 * Close a body 
 *
 * @param body IN body which has been copied
 * @param worker IN  worker from which we copy the lines for body
 */
static void worker_body_end(worker_t *body, worker_t *worker) {
  worker->flags = body->flags;
  /* write back sockets and state */
  worker->socket = body->socket;
  worker->listener = body->listener;

  /* destroy body */
  worker_destroy(body);
}

/** finde _ELSE in cascaded if statments
 *
 * @param worker IN thread data object
 * @param else_pos OUT position of else
 *
 * @return apr_status 
 */
static apr_status_t worker_where_is_else(worker_t *worker, int *else_pos) {
  char *line; 
  char *end; 
  int end_len;
  char *kind;
  int kind_len;
  char *my_else;
  int my_else_len;
  int ends;
  apr_table_entry_t *e;

  *else_pos = 0;

  end = "_END";
  end_len = strlen(end);
  kind = "_IF";
  kind_len = strlen(kind);
  my_else = "_ELSE";
  my_else_len = strlen(kind);
  ends = 1;

  e = (apr_table_entry_t *) apr_table_elts(worker->lines)->elts;
  for (worker->cmd = 0; worker->cmd < apr_table_elts(worker->lines)->nelts; worker->cmd++) {
    line = e[worker->cmd].val;
    /* count numbers of same kinds to include all their ends */
    if (strlen(line) >= kind_len && strncmp(line, kind, kind_len) == 0) {
      ++ends;
      worker_log(worker, LOG_DEBUG, "Increment: %d for line %s", ends, line);
    }
    /* check end and if it is our end */
    if (ends == 1 && strlen(line) >= my_else_len && strncmp(line, my_else, my_else_len) == 0) {
      worker_log(worker, LOG_DEBUG, "Found _ELSE in line %d", worker->cmd);
      *else_pos = worker->cmd;
      return APR_SUCCESS;
      break;
    }
    /* no is not our end, decrement ends */
    else if (strlen(line) >= end_len && strncmp(line, end, end_len) == 0) {
      --ends;
      worker_log(worker, LOG_DEBUG, "Decrement: %d for line %s", ends, line);
    }
  }

  worker_log(worker, LOG_DEBUG, "No _ELSE found");
  return APR_ENOENT;
}

/**
 * If statement (not implemented yet)
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN expression 
 *
 * @return an apr status
 */
apr_status_t command_IF(command_t * self, worker_t * worker, char *data, 
                        apr_pool_t *ptmp) {
  char *copy;
  apr_status_t status;
  worker_t *body;
  int doit = 0;
  int not = 0;
  int else_pos = 0;
 
  COMMAND_NEED_ARG("Need left operant right parameters or an condition");
  
  if (copy[0] == '(') {
    /* expression evaluation */
    apr_size_t len;
    long val;
    math_eval_t *math = math_eval_make(ptmp);
    ++copy;
    len = strlen(copy);
    if (len < 1) {
      worker_log(worker, LOG_ERR, "Empty condition");
      return APR_EINVAL;
    }
    copy[len-1] = 0;

    if ((status = math_evaluate(math, copy, &val)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Invalid condition");
      return status;
    }
    doit = val;
  }
  else {
    /* old behavour */
    char *left;
    char *right;
    apr_ssize_t left_val;
    apr_ssize_t right_val;
    char *middle;
    const char *err;
    int off;
    regex_t *compiled;
    apr_size_t len;
    char **argv;
    int i = 0;

    my_tokenize_to_argv(copy, &argv, ptmp, 0);
    left = argv[i]; i++;
    middle = argv[i]; i++;
    if (strcmp(middle, "NOT") == 0) {
      not = 1;
      middle = argv[i]; i++;
    }
    right = argv[i];
   
    if (!left || !middle || !right) {
      worker_log(worker, LOG_ERR, "%s: Syntax error '%s'", self->name, data);
      return APR_EGENERAL;
    }
    
    if (right[0] == '!') {
      not = 1;
      ++right;
    }
   
    if (strcmp(middle, "MATCH") == 0) {
      if (!(compiled = pregcomp(ptmp, right, &err, &off))) {
	worker_log(worker, LOG_ERR, "IF MATCH regcomp failed: %s", right);
	return APR_EINVAL;
      }
      len = strlen(left);
      if ((regexec(compiled, left, len, 0, NULL, PCRE_MULTILINE) == 0 && !not) ||
	  (regexec(compiled, left, len, 0, NULL, PCRE_MULTILINE) != 0 && not)) {
	doit = 1;
      }
    }
    else if (strcmp(middle, "EQUAL") == 0) {
      if (strcmp(left, right) == 0) {
	if (!not) {
	  doit = 1;
	}
	else {
	  if (not) {
	    doit = 0;
	  }
	}
      }
      else {
	if (not) {
	  doit = 1;
	}
      }
    }
    else {
      left_val = apr_atoi64(left);
      right_val = apr_atoi64(right);
      if (strcmp(middle, "EQ") == 0) {
	if ((left_val == right_val && !not) ||
	    (left_val != right_val && not)) {
	  doit = 1;
	}
      }
      else if (strcmp(middle, "LT") == 0) {
	if ((left_val < right_val && !not) ||
	    (left_val >= right_val && not)) {
	  doit = 1;
	}
      }
      else if (strcmp(middle, "GT") == 0) {
	if ((left_val > right_val && !not) ||
	    (left_val <= right_val && not)) {
	  doit = 1;
	}
      }
      else if (strcmp(middle, "LE") == 0) {
	if ((left_val <= right_val && !not) ||
	    (left_val > right_val && not)) {
	  doit = 1;
	}
      }
      else if (strcmp(middle, "GE") == 0) {
	if ((left_val >= right_val && !not) ||
	    (left_val < right_val && not)) {
	  doit = 1;
	}
      }
    }
  }

  if ((status = worker_body(&body, worker)) != APR_SUCCESS) {
    return status;
  }

  /* now split _IF body on _ELSE */
  if (worker_where_is_else(body, &else_pos) == APR_SUCCESS) {
    /* found _ELSE */
    if (doit) {
      body->cmd_from = 0;
      body->cmd_to = else_pos;
      status = body->interpret(body, worker, NULL);
      worker_log(worker, LOG_CMD, "_ELSE");
    }
    else {
      worker_log(worker, LOG_CMD, "_ELSE");
      body->cmd_from = else_pos + 1;
      body->cmd_to = 0;
      status = body->interpret(body, worker, NULL);
    }
  }
  else {
    /* did not found _ELSE */
    if (doit) {
      body->cmd_from = 0;
      body->cmd_to = 0;
      status = body->interpret(body, worker, NULL);
    }
  }

  worker_log(worker, LOG_CMD, "_END");

  worker_body_end(body, worker);
 
  return status;
}

/**
 * LOOP command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN <Number>|FOREVER
 *
 * @return APR_SUCCESS
 */
apr_status_t command_LOOP(command_t *self, worker_t *worker, char *data, 
                          apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  int loop;
  char **argv;
  int i;
  char *var;
  char *last;
  apr_time_t duration = 0;
  apr_time_t start;
  int initial = 0;

  COMMAND_NEED_ARG("<number>[s|ms]|FOREVER [<variable>[=<initial>]]"); 
 
  my_tokenize_to_argv(copy, &argv, ptmp, 0);

  if (strncmp(argv[0], "FOREVER", 7) == 0) {
    loop = -1;
  }
  else {
    loop = apr_atoi64(argv[0]);
  }

  if (argv[1] != NULL) {
    if (strcmp(argv[1], "[ms]") == 0) {
      /* this are miliseconds we wanna loop */
      /* apr_time_from_msec available in apr 1.4.x */
      duration = 1000 * loop;
      loop = -1;
      var = argv[2]; 
    }
    else {
      var = argv[1]; 
    }
  }
  else {
    var = NULL;
  }
  
  if (var && strchr(var, '=')) {
    var = apr_strtok(var, "=", &last);
    initial = apr_atoi64(last);
  }

  /* create a new worker body */
  if ((status = worker_body(&body, worker)) != APR_SUCCESS) {
    return status;
  }
  
  /* loop */
  start = apr_time_now();
  for (i = 0; loop == -1 || i < loop; i++) {
    /* interpret */
    if (var) {
      worker_var_set(body, var, apr_itoa(ptmp, i + initial));
    }
    if ((status = body->interpret(body, worker, NULL)) != APR_SUCCESS) {
      break;
    }
    if (duration != 0 && apr_time_now() - start >= duration) {
      break;
    }
  }
  
  /* special case to break the loop */
  if (status == -1) {
    status = APR_SUCCESS;
  }
  
  if (status != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Error in loop with count = %d", i);
  }
  
  worker_log(worker, LOG_CMD, "_END");
  
  worker_body_end(body, worker);
  return status;
}

/**
 * FOR command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN <variable> "<string>*"
 *
 * @return APR_SUCCESS
 */
apr_status_t command_FOR(command_t *self, worker_t *worker, char *data,
                         apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  char *last;
  char *var;
  char *list;
  char *cur;
  char **argv;

  COMMAND_NEED_ARG("<variable> \"<string>*\""); 
 
  my_tokenize_to_argv(copy, &argv, ptmp, 0);
  var = argv[0];
  list = argv[1];

  /* create a new worker body */
  if ((status = worker_body(&body, worker)) != APR_SUCCESS) {
    return status;
  }
  
  /* for */
  cur = apr_strtok(list, " \n\t", &last);
  while (cur) {
    /* interpret */
    worker_var_set(body, var, cur);
    if ((status = body->interpret(body, worker, NULL)) != APR_SUCCESS) {
      break;
    }
    cur = apr_strtok(NULL, " \n\t", &last);
  }
  
  /* special case to break the loop */
  if (status == -1) {
    status = APR_SUCCESS;
  }
  
  worker_log(worker, LOG_CMD, "_END");
  
  worker_body_end(body, worker);
  
  return status;
}

/**
 * BPS command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN header name (spaces are possible) 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_BPS(command_t *self, worker_t *worker, char *data, 
                         apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  int bps;
  int duration;
  char **argv;
  apr_time_t init;
  apr_time_t start;
  apr_time_t cur;

  COMMAND_NEED_ARG("Byte/s and duration time in second"); 

  my_tokenize_to_argv(copy, &argv, ptmp, 0);
  bps = apr_atoi64(argv[0]);
  duration = apr_atoi64(argv[1]);
  
  /* create a new worker body */
  if ((status = worker_body(&body, worker)) != APR_SUCCESS) {
    return status;
  }
  
  /* loop */
  init = apr_time_now();
  for (;;) {
    /* interpret */
    start = apr_time_now();
    if ((status = body->interpret(body, worker, NULL)) != APR_SUCCESS) {
      break;
    }
    cur = apr_time_now();

    if (bps > 0) {
      /* avoid division by zero, do happen on windows */
      while ((cur - start == 0)) {
        /* wait 1 ms */
        apr_sleep(1000);
        cur = apr_time_now();
      }
      
      /* wait loop until we are below the max bps */
      while (((body->sent * APR_USEC_PER_SEC) / (cur - start)) > bps ) {
        /* wait 1 ms */
        apr_sleep(1000);
        cur = apr_time_now();
      }
    }

    /* reset sent bytes */
    body->sent = 0;

    /* test termination */
    if (apr_time_sec(cur - init) >= duration) {
      goto end;
    }
  }
  
end:
  worker_log(worker, LOG_CMD, "_END");
  
  worker_body_end(body, worker);
  
  return status;
}

/**
 * RPS command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN header name (spaces are possible) 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_RPS(command_t *self, worker_t *worker, char *data, 
                         apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  char **argv;
  int rps;
  float ideal_req_time;
  int duration;
  apr_time_t init;
  apr_time_t cur_sec;
  apr_time_t cur;
  apr_time_t elapsed;

  COMMAND_NEED_ARG("Byte/s and duration time in second"); 

  my_tokenize_to_argv(copy, &argv, ptmp, 0);
  rps = apr_atoi64(argv[0]);
  ideal_req_time = 1.0 / rps;
  duration = apr_atoi64(argv[1]);
  
  /* create a new worker body */
  if ((status = worker_body(&body, worker)) != APR_SUCCESS) {
    return status;
  }
  
  /* loop */
  cur_sec = init = apr_time_now();
  for (;;) {
    /* interpret */
    if ((status = body->interpret(body, worker, NULL)) != APR_SUCCESS) {
      break;
    }
    cur = apr_time_now();

    if (rps > 0) {
      /* wait until we are below the max rps */
      apr_time_t ideal_time = (ideal_req_time * body->req_cnt) * APR_USEC_PER_SEC;
      apr_time_t act_time   = cur - cur_sec;
      while (act_time < ideal_time) {
        apr_sleep(ideal_time - act_time);
        cur = apr_time_now();
        act_time = cur - cur_sec;
      }

      /* reset sent requests */
      elapsed = cur - cur_sec - APR_USEC_PER_SEC;
      if (elapsed > 0) {
        body->req_cnt = 0;
        cur_sec = cur - elapsed;
      }
    }

    /* test termination */
    if (apr_time_sec(cur - init) >= duration) {
      goto end;
    }
  }
  
end:
  worker_log(worker, LOG_CMD, "_END");
  
  worker_body_end(body, worker);
  
  return status;
}

/**
 * ERROR command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN expected errors
 *
 * @return APR_SUCCESS
 */
apr_status_t command_ERROR(command_t *self, worker_t *worker, char *data, 
                           apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  char **argv;
  char *status_str;
  regex_t *compiled;
  const char *err;
  int off;

  COMMAND_NEED_ARG("<error>"); 
 
 if ((status = my_tokenize_to_argv(copy, &argv, ptmp, 0)) == APR_SUCCESS) {
    if (!argv[0]) {
      worker_log(worker, LOG_ERR, "No argument found, need an regex for expected errof.");
      return APR_EINVAL;
    }
  }
  else {
    worker_log(worker, LOG_ERR, "Could not read argument");
    return status;
  }

  /* store value by his index */
  if (!(compiled = pregcomp(ptmp, argv[0], &err, &off))) {
    worker_log(worker, LOG_ERR, "ERROR condition compile failed: \"%s\"", argv[0]);
    return APR_EINVAL;
  }

  /* create a new worker body */
  if ((status = worker_body(&body, worker)) != APR_SUCCESS) {
    return status;
  }
  
  /* interpret */
  status = body->interpret(body, worker, NULL);
  
  status_str = my_status_str(ptmp, status);
  if (regexec(compiled, status_str, strlen(status_str), 0, NULL, 0) != 0) {
    worker_log(worker, LOG_ERR, "Did expect error \"%s\" but got \"%s\"", argv[0], 
	             status_str);
    return APR_EINVAL;
  }
  else {
    status = APR_SUCCESS;
  }

  worker_log(worker, LOG_CMD, "_END");
  
  if (worker->socket) {
    worker->socket->config = apr_hash_make(worker->pbody);
  }
  worker_body_end(body, worker);
  return status;
}

/**
 * SOCKET command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_SOCKET(command_t *self, worker_t *worker, char *data, 
                            apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *body;

  COMMAND_NO_ARG;

  if (!worker->socket) {
    worker_log(worker, LOG_ERR, "Call _RES or REQ before you spawn a long life _SOCKET");
    return APR_ENOSOCKET;
  }

  worker_flush(worker, ptmp);

  /* create a new worker body */
  if ((status = worker_body(&body, worker)) != APR_SUCCESS) {
    return status;
  }

  status = body->interpret(body, worker, NULL);
  
  worker_log(worker, LOG_CMD, "_END");
  
  worker_body_end(body, worker);
  return status;
}

/**
 * MILESTONE command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused 
 * @note: dependency to finally, tests MUST fail if one milestone failed
 *
 * @return APR_SUCCESS
 */
apr_status_t command_MILESTONE(command_t *self, worker_t *worker, char *data, 
                               apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  milestone_t *milestone;

  COMMAND_NEED_ARG("<name>");

  worker_log(worker, LOG_NONE, "Milestone \"%s\"", copy);
  worker_flush(worker, ptmp);

  /* create a new worker body */
  if ((status = worker_body(&body, worker)) != APR_SUCCESS) {
    return status;
  }

  status = body->interpret(body, worker, NULL);
  
  worker_log(worker, LOG_CMD, "_END");
  
  worker_body_end(body, worker);

  /* store status but do not evaluate it */
  milestone = module_get_config(worker->config, "_MILESTONE");
  if (!milestone) {
    milestone = apr_pcalloc(worker->pbody, sizeof(*milestone));
    module_set_config(worker->config, apr_pstrdup(worker->pbody, "MILESTONE "), 
                      milestone);
  }
  if (status != APR_SUCCESS) {
    ++milestone->failures;
  }
  ++milestone->milestones;
  milestone->status = status;

  return APR_SUCCESS;
}

