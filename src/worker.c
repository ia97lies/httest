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
 * Implementation of the HTTP Test Tool worker.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <apr_version.h>
#include "defines.h"

#include <apr.h>
#include <apr_lib.h>
#include <apr_errno.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_thread_proc.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_portable.h>
#include <apr_hash.h>
#include <apr_base64.h>
#include <apr_hooks.h>
#include <apr_env.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#include "defines.h"
#include "util.h"
#include "replacer.h"
#include "regex.h"
#include "file.h"
#include "transport.h"
#include "socket.h"
#include "worker.h"
#include "module.h"
#include "eval.h"
#include "tcp_module.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/

typedef struct write_buf_to_file_s {
  char *buf;
  apr_size_t len;
  apr_file_t *fp;
} write_buf_to_file_t;

typedef struct tunnel_s {
  sockreader_t *sockreader;
  socket_t *sendto;
} tunnel_t;

typedef struct flush_s {
#define FLUSH_DO_NONE 0
#define FLUSH_DO_SKIP 1
  int flags;
} flush_t;

typedef struct replacer_s {
  int unresolved;
  apr_pool_t *ptmp;
  worker_t *worker;
} replacer_t;

#define RECORDER_CONFIG "RECORDER"
typedef struct recorder_s {
  int on;
#define RECORDER_OFF 0
#define RECORDER_RECORD 1
#define RECORDER_PLAY 2
  int flags;
#define RECORDER_RECORD_NONE 0
#define RECORDER_RECORD_STATUS 1
#define RECORDER_RECORD_HEADERS 2
#define RECORDER_RECORD_BODY 4
#define RECORDER_RECORD_ALL RECORDER_RECORD_STATUS|RECORDER_RECORD_HEADERS|RECORDER_RECORD_BODY 
  sockreader_t *sockreader;
} recorder_t;

#define SH_CONFIG "SH"
typedef struct sh_s {
  apr_pool_t *pool;
  apr_file_t *tmpf;
} sh_t;

#define EXEC_CONFIG "EXEC"
typedef struct exec_s {
  apr_pool_t *pool;
  apr_proc_t *proc;
} exec_t;


/************************************************************************
 * Globals 
 ***********************************************************************/
extern int success;

/************************************************************************
 * Implementation
 ***********************************************************************/

const char *worker_get_file_and_line(worker_t *worker) {
  if (worker && worker->lines) {
    apr_table_entry_t *e =
      (apr_table_entry_t *) apr_table_elts(worker->lines)->elts;
    if (worker->cmd < apr_table_elts(worker->lines)->nelts) {
      return e[worker->cmd].key;
    }
  }
  return NULL;
}

/**
 * checked lock function, will exit FAILED if status not ok
 *
 * @param mutex IN mutex
 */
void lock(apr_thread_mutex_t *mutex) {
  apr_status_t status;
  if ((status = apr_thread_mutex_lock(mutex)) != APR_SUCCESS) {
    apr_pool_t *ptmp;
    HT_POOL_CREATE(&ptmp);
    success = 0;
    fprintf(stderr, "could not lock: %s(%d)\n", 
	    my_status_str(ptmp, status), status);
    exit(1);
  }
}

/**
 * checked unlock function, will exit FAILED if status not ok
 *
 * @param mutex IN mutex
 */
void unlock(apr_thread_mutex_t *mutex) {
  apr_status_t status;
  if ((status = apr_thread_mutex_unlock(mutex)) != APR_SUCCESS) {
    apr_pool_t *ptmp;
    HT_POOL_CREATE(&ptmp);
    success = 0;
    fprintf(stderr, "could not unlock: %s(%d)\n", 
	    my_status_str(ptmp, status), status);
    exit(1);
  }
}

/**
 * Get recorder struct from worker config
 * @param worker IN thread object
 * @return recoder
 */
static recorder_t *worker_get_recorder(worker_t *worker) {
  recorder_t *recorder = module_get_config(worker->config, RECORDER_CONFIG);
  if (!recorder) {
    recorder = apr_pcalloc(worker->pbody, sizeof(recorder_t));
    module_set_config(worker->config, RECORDER_CONFIG, recorder);
  }
  return recorder;
}

/**
 * Set a variable either as local or global,
 * make a copy of passed value and replace existing value.
 * Always adds the terminating zero to the stored value.
 * So if you want to store an already zero terminated string "myStr", then pass "strlen(myStr)" in len.
 *
 * @param worker IN thread object
 * @param var IN variable name
 * @param val IN zero terminated or not terminated string to store
 * @param len IN length of val string (without terminating zero)
 */
void worker_var_set_and_zero_terminate(worker_t * worker, const char *var, const char *val, apr_size_t len) {
  const char *ret;

  /* do mapping from ret var to var */
  if ((ret = store_get(worker->retvars, var))) {
	  store_set_and_zero_terminate(worker->vars, ret, val, len);
    return;
  }

  /* if not test if local */
  if (store_get(worker->locals, var)) {
	  store_set_and_zero_terminate(worker->locals, var, val, len);
    return;
  }

  /* params can be shadowed by locals so this after locals */
  if (store_get(worker->params, var)) {
	  store_set_and_zero_terminate(worker->params, var, val, len);
    return;
  }

  /* test if there are globals at all to avoid locking  */
  if (worker->global->shared) {
    /* test if this variable is a global one */
    apr_thread_mutex_lock(worker->mutex);
    if (store_get(worker->global->shared, var)) {
      store_set_and_zero_terminate(worker->global->shared, var, val, len);
      apr_thread_mutex_unlock(worker->mutex);
      return;
    }
    apr_thread_mutex_unlock(worker->mutex);
  }

  /* if there is no var at all stored it in thread global vars */
  store_set_and_zero_terminate(worker->vars, var, val, len);
}


/**
 * set a variable either as local or global
 * make a copy and replace existing
 *
 * @param worker IN thread object
 * @param var IN variable name
 * @param val IN zero terminated string value to set
 */
void worker_var_set(worker_t * worker, const char *var, const char *val) {
  apr_size_t len = (val == NULL) ? 0 : strlen(val);
  worker_var_set_and_zero_terminate(worker, var, val, len);
}

/**
 * get a variable either as local or global
 *
 * @param worker IN thread object
 * @param var IN variable name
 *
 * @return value
 */
const char *worker_var_get(worker_t* worker, const char *var) {
  const char *val = NULL;

  /* first test locals */
  if ((val = store_get(worker->locals, var))) {
    return val;
  }
  
  /* next are params */
  if ((val = store_get(worker->params, var))) {
    return val;
  }

  /* next are thread globals */
  if ((val = store_get(worker->vars, var))) {
    return val;
  }

  /* last test globals */
  if (worker->global->shared) {
    apr_thread_mutex_lock(worker->mutex);
    val = store_get(worker->global->shared, var);
    apr_thread_mutex_unlock(worker->mutex);
  }
  return val;
}

/**
 * resolve vars
 * @param worker IN callee 
 * @param name IN name to lookup
 * @param ptmp IN temp pool
 * @return value
 */
const char * worker_resolve_var(worker_t *worker, const char *name, apr_pool_t *ptmp) {
  const char *val = NULL;

  if (strchr(name, '(')) {
    int log_mode;
    char *command = apr_pstrdup(ptmp, name);
    int i = 0;
    while (command[i] != 0) {
      if (command[i] == '(' || command[i] == ')') {
	command[i] = ' ';
      }
      ++i;
    }
    command = apr_pstrcat(ptmp, command, " __INLINE_RET", NULL);
    /** call it */
    log_mode = logger_get_mode(worker->logger);
    logger_set_mode(worker->logger, 0);
    if (command_CALL(NULL, worker, command, ptmp) == APR_SUCCESS) {
      val = worker_var_get(worker, "__INLINE_RET");
    }
    logger_set_mode(worker->logger, log_mode);
  }

  if (!val) {
    val = worker_var_get(worker, name);
  }

  return val;
}

/**
 * replace vars upcall function
 * @param udata IN void pointer to replacer_t object
 * @param name IN name to lookup
 * @return value
 */
static const char * replacer_upcall(void *udata, const char *name) {
  const char *val = NULL;
  replacer_t *hook = udata; 

  val = worker_resolve_var(hook->worker, name, hook->ptmp);
  if (!val) {
    hook->unresolved = 1;
  }
  return val;
}

/**
 * Replace vars with store, inline call and env vars
 * @param udata IN void pointer to replacer_t object
 * @param name IN variable name
 * @return value
 */
static const char * replacer_env_upcall(void *udata, const char *name) {
  const char *val = NULL;
  replacer_t *hook = udata;
  int unresolved = hook->unresolved;
  
  val = replacer_upcall(udata, name);
  if (!val) {
    char *env;
    hook->unresolved = unresolved;
    if (apr_env_get(&env, name, hook->ptmp) == APR_SUCCESS) {
      val = env;
    }
    if (!val) {
      hook->unresolved = 1;
    }
  }
  return val;
}

/**
 * replace variables in a line
 *
 * @param worker IN thread data object
 * @param line IN line to replace in
 *
 * @return new line 
 */
char * worker_replace_vars(worker_t * worker, char *line, int *unresolved,
                           apr_pool_t *ptmp) {
  char *new_line;
  replacer_t *upcall_hook = apr_pcalloc(ptmp, sizeof(*upcall_hook));

  upcall_hook->worker = worker;
  upcall_hook->ptmp = ptmp;
  new_line = replacer(ptmp, line, upcall_hook, replacer_env_upcall); 

  if (unresolved) {
    *unresolved = upcall_hook->unresolved;
  }
  return new_line;
}

/**
 * client thread
 *
 * @param thread IN thread object
 * @param selfv IN void pointer to tunnel object
 *
 * @return NULL 
 */
static void * APR_THREAD_FUNC streamer(apr_thread_t * thread, void *selfv) {
  apr_status_t status;
  char buf[BLOCK_MAX];
  apr_size_t len;

  tunnel_t *tunnel = selfv;

  do {
    /* read polled from and send to */
    len = BLOCK_MAX - 1;
    status = sockreader_read_block(tunnel->sockreader, buf, &len);
    if (APR_STATUS_IS_EOF(status) && len > 0) {
      status = APR_SUCCESS;
    }
    else if (APR_STATUS_IS_TIMEUP(status)) {
      status = APR_SUCCESS;
    }
    if (status == APR_SUCCESS) {
      status = transport_write(tunnel->sendto->transport, buf, len);
    }
  } while (status == APR_SUCCESS);

  if (APR_STATUS_IS_EOF(status)) {
    status = APR_SUCCESS;
  }
  apr_thread_exit(thread, APR_SUCCESS);
  return NULL;
}

/**
 * local file write 
 *
 * @param sockett IN socket 
 * @param buf IN buffer to send
 * @param len IN no bytes of buffer to send
 *
 * @return apr status
 */
static apr_status_t file_write(apr_file_t *file, char *buf,
                               apr_size_t len) {
  apr_status_t status = APR_SUCCESS;
  apr_size_t total = len;
  apr_size_t count = 0;

  while (total != count) {
    len = total - count;
    if ((status = apr_file_write(file, &buf[count], &len)) 
	!= APR_SUCCESS) {
      goto error;
    }
    count += len;
  }
error:
  return status;
}

/**
 * Buffer converter depends on the worker->flags
 *
 * @param worker IN thread data object
 * @param buf INOUT buffer to rewrite
 * @param len INOUT buffer len 
 */
static void worker_buf_convert(worker_t *self, char **buf, apr_size_t *len) {
  int j;
  char *hexbuf;
  apr_pool_t *pool;
  
  if (!(*buf)) {
    return;
  }
  
  if (self->flags & FLAGS_ONLY_PRINTABLE) {
    for (j = 0; j < *len; j++) {
      if ((*buf)[j] < 32) {
	(*buf)[j] = ' ';
      }
    }
  }
  
  if (self->flags & FLAGS_PRINT_HEX) {
    HT_POOL_CREATE(&pool);
    hexbuf = NULL;
    for (j = 0; j < *len; j++) {
      if (hexbuf == NULL) {
	 hexbuf = apr_psprintf(pool, "%02X", (*buf)[j]);
      }
      else {
	 hexbuf = apr_psprintf(pool, "%s %02X", hexbuf, (*buf)[j]);
      }
    }
    *buf = apr_pstrdup(self->pbody, hexbuf);
    *len = strlen(*buf);
    apr_pool_destroy(pool);
  }
}

/**
 * pipe buf to workers running process 
 *
 * @param worker IN thread data object
 * @param buf IN buffer to rewrite
 * @param len IN buffer len 
 */
static apr_status_t worker_buf_pipe_exec(worker_t *worker, char *buf, 
                                         apr_size_t len) {
  apr_status_t status = APR_SUCCESS;
  apr_exit_why_e exitwhy;
  int exitcode;
  exec_t *exec = module_get_config(worker->config, EXEC_CONFIG);

  if ((status = file_write(exec->proc->in, buf, len))
      != APR_SUCCESS) {
    return status;
  }
  apr_file_close(exec->proc->in);
  apr_proc_wait(exec->proc, &exitcode, &exitwhy, APR_WAIT);
  if (exitcode != 0) {
    status = APR_EGENERAL;
  }
  module_set_config(worker->config, EXEC_CONFIG, NULL);
  apr_pool_destroy(exec->pool);
  return status;
}

/**
 * write buf to file pointer
 *
 * @param thread IN thread pointer
 * @param selfv IN void pointer of type write_buf_to_file_t
 *
 * @return NULL
 */
static void * APR_THREAD_FUNC worker_write_buf_to_file(apr_thread_t * thread, void *selfv) {
  write_buf_to_file_t *wbtf = selfv;
  apr_size_t len;

  len = wbtf->len;
  file_write(wbtf->fp, wbtf->buf, len);
  apr_file_close(wbtf->fp);

  apr_thread_exit(thread, APR_SUCCESS);
  return NULL;
}

/**
 * do filter buf with workers process in/out 
 *
 * @param worker IN thread data object
 * @param ptmp IN temporary pool to alloc thread
 * @param buf INOUT buffer to rewrite
 * @param len INOUT buffer len 
 */
static apr_status_t worker_buf_filter_exec(worker_t *worker, apr_pool_t *ptmp, 
                                           char **buf, apr_size_t *len) {
  apr_status_t status;
  apr_status_t tmp_status;
  write_buf_to_file_t write_buf_to_file;
  apr_threadattr_t *tattr;
  apr_thread_t *thread;
  bufreader_t *br;
  apr_exit_why_e exitwhy;
  int exitcode;
  exec_t *exec = module_get_config(worker->config, EXEC_CONFIG);

  worker_log(worker, LOG_DEBUG, "write to stdin, read from stdout");
  /* start write thread */
  write_buf_to_file.buf = *buf;
  write_buf_to_file.len = *len;
  write_buf_to_file.fp = exec->proc->in;
  if ((status = apr_threadattr_create(&tattr, ptmp)) != APR_SUCCESS) {
    goto out_err;
  }
  if ((status = apr_threadattr_stacksize_set(tattr, DEFAULT_THREAD_STACKSIZE))
      != APR_SUCCESS) {
    goto out_err;
  }
  if ((status = apr_threadattr_detach_set(tattr, 1)) != APR_SUCCESS) {
    goto out_err;
  }
  if ((status =
       apr_thread_create(&thread, tattr, worker_write_buf_to_file,
			 &write_buf_to_file, worker->pbody)) != APR_SUCCESS) {
    goto out_err;
  }
  /* read from worker->proc.out to buf */
  if ((status = bufreader_new(&br, exec->proc->out, worker->pbody)) == APR_SUCCESS) {
    bufreader_read_eof(br, buf, len);
  }
  if (status == APR_EOF) {
    status = APR_SUCCESS;
  }
  apr_thread_join(&tmp_status, thread);
  apr_proc_wait(exec->proc, &exitcode, &exitwhy, APR_WAIT);
  if (exitcode != 0) {
    status = APR_EGENERAL;
    goto out_err;
  }
out_err:
  module_set_config(worker->config, EXEC_CONFIG, NULL);
  apr_pool_destroy(exec->pool);
  return status;
}


/**
 * Test socket state
 *
 * @param worker IN thread data object
 *
 * @return APR_SUCCESS or APR_ECONNABORTED
 */
apr_status_t worker_sockstate(worker_t * worker) {
  apr_status_t status = APR_SUCCESS;
  apr_size_t len = 1;

  if (!worker->socket) {
    return APR_ENOSOCKET;
  }
  
  if ((status = transport_set_timeout(worker->socket->transport, 1000)) 
      != APR_SUCCESS) {
    return status;
  }

  status = transport_read(worker->socket->transport, 
			  &worker->socket->peek[worker->socket->peeklen], &len);
  if (APR_STATUS_IS_TIMEUP(status)) {
    status = APR_SUCCESS;
  }

  if (APR_STATUS_IS_EOF(status)) {
    status = APR_ECONNABORTED; 
    goto go_out;
  }
  else if (status != APR_SUCCESS) {
    status = APR_ECONNABORTED; 
    goto go_out;
  }
  else {
    worker->socket->peeklen += len;
    status = APR_SUCCESS;
    goto go_out;
  }

go_out:
  transport_set_timeout(worker->socket->transport, worker->socktmo);

  return status;
}

/**
 * gets values from data and store it in the variable table
 *
 * @param worker IN thread data object
 * @param htt_regexs IN table of regular expressions to get the values from data
 * @param data IN data to match
 *
 * @return APR_SUCCESS
 */
apr_status_t worker_match(worker_t * worker, apr_table_t * htt_regexs, 
                          const char *data, apr_size_t len) {
  apr_table_entry_t *e;
  apr_table_entry_t *v;
  regmatch_t regmatch[11];
  int i;
  int j;
  char *val;
  char *last;
  char *var;
  char *tmp;
  apr_table_t *vtbl;
  int n;
  apr_pool_t *pool;
  apr_status_t status = APR_SUCCESS;

  if (!data) {
    return APR_SUCCESS;
  }

  HT_POOL_CREATE(&pool);
  vtbl = apr_table_make(pool, 2);
  
  e = (apr_table_entry_t *) apr_table_elts(htt_regexs)->elts;
  for (i = 0; i < apr_table_elts(htt_regexs)->nelts; ++i) {
    /* prepare vars if multiple */
    apr_table_clear(vtbl);
    tmp = apr_pstrdup(pool, e[i].key);
    var = apr_strtok(tmp, " ", &last);
    while (var) {
      apr_table_set(vtbl, var, var);
      var = apr_strtok(NULL, " ", &last);
    }

    n = apr_table_elts(vtbl)->nelts;
    if (n > 10) {
      worker_log(worker, LOG_ERR, "Too many vars defined for _MATCH statement, max 10 vars allowed");
      status = APR_EINVAL;
      goto error;
    }
    
    if (e[i].val
        && htt_regexec((htt_regex_t *) e[i].val, data, len, n + 1, regmatch,
                   PCRE_MULTILINE) == 0) {
      v = (apr_table_entry_t *) apr_table_elts(vtbl)->elts;
      for (j = 0; j < n; j++) {
	val =
	  apr_pstrndup(pool, &data[regmatch[j + 1].rm_so],
		       regmatch[j + 1].rm_eo - regmatch[j + 1].rm_so);
	worker_var_set(worker, v[j].key, val);
	if (worker->match_seq) {
	  /* if there is a defined match sequence do more checks */
	  if (strstr(worker->match_seq, v[j].key)) {
	   if (strncmp(v[j].key, worker->match_seq, strlen(v[j].key)) == 0) {
	     char *last;
	     /* remove the first var in the var sequence */
             apr_strtok(worker->match_seq, " ", &last);
	     worker->match_seq = last;
	   } 
	  }
	}
      }
    }
  }

error:
  apr_pool_destroy(pool);
  return status;
}

/**
 * checks if data contains a given pattern
 *
 * @param self IN thread data object
 * @param htt_regexs IN table of regular expressions
 * @param data IN data to check
 *
 * @return APR_SUCCESS
 */
apr_status_t worker_expect(worker_t * self, apr_table_t * htt_regexs, 
                           const char *data, apr_size_t len) {
  apr_table_entry_t *e;
  int i;

  if (!data) {
    return APR_SUCCESS;
  }

  e = (apr_table_entry_t *) apr_table_elts(htt_regexs)->elts;
  for (i = 0; i < apr_table_elts(htt_regexs)->nelts; ++i) {
    if (e[i].val
        && htt_regexec((htt_regex_t *) e[i].val, data, len, 0, NULL,
                   PCRE_MULTILINE) == 0) {
    }
  }

  return APR_SUCCESS;
}

/**
 * Throws assertions if specified match did have noch hit.
 * @param worker IN
 * @param match IN table of all specified matchs
 * @param namespace IN the namespace of this matchs
 * @param status IN current status of earlier calls
 * @return new status
 */
apr_status_t worker_assert_match(worker_t *worker, apr_table_t *match,
                                 char *namespace, apr_status_t status) {
  apr_table_entry_t *e;
  int i;
  apr_pool_t *pool;

  e = (apr_table_entry_t *) apr_table_elts(match)->elts;
  for (i = 0; i < apr_table_elts(match)->nelts; ++i) {
    htt_regex_t *htt_regex = (htt_regex_t *) e[i].val;
    if (!htt_regexhits(htt_regex)) {
      worker_log(worker, LOG_ERR, "%s: Did expect %s", namespace, htt_regexpattern(htt_regex));
      if (status == APR_SUCCESS) {
        status = APR_EINVAL;
      }
    }
  }
  apr_table_clear(match);
  pool = module_get_config(worker->config, namespace);
  module_set_config(worker->config, namespace, NULL);
  if (pool) {
    apr_pool_destroy(pool);
  }
  return status;
}

/**
 * Throws assertions if specified expect did have noch hit.
 * @param worker IN
 * @param expect IN table of all specified expects
 * @param namespace IN the namespace of this expects
 * @param status IN current status of earlier calls
 * @return new status
 */
apr_status_t worker_assert_expect(worker_t *worker, apr_table_t *expect,
                                  char *namespace, apr_status_t status) {
  apr_table_entry_t *e;
  int i;
  apr_pool_t *pool;

  e = (apr_table_entry_t *) apr_table_elts(expect)->elts;
  for (i = 0; i < apr_table_elts(expect)->nelts; ++i) {
    htt_regex_t *htt_regex = (htt_regex_t *) e[i].val;
    if (e[i].key[0] != '!' && !htt_regexhits(htt_regex)) {
      worker_log(worker, LOG_ERR, "%s: Did expect \"%s\"", namespace, 
	         htt_regexpattern(htt_regex));
      if (status == APR_SUCCESS) {
        status = APR_EINVAL;
      }
    }
    if (e[i].key[0] == '!' && htt_regexhits((htt_regex_t *) e[i].val)) {
      worker_log(worker, LOG_ERR, "%s: Did not expect \"%s\"", namespace, 
	         &e[i].key[1]);
      if (status == APR_SUCCESS) {
        status = APR_EINVAL;
      }
    }
  }
  apr_table_clear(expect);
  pool = module_get_config(worker->config, namespace);
  module_set_config(worker->config, namespace, NULL);
  if (pool) {
    apr_pool_destroy(pool);
  }
  return status;
}


/**
 * Grep do not have an assertion at all, actually.
 * @param worker IN
 * @param expect IN table of all specified expects
 * @param namespace IN the namespace of this expects
 * @param status IN current status of earlier calls
 * @return new status
 */
static apr_status_t worker_assert_grep(worker_t * worker, apr_table_t *grep, 
                                       char *namespace, apr_status_t status) {
  apr_pool_t *pool;

  apr_table_clear(grep);
  pool = module_get_config(worker->config, namespace);
  module_set_config(worker->config, namespace, NULL);
  if (pool) {
    apr_pool_destroy(pool);
  }
  return status;
}

/**
 * Do check for if all defined expects are handled 
 *
 * @param worker IN worker thread object
 * @param status IN current status
 *
 * @return current status or APR_EINVAL if there are unhandled expects
 */
apr_status_t worker_assert(worker_t * worker, apr_status_t status) {
  status = worker_assert_match(worker, worker->match.dot, "MATCH .", 
                               status);
  status = worker_assert_match(worker, worker->match.headers, "MATCH headers", 
                               status);
  status = worker_assert_match(worker, worker->match.body, "MATCH body", 
                               status);
  status = worker_assert_expect(worker, worker->expect.dot, "EXPECT .", 
                               status);
  status = worker_assert_expect(worker, worker->expect.headers, "EXPECT headers", 
                               status);
  status = worker_assert_expect(worker, worker->expect.body, "EXPECT body", 
                                status);
  status = worker_assert_grep(worker, worker->grep.dot, "GREP .", 
                              status);
  status = worker_assert_grep(worker, worker->grep.headers, "GREP headers", 
                              status);
  status = worker_assert_grep(worker, worker->grep.body, "GREP body", 
                              status);
  /* check if match sequence is empty */

  if (worker->match_seq && worker->match_seq[0] != 0) {
    worker_log(worker, LOG_ERR, "The following match sequence \"%s\" was not in correct order", worker->match_seq);
    status = APR_EINVAL;
    goto exit;
  }
exit:
  {
    apr_pool_t *pool;
    pool = module_get_config(worker->config, "MATCH_SEQ");
    if (pool) {
      module_set_config(worker->config, apr_pstrdup(pool, "MATCH_SEQ"), NULL);
      apr_pool_destroy(pool);
    }
  }
  return status;
}

/**
 * Check for error expects handling
 *
 * @param worker IN worker thread object
 * @param status IN current status
 *
 * @return current status or APR_INVAL
 */
apr_status_t worker_check_error(worker_t *worker, apr_status_t status) {
  char *error;
  apr_table_entry_t *e;
  int i;

  /* nothing to do in this case */
  if (status == APR_SUCCESS) {
    return status;
  }
  
  /* handle special case (break loop) */
  if (status == -1) {
    return status;
  }

  error = apr_psprintf(worker->pbody, "%s(%d)",
		     my_status_str(worker->pbody, status), status);

  worker_match(worker, worker->match.error, error, strlen(error));
  worker_match(worker, worker->grep.error, error, strlen(error));
  worker_expect(worker, worker->expect.error, error, strlen(error));

  if (apr_table_elts(worker->expect.error)->nelts) {
    status = APR_SUCCESS;
    e = (apr_table_entry_t *) apr_table_elts(worker->expect.error)->elts;
    for (i = 0; i < apr_table_elts(worker->expect.error)->nelts; ++i) {
      if (e[i].key[0] != '!' && !htt_regexhits((htt_regex_t *) e[i].val)) {
	worker_log(worker, LOG_ERR, "EXPECT: Did expect error \"%s\"", e[i].key);
	status = APR_EINVAL;
	goto error;
      }
      if (e[i].key[0] == '!' && htt_regexhits((htt_regex_t *) e[i].val)) {
	worker_log(worker, LOG_ERR, "EXPECT: Did not expect error \"%s\"", &e[i].key[1]);
	status = APR_EINVAL;
	goto error;
      }
    }
    apr_table_clear(worker->expect.error);
  }
 
  if (apr_table_elts(worker->match.error)->nelts) {
    status = APR_SUCCESS;
    e = (apr_table_entry_t *) apr_table_elts(worker->match.error)->elts;
    for (i = 0; i < apr_table_elts(worker->match.error)->nelts; ++i) {
      if (!htt_regexhits((htt_regex_t *) e[i].val)) {
	worker_log(worker, LOG_ERR, "MATCH error: Did expect %s", e[i].key);
	status = APR_EINVAL;
      }
    }
    apr_table_clear(worker->match.error);
  }

error:
  if (status == APR_SUCCESS) {
    worker_log(worker, LOG_INFO, "%s %s", worker->name, error);
  }
  else {
    worker_log(worker, LOG_ERR, "%s %s", worker->name, error);
  }
  return status;
}

/**
 * Test for unused expects and matchs
 * @param worker IN thread data object
 * @return APR_SUCCESS or APR_EGENERAL
 */
void worker_test_reset(worker_t * worker) {
  apr_table_clear(worker->match.dot);
  apr_table_clear(worker->match.headers);
  apr_table_clear(worker->match.body);
  apr_table_clear(worker->match.error);
  apr_table_clear(worker->expect.dot);
  apr_table_clear(worker->expect.headers);
  apr_table_clear(worker->expect.body);
  apr_table_clear(worker->expect.error);
}

/**
 * Test for unused expects and matchs
 * @param worker IN thread data object
 * @return APR_SUCCESS or APR_EGENERAL
 */
apr_status_t worker_test_unused(worker_t * worker) {
  if (apr_table_elts(worker->match.dot)->nelts) {
    worker_log(worker, LOG_ERR, "There are unused MATCH .");
    return APR_EGENERAL;
  }
  if (apr_table_elts(worker->match.headers)->nelts) {
    worker_log(worker, LOG_ERR, "There are unused MATCH headers");
    return APR_EGENERAL;
  }
  if (apr_table_elts(worker->match.body)->nelts) {
    worker_log(worker, LOG_ERR, "There are unused MATCH body");
    return APR_EGENERAL;
  }
  if (apr_table_elts(worker->match.exec)->nelts) {
    worker_log(worker, LOG_ERR, "There are unused MATCH exec");
    return APR_EGENERAL;
  }
  if (apr_table_elts(worker->expect.dot)->nelts) {
    worker_log(worker, LOG_ERR, "There are unused EXPECT .");
    return APR_EGENERAL;
  }
  if (apr_table_elts(worker->expect.headers)->nelts) {
    worker_log(worker, LOG_ERR, "There are unused EXPECT headers");
    return APR_EGENERAL;
  }
  if (apr_table_elts(worker->expect.body)->nelts) {
    worker_log(worker, LOG_ERR, "There are unused EXPECT body");
    return APR_EGENERAL;
  }

  return APR_SUCCESS;
}

/**
 * Test for unused expects errors and matchs
 *
 * @param worker IN thread data object
 *
 * @return APR_SUCCESS or APR_EGENERAL
 */
apr_status_t worker_test_unused_errors(worker_t * worker) {
  if (apr_table_elts(worker->expect.error)->nelts) { 
    worker_log(worker, LOG_ERR, "There are unused EXPECT ERROR");
    return APR_EGENERAL;
  }

  if (apr_table_elts(worker->match.error)->nelts) {
    worker_log(worker, LOG_ERR, "There are unused MATCH ERROR");
    return APR_EGENERAL;
  }
 
  return APR_SUCCESS;
}

/**
 * Close current socket
 *
 * @param self IN thread data object
 *
 * @return apr status
 */
apr_status_t worker_conn_close(worker_t * self, char *info) {
  apr_status_t status;

  if (!self->socket) {
    return APR_ENOSOCKET;
  }

  if (self->socket->socket_state == SOCKET_CLOSED) {
    return APR_SUCCESS;
  }
   
  if ((status = htt_run_pre_close(self)) != APR_SUCCESS) {
    return status;
  }

  if ((status = htt_run_close(self, info, &info)) != APR_SUCCESS) {
    if (APR_STATUS_IS_EINTR(status)) {
      return APR_SUCCESS;
    }
    return status;
  }

  if (!info || !info[0] || strcmp(info, "TCP") == 0) {
    tcp_close(self);
    self->socket->socket_state = SOCKET_CLOSED;
  }

  sockreader_destroy(&self->socket->sockreader);

  return APR_SUCCESS;
}

/**
 * Close all sockets for this worker
 *
 * @param self IN thread data object
 *
 * @return apr status
 */
void worker_conn_close_all(worker_t *self) {
  apr_hash_index_t *hi;
  void *s;
  
  socket_t *cur = self->socket;

  for (hi = apr_hash_first(self->pbody, self->sockets); hi; hi = apr_hash_next(hi)) {
    apr_hash_this(hi, NULL, NULL, &s);
    self->socket = s;
    worker_conn_close(self, NULL);
  }
  self->socket = cur;
  if (self->listener) {
    apr_socket_close(self->listener);
  }
}

/**
 * Convertion and/or pipe to executable and/or read from executable and check
 * _EXPECT and MATCH.
 *
 * @param worker IN worker object
 * @param buf IN buffer to handle
 * @param len IN length of buffer
 *
 * @return apr status
 */
apr_status_t worker_handle_buf(worker_t *worker, apr_pool_t *pool, char *buf, 
                               apr_size_t size) {
  apr_status_t status = APR_SUCCESS;
  char *tmpbuf = buf;
  apr_size_t len = size;

  if (tmpbuf) {
    worker_buf_convert(worker, &tmpbuf, &len);
    if (worker->flags & FLAGS_PIPE_IN) {
      worker->flags &= ~FLAGS_PIPE_IN;
      if ((status = worker_buf_pipe_exec(worker, tmpbuf, len)) != APR_SUCCESS) {
	return status;
      }
    }
    else if (worker->flags & FLAGS_FILTER) {
      worker->flags &= ~FLAGS_FILTER;
      if ((status =  worker_buf_filter_exec(worker, pool, &tmpbuf, &len)) != APR_SUCCESS) {
        return status;
      }	
    }
    if (tmpbuf) {
        worker_log_buf(worker, LOG_INFO, '<', tmpbuf, len);
        worker_match(worker, worker->match.dot, tmpbuf, len);
        worker_match(worker, worker->match.body, tmpbuf, len);
        worker_match(worker, worker->grep.dot, tmpbuf, len);
        worker_match(worker, worker->grep.body, tmpbuf, len);
        worker_expect(worker, worker->expect.dot, tmpbuf, len);
        worker_expect(worker, worker->expect.body, tmpbuf, len);
    }
  }
  return status;
}

/**
 * Store all cookies in the header table of worker in a cookie line
 *
 * @param worker IN thread data object
 */
static void worker_set_cookie(worker_t *worker) {
  int i;
  apr_table_entry_t *e;

  if (!worker->socket) {
    return;
  }

  if (!worker->socket->cookies) {
    worker->socket->cookies = apr_table_make(worker->pbody, 5);
  }

  e = (apr_table_entry_t *) apr_table_elts(worker->headers)->elts;
  for (i = 0; i < apr_table_elts(worker->headers)->nelts; ++i) {
    if (strcmp(e[i].key, "Set-Cookie") == 0) { 
      char *last;
      char *key;
      char *value;
      char *cookie = apr_pstrdup(worker->pbody, e[i].val);
      key = apr_strtok(cookie, "=", &last);
      value = apr_strtok(NULL, ";", &last);
      apr_table_set(worker->socket->cookies, key, value); 
    }
  }

  worker->socket->cookie = NULL;
  e = (apr_table_entry_t *) apr_table_elts(worker->socket->cookies)->elts;
  for (i = 0; i < apr_table_elts(worker->socket->cookies)->nelts; ++i) {
    if (worker->socket->cookie) {
      worker->socket->cookie = apr_pstrcat(worker->pbody, 
					   worker->socket->cookie, "; ", 
					   e[i].key, "=", e[i].val, NULL);
    }
    else {
      worker->socket->cookie = apr_pstrcat(worker->pbody, "Cookie: ", e[i].key, "=", 
					   e[i].val, NULL);
    }
  }
}

/**
 * Get value from a given param
 * @param worker IN thread data object
 * @param param IN resolved param or VAR param
 * @return final resolved value
 */
const char *worker_get_value_from_param(worker_t *worker, const char *param, apr_pool_t *ptmp) {
  const char *val = NULL;

  if (strncmp(param, "VAR(", 4) == 0) {
    char *var = apr_pstrdup(ptmp, param + 4);
    apr_size_t len = strlen(var);
    if (len > 0) {
      var[len-1] = 0;
    }
    val = store_get(worker->vars, var);
    if (!val) {
      val = store_get(worker->locals, var);
    }
    if (!val) {
      val = param;
    }
  }
  else {
    val = param;
  }
  return val;
}

/**
 * CALL command calls a defined block
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN name of calling block 
 *
 * @return block status or APR_EINVAL 
 */
apr_status_t command_CALL(command_t *self, worker_t *worker, char *data, 
                          apr_pool_t *ptmp) {
  apr_status_t status;
  char *copy;
  const char *block_name;
  char *last;
  worker_t *block, *call;
  apr_table_t *lines = NULL;
  int cmd;
  apr_pool_t *call_pool;
  char *module;
  apr_hash_t *blocks;
  store_t *params;
  store_t *retvars;
  store_t *locals;

  /** a pool for this call */
  HT_POOL_CREATE(&call_pool);

  /** temporary tables for param, local vars and return vars */
  params = store_make(call_pool);
  retvars = store_make(call_pool);
  locals = store_make(call_pool);

  while (*data == ' ') ++data; 
  copy = apr_pstrdup(call_pool, data);
  copy = worker_replace_vars(worker, copy, NULL, call_pool); 
  worker_log(worker, LOG_CMD, "%s", copy); 

  /** get args from copy */
  my_get_args(copy, params, call_pool);
  block_name = store_get(params, "0");
  module = apr_pstrdup(call_pool, block_name);

  /** get module worker */
  if ((last = strchr(block_name, ':'))) {
    module = apr_strtok(module, ":", &last);
    if (*module == '_') {
      module++;
      block_name = apr_pstrcat(call_pool, "_", last, NULL);
    }
    else {
      block_name = apr_pstrdup(call_pool, last);
    }
    if (!(blocks = apr_hash_get(worker->modules, module, APR_HASH_KEY_STRING))) {
      worker_log(worker, LOG_ERR, "Could not find module \"%s\"", module);
      return APR_EINVAL;
    }
  }
  else {
    blocks = worker->blocks;
  }

  /** get block from module */
  /* CR BEGIN */
  apr_thread_mutex_lock(worker->mutex);
  if (!(block = apr_hash_get(blocks, block_name, APR_HASH_KEY_STRING))) {
    worker_log(worker, LOG_ERR, "Could not find block %s", block_name);
    /* CR END */
    apr_thread_mutex_unlock(worker->mutex);
    status = APR_ENOENT;
    goto error;
  }
  else { 
    int log_mode; 
    int i;
    int j;
    char *index;
    const char *arg;
    const char *val;
    char *all = "";

    /** prepare call */
    /* iterate over indexed params and resolve VAR(foo) stuff*/
    for (i = 1; i < store_get_size(params); i++) {
      index = apr_itoa(ptmp, i);
      if ((val = store_get(params, index))) {
        val = worker_get_value_from_param(worker, val, ptmp);
        store_set(params, index, val);
      }
    }

    for (i = 1; i < store_get_size(params); i++) {
      index = apr_itoa(ptmp, i);
      if ((val = store_get(params, index))) {
        all = apr_pstrcat(ptmp, all, val, " ", NULL);
      }
    }

    /* handle parameters first */
    for (i = 1; i < store_get_size(block->params); i++) {
      index = apr_itoa(ptmp, i);
      if (!(arg = store_get(block->params, index))) {
        worker_log(worker, LOG_ERR, "Param missmatch for block \"%s\"", block->name);
        apr_thread_mutex_unlock(worker->mutex);
        status = APR_EGENERAL;
        goto error;
      }
      if (!(val = store_get(params, index))) {
        worker_log(worker, LOG_ERR, "Param missmatch for block \"%s\"", block->name);
        apr_thread_mutex_unlock(worker->mutex);
        status = APR_EGENERAL;
        goto error;
      }
      if (arg && val) {
        val = worker_get_value_from_param(worker, val, ptmp);
        store_set(params, arg, val);
      }
    }

    /* handle return variables second */
    j = i;
    for (i = 0; i < store_get_size(block->retvars); i++, j++) {
      index = apr_itoa(call_pool, j);
      if (!(arg = store_get(block->retvars, index))) {
        worker_log(worker, LOG_ERR, "Return variables missmatch for block \"%s\"", block->name);
        apr_thread_mutex_unlock(worker->mutex);
        status = APR_EGENERAL;
        goto error;
      }
      if (!(val = store_get(params, index))) {
        worker_log(worker, LOG_ERR, "Return variables missmatch for block \"%s\"", block->name);
        apr_thread_mutex_unlock(worker->mutex);
        status = APR_EGENERAL;
        goto error;
      }
      if (arg && val) {
        store_set(retvars, arg, val);
      }
    }

    if (block->lines) {
      lines = my_table_deep_copy(call_pool, block->lines);
    }
    else {
      lines = worker->lines; 
    }
    apr_thread_mutex_unlock(worker->mutex);
    /* CR END */

    call = apr_pcalloc(call_pool, sizeof(*call));
    memcpy(call, worker, sizeof(*call));
    call->block = block;
    call->params = params;
    call->retvars = retvars;
    call->locals = locals;
    call->lines = lines;
    log_mode = logger_get_mode(call->logger);
    if (log_mode == LOG_CMD) {
      logger_set_mode(call->logger, LOG_INFO);
    }
    status = block->interpret(call, worker, call_pool);

    /** get infos from call back to worker */
    logger_set_mode(call->logger, log_mode);
    cmd = worker->cmd;
    lines = worker->lines;
    params = worker->params;
    retvars = worker->retvars;
    locals = worker->locals;
    memcpy(worker, call, sizeof(*worker));
    store_merge(worker->vars, call->retvars); 
    worker->params = params;
    worker->retvars = retvars;
    worker->locals = locals;
    worker->lines = lines;
    worker->cmd = cmd;
    worker->block = NULL;

    goto error;
  }

error:
  /** all ends here */
  apr_pool_destroy(call_pool);
  return status;
}
 
/**
 * log formated wrapper
 * @param worker IN thread data object
 * @param mode IN log mode
 *                LOG_DEBUG for a lot of infos
 *                LOG_INFO for much infos
 *                LOG_ERR for only very few infos
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */
void worker_log(worker_t * worker, int mode, char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  logger_log_va(worker->logger, mode, worker_get_file_and_line(worker), fmt, va);
  va_end(va);
}

/**
 * log buffer wrapper
 * @param logger IN thread data object
 * @param mode IN log mode
 *                LOG_DEBUG for a lot of infos
 *                LOG_INFO for much infos
 *                LOG_ERR for only very few infos
 * @param dir IN <,>,+,=
 * @param buf IN buf to print (binary data allowed)
 * @param len IN buf len
 */
void worker_log_buf(worker_t * worker, int mode, char dir, const char *buf,
                    apr_size_t len) {
  if (buf == NULL) {
    len = 0;
  }
  logger_log_buf(worker->logger, mode, dir, buf, len);
}


/**
 * Read headers from transport
 * @param worker IN thread data object
 * @param sockreader IN reader
 * @return apr status
 */
static apr_status_t worker_get_headers(worker_t *worker, 
                                       sockreader_t *sockreader) {
  apr_status_t status;
  char *line;
  char *last;
  char *key = NULL;
  const char *val = "";
  recorder_t *recorder = worker_get_recorder(worker);

  /** get headers */
  while ((status = sockreader_read_line(sockreader, &line)) == APR_SUCCESS && 
         line[0] != 0) {
    if ((status = htt_run_read_header(worker, line)) != APR_SUCCESS) {
      return status;
    }
    if (recorder->on == RECORDER_RECORD && 
        recorder->flags & RECORDER_RECORD_HEADERS) {
      sockreader_push_line(recorder->sockreader, line);
    }
    worker_log_buf(worker, LOG_INFO, '<', line, strlen(line));
    worker_match(worker, worker->match.dot, line, strlen(line));
    worker_match(worker, worker->match.headers, line, strlen(line));
    worker_match(worker, worker->grep.dot, line, strlen(line));
    worker_match(worker, worker->grep.headers, line, strlen(line));
    worker_expect(worker, worker->expect.dot, line, strlen(line));
    worker_expect(worker, worker->expect.headers, line, strlen(line));

    /* headers */
    key = apr_strtok(line, ":", &last);
    val = last;
    while (*val == ' ') ++val;
    if (worker->headers_allow) {
      if (!apr_table_get(worker->headers_allow, key)) {
        worker_log(worker, LOG_ERR, "%s header not allowed", key);
        return APR_EGENERAL;
      }
    }
    if (worker->headers_filter) {
      if (!apr_table_get(worker->headers_filter, key)) {
                                apr_table_add(worker->headers, key, val);
      }
    }
    else {
      apr_table_add(worker->headers, key, val);
    }
  }
  if (status == APR_SUCCESS && line[0] == 0) {
    worker_log_buf(worker, LOG_INFO, '<', NULL, 0);
  }
  return status;
}

/**
 * Wait for data (same as command_recv)
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN <number> or variable name
 * @return an apr status
 */
apr_status_t command_WAIT(command_t * self, worker_t * worker,
                          char *data, apr_pool_t *ptmp) {
  char *copy;
  char *line;
  char *buf;
  apr_status_t status;
  sockreader_t *sockreader;
  char *var = NULL;
  const char *val = "";
  apr_size_t len;
  apr_ssize_t recv_len = -1;
  apr_size_t peeklen;

  recorder_t *recorder = worker_get_recorder(worker);
  buf = NULL;
  len = 0;

  COMMAND_OPTIONAL_ARG;

  if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
    goto out_err;
  }

  if (apr_isdigit(copy[0])) {
    recv_len = apr_atoi64(copy);
  }
  else {
    if (copy[0]) {
      var = copy;
      apr_collapse_spaces(var, var);
    }
    recv_len = -1;
  }

  if (recorder->on == RECORDER_PLAY) {
    worker->socket->sockreader = recorder->sockreader;
  }

  /**
   * Give modules a chance to setup stuff before _WAIT read from network
   */
  if ((status = htt_run_WAIT_begin(worker)) != APR_SUCCESS) {
    goto out_err;
  }

  if (worker->socket->sockreader == NULL) {
    peeklen = worker->socket->peeklen;
    worker->socket->peeklen = 0;
    if ((status = sockreader_new(&worker->socket->sockreader, 
                                 worker->socket->transport,
				 worker->socket->peek, peeklen)) 
        != APR_SUCCESS) {
      goto out_err;
    }
  }
  sockreader = worker->socket->sockreader;

  /* bodies were read but not store */
  if (worker->flags & FLAGS_IGNORE_BODY) {
    sockreader_set_options(sockreader, SOCKREADER_OPTIONS_IGNORE_BODY);
  }
  else {
    sockreader_set_options(sockreader, SOCKREADER_OPTIONS_NONE);
  }

  if (worker->headers) {
    apr_table_clear(worker->headers);
  }
  else {
    worker->headers = apr_table_make(worker->pbody, 5);
  }
  
  if (worker->headers_add) {
    int i;
    apr_table_entry_t *e;

    e = (apr_table_entry_t *) apr_table_elts(worker->headers_add)->elts;
    for (i = 0; i < apr_table_elts(worker->headers_add)->nelts; ++i) {
      apr_table_add(worker->headers, e[i].key, e[i].val);
    }
    apr_table_clear(worker->headers_add);
  }

  /**
   * Give modules the possibility to expect/grep/match there own stuff
   */
  if ((status = htt_run_read_pre_headers(worker)) != APR_SUCCESS) {
    goto out_err;
  }

  /** Status line, make that a little fuzzy in reading trailing empty lines of last
   *  request */
  while ((status = sockreader_read_line(sockreader, &line)) == APR_SUCCESS && 
      line[0] == 0);
  if (line[0] != 0) { 
    if ((status = htt_run_read_status_line(worker, line)) != APR_SUCCESS) {
      goto out_err;
    }
    if (recorder->on == RECORDER_RECORD &&
	recorder->flags & RECORDER_RECORD_STATUS) {
      sockreader_push_line(recorder->sockreader, line);
    }
    worker_log_buf(worker, LOG_INFO, '<', line, strlen(line));
    worker_match(worker, worker->match.dot, line, strlen(line));
    worker_match(worker, worker->match.headers, line, strlen(line));
    worker_match(worker, worker->grep.dot, line, strlen(line));
    worker_match(worker, worker->grep.headers, line, strlen(line));
    worker_expect(worker, worker->expect.dot, line, strlen(line));
    worker_expect(worker, worker->expect.headers, line, strlen(line));

    if (!strstr(line, "HTTP/") && !strstr(line, "ICAP/")) {
      worker_log(worker, LOG_DEBUG, "Not HTTP or ICAP version in \"%s\", must be HTTP/0.9", line); 
      apr_table_add(worker->headers, "Connection", "close");
      status = sockreader_push_line(sockreader, line);
      goto http_0_9;
    }
  }
  else {
    worker_log_buf(worker, LOG_INFO, '<', line, strlen(line));
    worker_log(worker, LOG_ERR, "No status line received");
    status = APR_EINVAL;
    goto out_err;
  }
 
  status = worker_get_headers(worker, sockreader);

http_0_9:
  if (status == APR_SUCCESS) {
    int doreadtrailing = 0;
    /* if recv len is specified use this */
    if (recv_len > 0) {
      len = recv_len;
      if ((status = worker_check_error(worker, content_length_reader(sockreader, &buf, &len, val))) 
          != APR_SUCCESS) {
        goto out_err;
      }
    }
    else if (recv_len == 0) {
      buf = NULL; 
    }
    /* else get transfer type */
    else if ((val = apr_table_get(worker->headers, "Content-Length"))) {
      len = apr_atoi64(val);
      if ((status = worker_check_error(worker, content_length_reader(sockreader, &buf, &len, val))) 
          != APR_SUCCESS) {
        goto out_err;
      }
    }
    else if ((val = apr_table_get(worker->headers, "Transfer-Encoding"))) {
      if ((status = transfer_enc_reader(sockreader, &buf, &len, val)) == APR_SUCCESS) {
        if (strcmp(val, "chunked") == 0) {
          doreadtrailing = 1;
        }
      }
      else if ((status = worker_check_error(worker, status)) != APR_SUCCESS) {
        goto out_err;
      }
    }
    else if ((val = apr_table_get(worker->headers, "Encapsulated"))) {
      if ((status = worker_check_error(worker, encapsulated_reader(sockreader, &buf, &len, val, apr_table_get(worker->headers, "Preview"))))
          != APR_SUCCESS) {
        goto out_err;
      }
    }
    else if (worker->flags & FLAGS_CLIENT && 
	     (val = apr_table_get(worker->headers, "Connection"))) {
      if ((status = worker_check_error(worker, eof_reader(sockreader, &buf, &len, val))) 
          != APR_SUCCESS) {
        goto out_err;
      }
    }
    if ((status = htt_run_read_buf(worker, buf, len)) != APR_SUCCESS) {
      goto out_err;
    }
    if ((status = worker_handle_buf(worker, ptmp, buf, len)) != APR_SUCCESS) {
      goto out_err;
    }
    if (recorder->on == RECORDER_RECORD && 
        recorder->flags & RECORDER_RECORD_BODY) {
      sockreader_push_line(recorder->sockreader, "");
      sockreader_push_back(recorder->sockreader, buf, len);
    }
    if (var) {
      worker_var_set_and_zero_terminate(worker, var, buf, len);
    }
    if (doreadtrailing) {
      /* read trailing headers */
      if ((status = worker_get_headers(worker, sockreader)) != APR_SUCCESS) {
        worker_log(worker, LOG_ERR, "Missing trailing empty header(s) after chunked encoded body");
      }
    }

    if (worker->flags & FLAGS_AUTO_CLOSE) {
      val = apr_table_get(worker->headers, "Connection");
      if (val && strcasecmp(val, "close") == 0) {
        command_CLOSE(self, worker, "do not test expects", ptmp);
      }
    }
    if (worker->flags & FLAGS_AUTO_COOKIE) {
      /* get all set cookie and store them in cookie line */
      worker_set_cookie(worker);
    }
  }

out_err:
  if (recorder->on == RECORDER_PLAY) {
    sockreader_destroy(&recorder->sockreader);
    recorder->on = RECORDER_OFF;
    worker->socket->sockreader = NULL;
  }
  else {
    ++worker->req_cnt;
  }
  status = worker_assert(worker, status);

  /**
   * Give modules a chance to cleanup stuff after _WAIT
   */
  htt_run_WAIT_end(worker, status);
  return status;
}

/**
 * Bind to socket and wait for data (same as command_RES and command_WAIT).
 * Ignores TCP connections not sending any data (open/close).
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN not used
 *
 * @return an apr status
 */
apr_status_t command_RESWAIT(command_t * self, worker_t * worker, char * data,
                             apr_pool_t *ptmp) {
  apr_status_t status;
  do {
    status = command_RES(self, worker, "", ptmp);
    if(status != APR_SUCCESS) {
      return status;
    }
    status = command_WAIT(self, worker, "", ptmp);
    if(status == APR_EOF) {
      /* EOF = client failed to send data */
      command_CLOSE(self, worker, "do not test expects", ptmp);
    }
  } while(status == APR_EOF);
  return status;
}

/****
 * Scriptable commands 
 ****/

/**
 * Get socket from hash or add a new one
 *
 * @param self IN thread data object
 * @param hostname IN host name
 * @param portname IN port as ascii string
 *
 */
void worker_get_socket(worker_t *self, const char *hostname, 
                       const char *portname) {
  socket_t *socket;
  char *tag;
  apr_pool_t *pool;

  HT_POOL_CREATE(&pool);
  socket = 
    apr_hash_get(self->sockets, apr_pstrcat(self->pbody, hostname, portname, 
	                                    NULL),
	         APR_HASH_KEY_STRING);

  if (!socket) {
    socket = apr_pcalloc(self->pbody, sizeof(*socket));
    socket->config = apr_hash_make(self->pbody);
    socket->socket_state = SOCKET_CLOSED;
    tag = apr_pstrdup(self->pbody, portname);
    apr_hash_set(self->sockets, apr_pstrcat(self->pbody, hostname, tag,
	                                    NULL),
	         APR_HASH_KEY_STRING, socket);
  }

  self->socket = socket;
  apr_pool_destroy(pool);
}

/**
 * Setup a connection to host
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN aditional data
 *
 * @return an apr status
 */
apr_status_t command_REQ(command_t * self, worker_t * worker,
                         char *data, apr_pool_t *ptmp) {
  apr_status_t status;
  char *portname;
  char *hostname;
  char *last;
  char *copy;

  COMMAND_NEED_ARG("Need hostname and port");

  if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
    return status;
  }

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    return status;
  }

  hostname = apr_strtok(copy, " ", &last);
  portname = apr_strtok(NULL, " ", &last);

  /* use hostname and portname for unique id of sockets, portname may also have 
   * additional tags and infos which are possible resolved in the following
   * hook
   */
  worker_log(worker, LOG_DEBUG, "get socket \"%s:%s\"", hostname, portname);
  worker_get_socket(worker, hostname, portname);

  if ((status = htt_run_client_port_args(worker, portname, &portname, last)) != APR_SUCCESS) {
    return status;
  }

  if (worker->socket->socket_state == SOCKET_CLOSED) {
    if ((status = htt_run_pre_connect(worker)) != APR_SUCCESS) {
      return status;
    }
    if ((status = tcp_connect(worker, hostname, portname)) != APR_SUCCESS) {
      return status;
    }
    if ((status = htt_run_connect(worker)) != APR_SUCCESS) {
      return status;
    }
    if ((status = htt_run_post_connect(worker)) != APR_SUCCESS) {
      return status;
    }
    worker->socket->socket_state = SOCKET_CONNECTED;
  }

  worker_test_reset(worker);

  return APR_SUCCESS;
}

/**
 * Setup a connection to host
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN unused 
 *
 * @return an apr status
 */
apr_status_t command_RES(command_t * self, worker_t * worker,
                         char *data, apr_pool_t *ptmp) {
  apr_status_t status;
  char *copy;
  int ignore_monitors = 0;
  char *cur;
  char *last;
  char *reasemble = NULL;

  COMMAND_OPTIONAL_ARG;

  if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
    return status;
  }

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    return status;
  }

  worker_get_socket(worker, "Default", "0");
 
  cur = apr_strtok(copy, " ", &last);
  while (cur) {
    if (strcmp("IGNORE_MONITORS", cur) == 0) {
      ignore_monitors = 1;
    }
    else {
      reasemble = apr_pstrcat(ptmp, (reasemble ? reasemble : ""), (reasemble ? " " : ""), cur, NULL); 
    }
    cur = apr_strtok(NULL, " ", &last);
  }
  if (!reasemble) {
    reasemble = apr_pstrdup(ptmp, "");
  }

  while (worker->socket->socket_state == SOCKET_CLOSED) {
    int interim;

    if ((status = tcp_accept(worker)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Accept TCP connection aborted");
      return status;
    }
    
    interim = htt_run_accept(worker, reasemble);

    if (ignore_monitors) {
      if (interim == APR_SUCCESS) {
        worker->socket->peeklen = 1;
        status = transport_read(worker->socket->transport, worker->socket->peek, &worker->socket->peeklen);
        if (status != APR_SUCCESS && status != APR_EOF) {
          worker_log(worker, LOG_ERR, "Peek abort");
          return status;
        }
        else if (status == APR_SUCCESS) {
          worker->socket->socket_state = SOCKET_CONNECTED;
        }
      }
      else {
        worker_conn_close(worker, NULL);
      }
    }
    else if (interim == APR_SUCCESS) {
      worker->socket->socket_state = SOCKET_CONNECTED;
    }
    else {
      return interim;
    }
  }

  worker_test_reset(worker);

  return APR_SUCCESS;
}

/**
 * Close socket
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return an apr status
 */
apr_status_t command_CLOSE(command_t * self, worker_t * worker,
                           char *data, apr_pool_t *ptmp) {
  apr_status_t status;
  char *copy;

  COMMAND_OPTIONAL_ARG;

  if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
    worker_conn_close(worker, NULL);
    return status;
  }

  if (strcmp(copy, "do not test expects") != 0) {
    if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
      worker_conn_close(worker, NULL);
      return status;
    }
  }
  else {
    /* do not test expects and remove this string */
    copy = NULL;
  }

  if ((status = worker_conn_close(worker, copy)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * Specify a timeout for socket operations (ms) 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN time in ms 
 *
 * @return an apr status
 */
apr_status_t command_TIMEOUT(command_t * self, worker_t * worker,
                             char *data, apr_pool_t *ptmp) {
  apr_time_t tmo;
  char *copy;

  COMMAND_NEED_ARG("Time not specified");

  tmo = apr_atoi64(copy);
  worker->socktmo = tmo * 1000;

  return APR_SUCCESS;
}

/**
 * Define an expect
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN "%s %s" type match 
 *
 * @return an apr status
 */
apr_status_t command_EXPECT(command_t * self, worker_t * worker,
                            char *data, apr_pool_t *ptmp) {
  char *last;
  char *type;
  char *match;
  htt_regex_t *compiled;
  const char *err;
  int off;
  char *copy;
  char *interm;
  apr_pool_t *pool;

  COMMAND_NEED_ARG("Type and htt_regex not specified");

  type = apr_strtok(copy, " ", &last);
  
  interm = my_unescape(last, &last);

  if (last) {
    while (*last == ' ') ++last;
    if (*last != 0) {
      worker_log(worker, LOG_ERR, "there is more stuff behind last quote");
      return APR_EGENERAL;
    }
  }

  if (!type) {
    worker_log(worker, LOG_ERR, "Type not specified");
    return APR_EGENERAL;
  }
  
  pool = module_get_config(worker->config, apr_pstrcat(ptmp, "EXPECT ", type, NULL));
  if (!pool) {
    /* create a pool for match */
    HT_POOL_CREATE(&pool);
    module_set_config(worker->config, apr_pstrcat(pool, "EXPECT ", type, NULL), pool);
  }
  match = apr_pstrdup(pool, interm);

  if (!match) {
    worker_log(worker, LOG_ERR, "Regex not specified");
    return APR_EGENERAL;
  }

  if (interm[0] == '!') {
    ++interm;
  }
  
  if (!(compiled = htt_regexcomp(pool, interm, &err, &off))) {
    worker_log(worker, LOG_ERR, "EXPECT regcomp failed: \"%s\"", last);
    return APR_EINVAL;
  }

  if (strcmp(type, ".") == 0) {
    apr_table_addn(worker->expect.dot, match, (char *) compiled);
  }
  else if (strcasecmp(type, "Headers") == 0) {
    apr_table_addn(worker->expect.headers, match, (char *) compiled);
  }
  else if (strcasecmp(type, "Body") == 0) {
    apr_table_addn(worker->expect.body, match, (char *) compiled);
  }
  else if (strcasecmp(type, "Exec") == 0) {
    apr_table_addn(worker->expect.exec, match, (char *) compiled);
  }
  else if (strcasecmp(type, "Error") == 0) {
    apr_table_addn(worker->expect.error, match, (char *) compiled);
  }
  else if (strncasecmp(type, "Var(", 4) == 0) {
    const char *val;
    char *var;
    
    var= apr_strtok(type, "(", &last);
    var = apr_strtok(NULL, ")", &last);
    val = worker_var_get(worker, var);
    if (val) {
      apr_table_t *tmp_table;
      tmp_table = apr_table_make(ptmp, 1);
      apr_table_addn(tmp_table, match, (char *) compiled);
      worker_expect(worker, tmp_table, val, strlen(val));
      return worker_assert_expect(worker, tmp_table, "EXPECT var", 
	                          APR_SUCCESS);
    }
    else {
      worker_log(worker, LOG_ERR, "Variable \"%s\" does not exist", var);
      return APR_EINVAL;
    }
  }
  else {
    worker_log(worker, LOG_ERR, "EXPECT type \"%s\" unknown", type);
    return APR_EINVAL;
  }

  return APR_SUCCESS;
}

/**
 * Define an expect
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN "%s %s %s" type match variable
 *
 * @return an apr status
 */
apr_status_t command_MATCH(command_t * self, worker_t * worker,
                           char *data, apr_pool_t *ptmp) {
  char *tmp;
  char *last;
  char *type;
  char *match;
  char *vars;
  htt_regex_t *compiled;
  const char *err;
  int off;
  char *copy;
  apr_pool_t *pool;

  COMMAND_NEED_ARG("Type, htt_regex and variable not specified");

  type = apr_strtok(copy, " ", &last);
  
  match = my_unescape(last, &last);
  
  tmp = apr_strtok(NULL, "", &last);

  if (!type) {
    worker_log(worker, LOG_ERR, "Type not specified");
    return APR_EGENERAL;
  }
  
  pool = module_get_config(worker->config, apr_pstrcat(ptmp, "MATCH ", type, NULL));
  if (!pool) {
    /* create a pool for match */
    HT_POOL_CREATE(&pool);
    module_set_config(worker->config, apr_pstrcat(pool, "MATCH ", type, NULL), pool);
  }
  vars = apr_pstrdup(pool, tmp);

  if (!match) {
    worker_log(worker, LOG_ERR, "Regex not specified");
    return APR_EGENERAL;
  }

  if (!vars) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }

  if (vars) {
    ++vars;
  }

  if (!vars) {
    return APR_EINVAL;
  }

  if (!(compiled = htt_regexcomp(pool, match, &err, &off))) {
    worker_log(worker, LOG_ERR, "MATCH regcomp failed: %s", last);
    return APR_EINVAL;
  }
  if (strcmp(type, ".") == 0) {
    apr_table_addn(worker->match.dot, vars, (char *) compiled);
  }
  else if (strcasecmp(type, "Headers") == 0) {
    apr_table_addn(worker->match.headers, vars, (char *) compiled);
  }
  else if (strcasecmp(type, "Body") == 0) {
    apr_table_addn(worker->match.body, vars, (char *) compiled);
  }
  else if (strcasecmp(type, "Error") == 0) {
    apr_table_addn(worker->match.error, vars, (char *) compiled);
  }
  else if (strcasecmp(type, "Exec") == 0) {
    apr_table_addn(worker->match.exec, vars, (char *) compiled);
  }
  else if (strncasecmp(type, "Var(", 4) == 0) {
    const char *val;
    char *var;
    
    var= apr_strtok(type, "(", &last);
    var = apr_strtok(NULL, ")", &last);
    val = worker_var_get(worker, var);
    if (val) {
      apr_table_t *tmp_table;
      tmp_table = apr_table_make(ptmp, 1);
      apr_table_addn(tmp_table, vars, (char *) compiled);
      worker_match(worker, tmp_table, val, strlen(val));
      return worker_assert_match(worker, tmp_table, "MATCH var", 
	                         APR_SUCCESS);
    }
    else {
      /* this should cause an error? */
    }
  }
  else {
    worker_log(worker, LOG_ERR, "Match type %s does not exist", type);
    return APR_ENOENT;
  }

  return APR_SUCCESS;
}

/**
 * Define an grep 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN "%s %s %s" type grep variable
 *
 * @return an apr status
 */
apr_status_t command_GREP(command_t * self, worker_t * worker,
                          char *data, apr_pool_t *ptmp) {
  char *tmp;
  char *last;
  char *type;
  char *grep;
  char *vars;
  htt_regex_t *compiled;
  const char *err;
  int off;
  char *copy;
  apr_pool_t *pool;

  COMMAND_NEED_ARG("Type, htt_regex and variable not specified");

  type = apr_strtok(copy, " ", &last);
  
  grep = my_unescape(last, &last);
  
  tmp = apr_strtok(NULL, "", &last);

  if (!type) {
    worker_log(worker, LOG_ERR, "Type not specified");
    return APR_EGENERAL;
  }

  pool = module_get_config(worker->config, apr_pstrcat(ptmp, "GREP ", type, NULL));
  if (!pool) {
    /* create a pool for match */
    HT_POOL_CREATE(&pool);
    module_set_config(worker->config, apr_pstrcat(pool, "GREP ", type, NULL), pool);
  }
  vars = apr_pstrdup(pool, tmp);

  if (!grep) {
    worker_log(worker, LOG_ERR, "Regex not specified");
    return APR_EGENERAL;
  }

  if (!vars) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }

  if (vars) {
    ++vars;
  }

  if (!vars) {
    return APR_EINVAL;
  }

  if (!(compiled = htt_regexcomp(pool, grep, &err, &off))) {
    worker_log(worker, LOG_ERR, "MATCH regcomp failed: %s", last);
    return APR_EINVAL;
  }
  if (strcmp(type, ".") == 0) {
    apr_table_addn(worker->grep.dot, vars, (char *) compiled);
  }
  else if (strcasecmp(type, "Headers") == 0) {
    apr_table_addn(worker->grep.headers, vars, (char *) compiled);
  }
  else if (strcasecmp(type, "Body") == 0) {
    apr_table_addn(worker->grep.body, vars, (char *) compiled);
  }
  else if (strcasecmp(type, "Error") == 0) {
    apr_table_addn(worker->grep.error, vars, (char *) compiled);
  }
  else if (strcasecmp(type, "Exec") == 0) {
    apr_table_addn(worker->grep.exec, vars, (char *) compiled);
  }
  else if (strncasecmp(type, "Var(", 4) == 0) {
    const char *val;
    char *var;
    
    var= apr_strtok(type, "(", &last);
    var = apr_strtok(NULL, ")", &last);
    val = worker_var_get(worker, var);
    if (val) {
      apr_table_t *tmp_table;
      tmp_table = apr_table_make(ptmp, 1);
      apr_table_addn(tmp_table, vars, (char *) compiled);
      worker_match(worker, tmp_table, val, strlen(val));
    }
    else {
      /* this should cause an error? */
    }
  }
  else {
    worker_log(worker, LOG_ERR, "Grep type %s does not exist", type);
    return APR_ENOENT;
  }

  return APR_SUCCESS;
}

/**
 * assert command
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN expression
 *
 * @return an apr status
 */
apr_status_t command_ASSERT(command_t * self, worker_t * worker,
                            char *data, apr_pool_t *ptmp) {
  apr_status_t status;
  char *copy;
  char **argv;
  apr_size_t len;
  long val;
  math_eval_t *math = math_eval_make(ptmp);

  COMMAND_NEED_ARG("expression"); 

  my_tokenize_to_argv(copy, &argv, ptmp, 0);

  if (!argv[0]) {
    worker_log(worker, LOG_ERR, "Need an expression"); 
    return APR_EINVAL;
  }

  len = strlen(argv[0]);
  if (len < 1) {
    worker_log(worker, LOG_ERR, "Empty expression");
    return APR_EINVAL;
  }

  if (strcmp(argv[0], "_STRING_EQUAL") == 0) {
    if (argv[1] == 0) {
      worker_log(worker, LOG_ERR, "Need two strings, got none");
      return APR_EINVAL;
    }
    else if (argv[2] == 0) {
      worker_log(worker, LOG_ERR, "Need two strings, got one");
      return APR_EINVAL;
    }
    else if (strcmp(argv[1], argv[2]) != 0) {
      worker_log(worker, LOG_ERR, "Strings not equal");
      return APR_EINVAL;
    }
    val = 1;
  }
  else {
    if ((status = math_evaluate(math, argv[0], &val)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Invalid expression");
      return status;
    }
  }

  if (!val) {
    worker_log(worker, LOG_ERR, "Did expect \"%s\"", argv[0]);
    return APR_EINVAL;
  }

  return APR_SUCCESS;
}

/**
 * Single line variable
 * @param copy IN copy of variable=value
 * @param value OUT value
 * @return variable
 */
static const char *single_line_variable(worker_t *worker, char *copy, 
                                        char **value) {
  return apr_strtok(copy, "=", value);
}

/**
 * Single line variable
 * @param copy IN copy variable=value
 * @param value OUT value
 * @param ptmp IN temp pool
 * @return variable
 */
static const char *multi_line_variable(worker_t *worker, char *copy, 
                                       char **value, apr_pool_t *ptmp) {
  char *delimiter;
  char *var;
  char *val;
  apr_table_entry_t *e ;
  int to;
  int delim_found = 0;
  int store_cmd = worker->cmd;

  var = apr_strtok(copy, "<", &delimiter);
  apr_collapse_spaces(delimiter, delimiter);

  /* read line until delimiter, delimiter can be indented! */
  e = (apr_table_entry_t *) apr_table_elts(worker->lines)->elts;

  to = worker->cmd_to ? worker->cmd_to : apr_table_elts(worker->lines)->nelts;

  val = NULL;
  for (worker->cmd = worker->cmd_from + 1; worker->cmd < to; worker->cmd++) {
    int i;
    char *line = e[worker->cmd].val;
    for (i = 0; line[i] == ' '; i++);
    if (strcmp(delimiter, &line[i]) == 0) {
      delim_found = 1;
      break;
    }
    else {
      val = val ? apr_pstrcat(ptmp, val, "\n", line, NULL) : apr_pstrdup(ptmp, line);
    }
  }

  if (!delim_found) {
    int old_cmd = worker->cmd;
    worker->cmd = store_cmd;
    worker_log(worker, LOG_ERR, 
               "No ending delimiter \"%s\" found for multiline variable",
               delimiter);
    return NULL;
    worker->cmd = old_cmd;
  }

  if (val == NULL) {
    val = apr_pstrdup(ptmp, "");
  }

  *value = val;

  return var;
}

/**
 * set command
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN key=value 
 *
 * @return an apr status
 */
apr_status_t command_SET(command_t * self, worker_t * worker, char *data, 
                         apr_pool_t *ptmp) {
  const char *vars_key;
  char *vars_val;
  char *copy;
  int i;

  COMMAND_NEED_ARG("Variable and value not specified");
  
  for (i = 0; copy[i] != 0 && strchr(VAR_ALLOWED_CHARS, copy[i]); i++); 

  if (copy[i] == '=') {
    /* single line */
    vars_key = single_line_variable(worker, copy, &vars_val);
  }
  else if (copy[i] == '<') {
    /* multi line */
    vars_key = multi_line_variable(worker, copy, &vars_val, ptmp);
  }
  else {
    vars_key = apr_strtok(copy, "=<", &vars_val);
    worker_log(worker, LOG_ERR, "Char '%c' is not allowed in variable \"%s\"", copy[i], vars_key);
  }

  if (!vars_key) {
    worker_log(worker, LOG_ERR, "Key not specified");
    return APR_EGENERAL;
  }

  if (!vars_val) {
    worker_log(worker, LOG_ERR, "Value not specified");
    return APR_EGENERAL;
  }
  
  vars_val = worker_replace_vars(worker, vars_val, NULL, ptmp); \
  worker_var_set(worker, vars_key, vars_val);

  return APR_SUCCESS;
}

/**
 * unset command
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN key 
 *
 * @return an apr status
 */
apr_status_t command_UNSET(command_t * self, worker_t * worker,
                           char *data, apr_pool_t *ptmp) {
  const char *var;
  char *copy;
  int i;

  COMMAND_NEED_ARG("Variable and value not specified");
  
  var = copy;
  for (i = 0; var[i] != 0 && strchr(VAR_ALLOWED_CHARS, var[i]); i++); 
  if (var[i] != 0) {
    worker_log(worker, LOG_ERR, "Char '%c' is not allowed in \"%s\"", var[i], var);
    return APR_EINVAL;
  }

  if (store_get(worker->locals, var)) {
    store_unset(worker->locals, var);
  }
  else {
    store_unset(worker->vars, var);
  }

  return APR_SUCCESS;
}

/**
 * Send data 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN data to send
 *
 * @return an apr status
 */
apr_status_t command_DATA(command_t * self, worker_t * worker,
                          char *data, apr_pool_t *ptmp) {
  char *copy;
  int unresolved;

  if (!worker->socket) {
    return APR_ENOSOCKET;
  }
    
  copy = apr_pstrdup(ptmp, data); 
  copy = worker_replace_vars(worker, copy, &unresolved, ptmp);
  worker_log(worker, LOG_CMD, "%s%s", self->name, copy); 


  if (strncasecmp(copy, "Content-Length: AUTO", 20) == 0) {
    apr_table_add(worker->cache, "Content-Length", "Content-Length");
  }
  else if (strncasecmp(copy, "Encapsulated: ", 14) == 0 && strstr(copy, "AUTO")) {
    apr_table_add(worker->cache, "Encapsulated", copy);
  }
  else if (strncasecmp(copy, "Cookie: AUTO", 12) == 0) {
    apr_table_add(worker->cache, "Cookie", "Cookie");
  }
  else if (strncasecmp(copy, "Expect: 100-Continue", 20) == 0) {
    apr_table_add(worker->cache, "100-Continue", copy);
  }
  else {
    if (unresolved) {
      apr_table_add(worker->cache, "PLAIN;resolve", copy);
    }
    else {
      apr_table_add(worker->cache, "PLAIN", copy);
    }
  }

  return APR_SUCCESS;
}

/**
 * Flush data 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return an apr status
 */
apr_status_t command_FLUSH(command_t * self, worker_t * worker,
                           char *data, apr_pool_t *ptmp) {
  apr_status_t status;

  COMMAND_NO_ARG;

  if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * Chunk info 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return an apr status
 */
apr_status_t command_CHUNK(command_t * self, worker_t * worker,
                           char *data, apr_pool_t *ptmp) {
  apr_status_t status;

  COMMAND_NO_ARG;

  apr_table_add(worker->cache, "CHUNKED", "CHUNKED");

  if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * read from file descriptor and write it to the HTTP stream
 * 
 * @param worker IN thread data object
 * @param file IN open file descriptor for reading
 * @param flags IN FLAGS_CHUNKED or FLAGS_NONE
 *
 * @return APR_SUCCESS or an apr error status
 */
apr_status_t worker_file_to_http(worker_t *worker, apr_file_t *file, int flags, apr_pool_t *ptmp) {
  apr_status_t status;
  apr_size_t len;
  char *buf;

  while (1) {
    if (flags & FLAGS_CHUNKED) {
      len = worker->chunksize;
    }
    else {
      len = BLOCK_MAX;
    }
    buf = apr_pcalloc(worker->pcache, len + 1);
    if ((status = apr_file_read(file, buf, &len)) != APR_SUCCESS) {
      break;
    }
    buf[len] = 0;
    apr_table_addn(worker->cache, 
		   apr_psprintf(worker->pcache, "NOCRLF:%"APR_SIZE_T_FMT, len), buf);
    if (flags & FLAGS_CHUNKED) {
      worker_log(worker, LOG_DEBUG, "--- chunk size: %"APR_SIZE_T_FMT, len);
      apr_table_add(worker->cache, "CHUNKED", "CHUNKED");
      if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
	return status;
      }
    }
  }

  if (APR_STATUS_IS_EOF(status)) {
    return APR_SUCCESS;
  }
  else {
    return status;
  }
}

/**
 * Report error of a child if any
 *
 * @param pool IN 
 * @param err IN
 * @param description IN error description
 */
static void child_errfn(apr_pool_t *pool, apr_status_t err, 
                        const char *description) { 
  fprintf(stderr, "\nChild error occure: %s", description);
  fflush(stderr);
}

/**
 * Execute an external program 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN external program call with arguments 
 *
 * @return an apr status
 */
apr_status_t command_EXEC(command_t * self, worker_t * worker,
                          char *data, apr_pool_t *ptmp) {
  char *copy;
  apr_status_t status;
  apr_procattr_t *attr;
  bufreader_t *br;
  const char *progname;
  const char * const*args;
  apr_exit_why_e exitwhy;
  int exitcode;
  int flags;

  COMMAND_NEED_ARG("Need a shell command");

  flags = worker->flags;
  worker->flags &= ~FLAGS_PIPE;
  worker->flags &= ~FLAGS_CHUNKED;
  worker->flags &= ~FLAGS_PIPE_IN;
  worker->flags &= ~FLAGS_FILTER;
  /* pipe http to shell */
  if (copy[0] == '|') {
    ++copy;
    worker->flags |= FLAGS_PIPE_IN;
  }
  /* filter http */
  else if (copy[0] == '<') {
    ++copy;
    worker->flags |= FLAGS_FILTER;
  }

  my_tokenize_to_argv(copy, (char ***)&args, ptmp, 1);
  progname = args[0];

  if (!progname) {
    worker_log(worker, LOG_ERR, "No program name specified");
    return APR_EGENERAL;
  }
  
  if ((status = apr_procattr_create(&attr, worker->pbody)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_procattr_cmdtype_set(attr, APR_SHELLCMD_ENV)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_procattr_detach_set(attr, 0)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_procattr_error_check_set(attr, 1)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_procattr_child_errfn_set(attr, child_errfn)) 
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_procattr_io_set(attr,  APR_FULL_BLOCK, APR_FULL_BLOCK,
				    APR_NO_PIPE))
      != APR_SUCCESS) {
    return status;
  }

  {
    apr_pool_t *pool;
    apr_proc_t *proc;

    HT_POOL_CREATE(&pool);
    proc = apr_pcalloc(pool, sizeof(*proc));
    if ((status = apr_proc_create(proc, progname, args, NULL, attr,
            worker->pbody)) != APR_SUCCESS) {
      goto exit;
    }

    if (flags & FLAGS_PIPE) {
      worker_log(worker, LOG_DEBUG, "write stdout to http: %s", progname);
      if ((status = worker_file_to_http(worker, proc->out, flags, ptmp)) 
          != APR_SUCCESS) {
        goto exit;
      }
    }
    else if (worker->flags & FLAGS_PIPE_IN || worker->flags & FLAGS_FILTER) {
      /* do not wait for proc termination here */
      exec_t *exec = apr_pcalloc(pool, sizeof(*exec));
      exec->pool = pool;
      exec->proc = proc;
      module_set_config(worker->config, apr_pstrdup(pool, "EXEC"), exec);
      return status;
    }
    else {
      apr_size_t len = 0;
      char *buf = NULL;

      worker_log(worker, LOG_DEBUG, "read stdin: %s", progname);
      status = bufreader_new(&br, proc->out, worker->pbody);
      if (status == APR_SUCCESS || APR_STATUS_IS_EOF(status)) {
        status = APR_SUCCESS;
        bufreader_read_eof(br, &buf, &len);
      }
      else {
        goto exit;
      }

      if (buf) {
        worker_log_buf(worker, LOG_INFO, '<', buf, len);
        worker_match(worker, worker->match.exec, buf, len);
        worker_match(worker, worker->grep.exec, buf, len);
        worker_expect(worker, worker->expect.exec, buf, len);
      }

      status = worker_assert_match(worker, worker->match.exec, "MATCH exec", 
          status);
      status = worker_assert_expect(worker, worker->expect.exec, "EXPECT exec", 
          status);
      status = worker_assert_grep(worker, worker->grep.exec, "GREP exec", 
          status);
    }

    worker_log(worker, LOG_DEBUG, "wait for: %s", progname);
    apr_proc_wait(proc, &exitcode, &exitwhy, APR_WAIT);

    apr_file_close(proc->in);
    apr_file_close(proc->out);

    if (exitcode != 0) {
      status = APR_EGENERAL;
    }

exit:
    apr_pool_destroy(pool);
    return status;
  }
}

/**
 * Send file
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN file
 *
 * @return an apr status
 */
apr_status_t command_SENDFILE(command_t * self, worker_t * worker,
                              char *data, apr_pool_t *ptmp) {
  char *copy;
  char **argv;
  apr_status_t status;
  int flags;
  apr_file_t *fp;
  int i;

  COMMAND_NEED_ARG("Need a file name");

  my_tokenize_to_argv(copy, &argv, ptmp, 0);

  flags = worker->flags;
  worker->flags &= ~FLAGS_PIPE;
  worker->flags &= ~FLAGS_CHUNKED;
  
  for (i = 0; argv[i]; i++) {
    if ((status =
         apr_file_open(&fp, argv[i], APR_READ, APR_OS_DEFAULT,
                       ptmp)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "\nCan not send file: File \"%s\" not found", copy);
      return APR_ENOENT;
    }
    
    if ((status = worker_file_to_http(worker, fp, flags, ptmp)) 
                                != APR_SUCCESS) {
      return status;
    }

    apr_file_close(fp);
  }

  return APR_SUCCESS;
}

/**
 * Declare a pipe
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN not used
 *
 * @return an apr status
 */
apr_status_t command_PIPE(command_t * self, worker_t * worker,
                          char *data, apr_pool_t *ptmp) {
  char *copy;
  char *last;
  char *add;
  char *val;

  COMMAND_OPTIONAL_ARG;

  add = apr_strtok(copy, " ", &last);
  if (add) {
    val = apr_strtok(NULL, " ", &last);
  }
  else {
    val = NULL;
  }
  
  worker_log(worker, LOG_DEBUG, "additional: %s, value: %s", add, val);
  
  if (add && strncasecmp(add, "chunked", 7) == 0) {
    worker->chunksize = val ? apr_atoi64(val) : BLOCK_MAX;
    worker->flags |= FLAGS_CHUNKED;
  }
  
  worker->flags |= FLAGS_PIPE;

  return APR_SUCCESS;
}

/**
 * Send data without a CRLF
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN data to send
 *
 * @return an apr status
 */
apr_status_t command_NOCRLF(command_t * self, worker_t * worker,
                            char *data, apr_pool_t *ptmp) {
  char *copy;
  int unresolved; 

  copy = apr_pstrdup(ptmp, data); 
  copy = worker_replace_vars(worker, copy, &unresolved, ptmp);
  worker_log(worker, LOG_CMD, "%s%s", self->name, copy); 

  if (unresolved) {
    apr_table_add(worker->cache, "NOCRLF;resolve", copy);
  }
  else {
    apr_table_add(worker->cache, "NOCRLF", copy);
  }

  return APR_SUCCESS;
}

/**
 * Send data without a CRLF
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN data to send
 *
 * @return an apr status
 */
apr_status_t command_SOCKSTATE(command_t * self, worker_t * worker,
                               char *data, apr_pool_t *ptmp) {
  char *copy;

  COMMAND_NEED_ARG("Need a variable name");

  if (!worker->socket) {
    worker_var_set(worker, copy, "UNDEF");
  }

  if (worker_sockstate(worker) == APR_SUCCESS) {
    worker_var_set(worker, copy, "CONNECTED");
  }
  else {
    worker_var_set(worker, copy, "CLOSED");
  }

  return APR_SUCCESS;
}

/**
 * HEADER command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN header name (spaces are possible) 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_HEADER(command_t *self, worker_t *worker, char *data, 
                            apr_pool_t *ptmp) {
  char *copy;
  char *method;
  char *header;
  char *last;

  COMMAND_NEED_ARG("Need method ALLOW or FILTER and a header name");

  method = apr_strtok(copy, " ", &last);
  header = apr_strtok(NULL, " ", &last);
  
  if (strcasecmp(method, "ALLOW") == 0) {
    if (!worker->headers_allow) {
      worker->headers_allow = apr_table_make(worker->pbody, 10);
    }
    apr_table_add(worker->headers_allow, header, method);
  }
  else if (strcasecmp(method, "FILTER") == 0) {
    if (!worker->headers_filter) {
      worker->headers_filter = apr_table_make(worker->pbody, 5);
    }
    apr_table_add(worker->headers_filter, header, method);
  }
  else {
    return APR_ENOTIMPL;
  }

  return APR_SUCCESS;
}

/**
 * DEBUG command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN string to print on stderr
 *
 * @return APR_SUCCESS
 */
apr_status_t command_DEBUG(command_t *self, worker_t *worker, char *data, 
                           apr_pool_t *ptmp) {
  char *copy;
  
  COMMAND_OPTIONAL_ARG;

  /* Using LOG_NONE so this prints, regardless of httest internal log level */
  worker_log(worker, LOG_NONE, "%s", copy);

  return APR_SUCCESS;
}

/**
 * Setup listener
 *
 * @param worker IN thread data object
 *
 * @return APR_SUCCESS
 */
apr_status_t worker_listener_up(worker_t *worker, apr_int32_t backlog) {
  apr_status_t status = APR_SUCCESS;

  worker_get_socket(worker, "Default", "0");

  status = tcp_listen(worker, backlog);

  worker->socket->socket_state = SOCKET_CLOSED;

  return status;
}

/**
 * UP command bind a listener socket
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
apr_status_t command_UP(command_t *self, worker_t *worker, char *data, 
                        apr_pool_t *ptmp) {
  char *copy;
  
  apr_int32_t backlog = LISTENBACKLOG_DEFAULT;

  COMMAND_OPTIONAL_ARG;

  if (copy[0] != '\0') {
    backlog = apr_atoi64(copy);
  }
  
  return worker_listener_up(worker, backlog);
}

/**
 * DOWN command shuts down listener
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
apr_status_t command_DOWN(command_t *self, worker_t *worker, char *data, 
                          apr_pool_t *ptmp) {
  apr_status_t status;

  COMMAND_NO_ARG;

  if (!worker->listener) {
    worker_log(worker, LOG_ERR, "Server allready down", self->name);
    return APR_EGENERAL;
  }
  
  if ((status = apr_socket_close(worker->listener)) != APR_SUCCESS) {
    return status;
  }
  worker->listener = NULL;
  return status;
}

/**
 * LOG_LEVEL command sets log level 
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN number 0-4 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_LOG_LEVEL_SET(command_t *self, worker_t *worker, char *data, 
                                   apr_pool_t *ptmp) {
  char *copy;

  COMMAND_NEED_ARG("Need a number between 0 and 4");

  logger_set_mode(worker->logger, apr_atoi64(copy));

  return APR_SUCCESS;
}

/**
 * GET_LOG_LEVEL command sets log level 
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN number 0-4 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_LOG_LEVEL_GET(command_t *self, worker_t *worker, char *data, 
                                   apr_pool_t *ptmp) {
  char *copy;

  COMMAND_NEED_ARG("<variable>");

  worker_var_set(worker, copy, apr_itoa(ptmp, logger_get_mode(worker->logger)));
  return APR_SUCCESS;
}

/**
 * RECV command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN either POLL or number of bytes
 *
 * @return APR_SUCCESS
 */
apr_status_t command_RECV(command_t *self, worker_t *worker, char *data, 
                          apr_pool_t *ptmp) {
  char *copy;
  apr_status_t status;
  apr_size_t recv_len;
  apr_size_t peeklen;
  sockreader_t *sockreader;
  char *last;
  char *val;

  char *buf = NULL;
  int poll = 0;

  COMMAND_NEED_ARG("Need a number or POLL");

  /* get first value, can be either POLL or a number */
  val = apr_strtok(copy, " ", &last);
  if (strcasecmp(val, "POLL") == 0) {
    poll = 1;
    /* recv_len to max and timeout to min */
    recv_len = BLOCK_MAX;
    /* set timout to specified socket tmo */
    if ((status = transport_set_timeout(worker->socket->transport, 
                                        worker->socktmo)) != APR_SUCCESS) {
      return status;
    }
  }
  else if (strcasecmp(val, "CHUNKED") == 0) {
    recv_len = 0;
  }
  else if (strcasecmp(val, "CLOSE") == 0) {
    recv_len = 0;
  }
  else {
    /* must be a number */
    recv_len = apr_atoi64(val);
  }

  if (worker->socket->sockreader == NULL) {
    peeklen = worker->socket->peeklen;
    worker->socket->peeklen = 0;
    if ((status = sockreader_new(&worker->socket->sockreader, 
                                 worker->socket->transport,
				 worker->socket->peek, peeklen)) 
        != APR_SUCCESS) {
      goto out_err;
    }
  }
  sockreader = worker->socket->sockreader;

  if (strcasecmp(val, "CHUNKED") == 0) {
    if ((status = transfer_enc_reader(sockreader, &buf, &recv_len, "chunked")) != APR_SUCCESS) {
      goto out_err;
    }
  }
  else if (strcasecmp(val, "CLOSE") == 0) {
    if ((status = eof_reader(sockreader, &buf, &recv_len, "close")) != APR_SUCCESS) {
      goto out_err;
    }
  }
  else {
    if ((status = content_length_reader(sockreader, &buf, &recv_len, "")) != APR_SUCCESS) {
      if (poll && APR_STATUS_IS_INCOMPLETE(status)) {
	status = APR_SUCCESS;
      }
      else {
	goto out_err;
      }
    }
  }

  if ((status = worker_handle_buf(worker, ptmp, buf, recv_len)) 
      != APR_SUCCESS) {
    goto out_err;
  }

out_err:
  if (strcasecmp(last, "DO_NOT_CHECK") != 0) {
    status = worker_assert(worker, status);
  }

  return status;
}

/**
 * READLINE command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN optional parameter DO_NOT_CHECK to avoid expect checking
 *
 * @return APR_SUCCESS
 */
apr_status_t command_READLINE(command_t *self, worker_t *worker, char *data, 
                              apr_pool_t *ptmp) {
  apr_status_t status;
  apr_size_t peeklen;
  apr_size_t len;
  sockreader_t *sockreader;
  char *copy;
  char *buf = NULL;

  COMMAND_OPTIONAL_ARG;

  if (worker->socket->sockreader == NULL) {
    peeklen = worker->socket->peeklen;
    worker->socket->peeklen = 0;
    if ((status = sockreader_new(&worker->socket->sockreader, 
                                 worker->socket->transport,
				 worker->socket->peek, peeklen)) 
        != APR_SUCCESS) {
      goto out_err;
    }
  }
  sockreader = worker->socket->sockreader;

  if ((status = sockreader_read_line(sockreader, &buf)) != APR_SUCCESS) {
    goto out_err;
  }

  if (buf) {
    len = strlen(buf);
    if ((status = worker_handle_buf(worker, ptmp, buf, len)) 
	!= APR_SUCCESS) {
      goto out_err;
    }
  }

out_err:
  if (strcasecmp(copy, "DO_NOT_CHECK") != 0) {
    status = worker_assert(worker, status);
  }

  return status;
}

/**
 * CHECK command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN optional check match and expects
 *
 * @return APR_SUCCESS
 */
apr_status_t command_CHECK(command_t *self, worker_t *worker, char *data, 
                           apr_pool_t *ptmp) {
  apr_status_t status = worker_assert(worker, APR_SUCCESS);
  return status;
}

/**
 * WHICH command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN varname
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_WHICH(command_t *self, worker_t *worker, char *data, 
                           apr_pool_t *ptmp) {
  char *copy;
  char *result;

  COMMAND_NEED_ARG("<variable> expected");
 
  result  = apr_psprintf(ptmp, "%d", worker->which);
  worker_var_set(worker, copy, result);
  
  return APR_SUCCESS;
}

/**
 * ONLY_PRINTABLE command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN on|off
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_ONLY_PRINTABLE(command_t *self, worker_t *worker, char *data, 
                                    apr_pool_t *ptmp) {
  char *copy;

  COMMAND_NEED_ARG("Need on|off");
 
  if (strcasecmp(copy, "on") == 0) {
    worker->flags |= FLAGS_ONLY_PRINTABLE;
  }
  else {
    worker->flags &= ~FLAGS_ONLY_PRINTABLE;
  }
  return APR_SUCCESS;
}

/**
 * PRINT_HEX command
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN on|off
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_PRINT_HEX(command_t *self, worker_t *worker, char *data, 
                               apr_pool_t *ptmp) {
  char *copy;

  COMMAND_NEED_ARG("Need on|off");
 
  if (strcasecmp(copy, "on") == 0) {
    worker->flags |= FLAGS_PRINT_HEX;
  }
  else {
    worker->flags &= ~FLAGS_PRINT_HEX;
  }
  return APR_SUCCESS;
}

/**
 * SH command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_SH(command_t *self, worker_t *worker, char *data, 
                        apr_pool_t *ptmp) {
  char *copy;
  apr_size_t len;

#ifdef _WINDOWS
  char *name = apr_pstrdup(worker->pbody, "httXXXXXX.bat");
  char *exec_prefix = "";
  int has_apr_file_perms_set = 0;
#else
  char *name = apr_pstrdup(worker->pbody, "httXXXXXX");
  char *exec_prefix = "./";
  int has_apr_file_perms_set = 1;
#endif
  sh_t *sh = module_get_config(worker->config, SH_CONFIG);

  apr_status_t status = APR_SUCCESS;
  
  COMMAND_NEED_ARG("Either shell commands or END");

  if (strcasecmp(copy, "END")== 0) {
    if (sh) {
      if ((status = apr_file_name_get((const char **)&name, sh->tmpf)) != APR_SUCCESS) {
        return status;
      }

      if (has_apr_file_perms_set && (status = apr_file_perms_set(name, 0x700)) != APR_SUCCESS) {
        return status;
      }

      /* close file */
      apr_file_close(sh->tmpf);

      /* exec file */
      status = command_EXEC(self, worker, apr_pstrcat(worker->pbody, exec_prefix, name, NULL), sh->pool);
      
      apr_file_remove(name, sh->pool);
      module_set_config(worker->config, apr_pstrdup(sh->pool, SH_CONFIG), NULL);
      apr_pool_destroy(sh->pool);
    }
  }
  else {
    if (!sh) {
      apr_pool_t *pool;
      HT_POOL_CREATE(&pool);
      sh = apr_pcalloc(pool, sizeof(*sh));
      sh->pool = pool;
      if ((status = apr_file_mktemp(&sh->tmpf, name, 
	                            APR_CREATE | APR_READ | APR_WRITE | 
				    APR_EXCL, pool))
	  != APR_SUCCESS) {
	worker_log(worker, LOG_ERR, "Could not mk temp file %s(%d)", 
	           my_status_str(ptmp, status), status);
	return status;
      }
    }
    module_set_config(worker->config, apr_pstrdup(sh->pool, SH_CONFIG), sh);
    
    len = strlen(copy);
    if ((status = file_write(sh->tmpf, copy, len)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not write to temp file");
      return status;
    }
    len = 1;
    if ((status = file_write(sh->tmpf, "\n", len)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not write to temp file");
      return status;
    }
  }

  return status;
}

/**
 * ADD_HEADER command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN header value
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_ADD_HEADER(command_t *self, worker_t *worker, char *data, 
                                apr_pool_t *ptmp) {
  char *copy;
  char **argv;

  COMMAND_NEED_ARG("<header> <value>");

  if (!worker->headers_add) {
    worker->headers_add = apr_table_make(worker->pbody, 12);
  }

  my_tokenize_to_argv(copy, &argv, ptmp, 0);
  apr_table_add(worker->headers_add, argv[0], argv[1]);

  return APR_SUCCESS;
}

/**
 * TUNNEL command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN <host> [SSL:]<port>
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t command_TUNNEL(command_t *self, worker_t *worker, char *data, 
                            apr_pool_t *ptmp) {
  apr_status_t status;
  apr_threadattr_t *tattr;
  apr_thread_t *client_thread;
  apr_thread_t *backend_thread;
  tunnel_t client;
  tunnel_t backend;
  apr_size_t peeklen;

  if (!(worker->flags & FLAGS_SERVER)) {
    worker_log(worker, LOG_ERR, "This command is only valid in a SERVER");
    return APR_EGENERAL;
  }

  if (worker->socket->socket_state == SOCKET_CLOSED) {
    worker_log(worker, LOG_ERR, "Socket to client is closed\n");
    return APR_ECONNREFUSED;
  }

  worker_log(worker, LOG_DEBUG, "--- tunnel\n");

  /* client side */
  if ((status = transport_set_timeout(worker->socket->transport, 100000)) 
      != APR_SUCCESS) {
    goto error1;
  }
  if (worker->socket->sockreader == NULL) {
    peeklen = worker->socket->peeklen;
    worker->socket->peeklen = 0;
    status = sockreader_new(&client.sockreader, worker->socket->transport,
	   	            worker->socket->peek, peeklen);
    if (status != APR_SUCCESS && !APR_STATUS_IS_TIMEUP(status)) {
      goto error1;
    }
  }
  else {
    client.sockreader = worker->socket->sockreader;
  }
  backend.sendto = worker->socket;

  /* backend side */
  if ((status = command_REQ(self, worker, data, ptmp)) != APR_SUCCESS) {
    goto error1;
  }
  if ((status = transport_set_timeout(worker->socket->transport, 100000)) 
      != APR_SUCCESS) {
    goto error2;
  }
  status = sockreader_new(&backend.sockreader, worker->socket->transport,
		          NULL, 0);
  if (status != APR_SUCCESS && !APR_STATUS_IS_TIMEUP(status)) {
    goto error2;
  }
  client.sendto = worker->socket;

  /* need two threads reading/writing from/to backend */
  if ((status = apr_threadattr_create(&tattr, worker->pbody)) != APR_SUCCESS) {
    goto error2;
  }

  if ((status = apr_threadattr_stacksize_set(tattr, DEFAULT_THREAD_STACKSIZE))
      != APR_SUCCESS) {
    goto error2;
  }

  if ((status = apr_threadattr_detach_set(tattr, 0)) != APR_SUCCESS) {
    goto error2;
  }

  if ((status = apr_thread_create(&client_thread, tattr, streamer, 
	                          &client, worker->pbody)) != APR_SUCCESS) {
    goto error2;
  }

  if ((status = apr_thread_create(&backend_thread, tattr, streamer, 
	                          &backend, worker->pbody)) != APR_SUCCESS) {
    goto error2;
  }

  apr_thread_join(&status, client_thread);
  if (status != APR_SUCCESS) {
    goto error2;
  }
  apr_thread_join(&status, backend_thread);
  if (status != APR_SUCCESS) {
    goto error2;
  }

error2:
  command_CLOSE(self, worker, "do not test expects", ptmp);
error1:
  worker_get_socket(worker, "Default", "0");
  sockreader_destroy(&client.sockreader);
  sockreader_destroy(&backend.sockreader);
  worker_log(worker, LOG_DEBUG, "--- tunnel end\n");
  return status;
}

/**
 * BREAK command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t command_BREAK(command_t *self, worker_t *worker, char *data, 
                           apr_pool_t *ptmp) {
  /* singal break for loop */
  COMMAND_NO_ARG;
  return -1;
}

/**
 * AUTO_CLOSE command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_AUTO_CLOSE(command_t *self, worker_t *worker, char *data, 
                                apr_pool_t *ptmp) {
  char *copy;
  COMMAND_NEED_ARG("on|off, default off");

  if (strcasecmp(copy, "on") == 0) {
    worker->flags |= FLAGS_AUTO_CLOSE;
  }
  else {
    worker->flags &= ~FLAGS_AUTO_CLOSE;
  }
  return APR_SUCCESS;
}

/**
 * AUTO_COOKIE command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_AUTO_COOKIE(command_t *self, worker_t *worker, char *data, 
                                 apr_pool_t *ptmp) {
  char *copy;
  COMMAND_NEED_ARG("on|off, default off");

  if (strcasecmp(copy, "on") == 0) {
    worker->flags |= FLAGS_AUTO_COOKIE;
  }
  else {
    if (worker->socket) {
      apr_table_clear(worker->socket->cookies);
      worker->socket->cookie = NULL;
    }
    worker->flags &= ~FLAGS_AUTO_COOKIE;
  }
  return APR_SUCCESS;
}

/**
 * MATCH_SEQ command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN sequence
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_MATCH_SEQ(command_t *self, worker_t *worker, char *data, 
                               apr_pool_t *ptmp) {
  char *copy;
  apr_pool_t *pool;
  COMMAND_NEED_ARG("<var-sequence>*");
  
  pool = module_get_config(worker->config, apr_pstrdup(ptmp, "MATCH_SEQ"));
  if (!pool) {
    /* create a pool for match */
    HT_POOL_CREATE(&pool);
    module_set_config(worker->config, apr_pstrdup(pool, "MATCH_SEQ"), pool);
  }

  worker->match_seq = apr_pstrdup(pool, copy);
  return APR_SUCCESS;
}

/**
 * RECORD command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN "RES" ["ALL"]|[["STATUS"] ["HEADERS"] ["BODY"]]
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_RECORD(command_t *self, worker_t *worker, char *data, 
                            apr_pool_t *ptmp) {
  char *copy;
  recorder_t *recorder = worker_get_recorder(worker);
  COMMAND_NEED_ARG("RES [ALL] {STATUS|HEADERS|BODY}*");

  if (strncmp(copy, "RES", 3) != 0) {
    worker_log(worker, LOG_ERR, "Only response recording supported yet");
    return APR_EINVAL;
  }

  if (strstr(copy, "ALL")) {
    recorder->flags = RECORDER_RECORD_ALL;
  }
  if (strstr(copy, "STATUS")) {
    recorder->flags |= RECORDER_RECORD_STATUS;
  }
  if (strstr(copy, "HEADERS")) {
    recorder->flags |= RECORDER_RECORD_HEADERS;
  }
  if (strstr(copy, "BODY")) {
    recorder->flags |= RECORDER_RECORD_BODY;
  }

  if (recorder->on) {
    /* restart the recorder by dropping the sockreader pool */
    sockreader_destroy(&recorder->sockreader);
  }

  /* setup a sockreader for recording */
  sockreader_new(&recorder->sockreader, NULL, NULL, 0);

  recorder->on = RECORDER_RECORD;

  return APR_SUCCESS;
}

/**
 * PLAY command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN "BACK"|"VAR" <varname>
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_PLAY(command_t *self, worker_t *worker, char *data, 
                          apr_pool_t *ptmp) {
  recorder_t *recorder = worker_get_recorder(worker);
  COMMAND_NO_ARG;
  /* if recorded data available do play back */
  if (recorder->on == RECORDER_RECORD) {
    recorder->on = RECORDER_PLAY;
  }
  else {
    worker_log(worker, LOG_ERR, "Can not play cause recorder is not in recording mode");
    return APR_EINVAL;
  }
  return APR_SUCCESS;
}

/**
 * LOCAL command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN <var> (" " <var>)*
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_LOCAL(command_t *self, worker_t *worker, char *data, 
                           apr_pool_t *ptmp) {
  char *copy;
  char *last;
  char *var;
  COMMAND_NEED_ARG("<var> (\" \" <var>)*");

  var = apr_strtok(copy, " ", &last);
  while (var) {
    store_set(worker->locals, var, "");
    var = apr_strtok(NULL, " ", &last);
  }

  return APR_SUCCESS;
}

/**
 * USE command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN <module>
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_USE(command_t *self, worker_t *worker, char *data, 
                         apr_pool_t *ptmp) {
  char *copy;
  COMMAND_NEED_ARG("<module>");

  if (!(worker->blocks = apr_hash_get(worker->modules, copy, APR_HASH_KEY_STRING))) {
    worker_log(worker, LOG_ERR, "Could not finde module \"%s\"", copy);
    return APR_EINVAL;
  }

  return APR_SUCCESS;
}

/**
 * IGNORE_BODY command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_IGNORE_BODY(command_t *self, worker_t *worker, char *data, 
                                 apr_pool_t *ptmp) {
  char *copy;
  COMMAND_NEED_ARG("on|off, default off");

  apr_collapse_spaces(copy, copy);
  if (strcasecmp(copy, "on") == 0) {
    worker->flags |= FLAGS_IGNORE_BODY;
  }
  else if (strcasecmp(copy, "off") == 0) {
    worker->flags &= ~FLAGS_IGNORE_BODY;
  }
  else {
    worker_log(worker, LOG_ERR, "Do not understand \"%s\"", copy);
    return APR_EINVAL;
  }
  return APR_SUCCESS;
}

/**
 * VERSION command
 *
 * @param self IN unused
 * @param worker IN thread data object
 * @param data IN variable to store in 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_VERSION(command_t *self, worker_t *worker, char *data, 
                             apr_pool_t *ptmp) {
  char *copy;
  COMMAND_NEED_ARG("<variable>");
  worker_var_set(worker, copy, PACKAGE_VERSION);
  return APR_SUCCESS;
}

/**
 * DUMMY command used for opsolete commands
 *
 * @param self IN unused
 * @param worker IN unused 
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
apr_status_t command_DUMMY(command_t *self, worker_t *worker, char *data, 
                           apr_pool_t *ptmp) {
  return APR_SUCCESS;
}

/**
 * Object thread data
 */

/**
 * New thread data object 
 *
 * @param self OUT thread data object
 * @param log_mode IN log mode  
 *
 */
void worker_new(worker_t ** self, char *additional, global_t *global, 
                interpret_f function) {
  if (global->mutex) apr_thread_mutex_lock(global->mutex);
  {
    apr_pool_t *p;
    HT_POOL_CREATE(&p);
    (*self) = apr_pcalloc(p, sizeof(worker_t));
    (*self)->global = global;
    (*self)->heartbeat = p;
    apr_pool_create(&p, (*self)->heartbeat);
    (*self)->pbody = p;
    apr_pool_create(&p, (*self)->heartbeat);
    (*self)->pcache = p;
    /* this stuff muss last until END so take pbody pool for this */
    p = (*self)->pbody;
    (*self)->interpret = function;
    (*self)->config = apr_hash_make(p);
    (*self)->filename = apr_pstrdup(p, "<none>");
    (*self)->socktmo = global->socktmo;
    (*self)->additional = apr_pstrdup(p, additional);
    (*self)->sync_mutex = global->sync_mutex;
    (*self)->mutex = global->mutex;
    (*self)->lines = apr_table_make(p, 20);
    (*self)->cache = apr_table_make((*self)->pcache, 20);
    (*self)->expect.dot = apr_table_make(p, 2);
    (*self)->expect.headers = apr_table_make(p, 2);
    (*self)->expect.body = apr_table_make(p, 2);
    (*self)->expect.exec= apr_table_make(p, 2);
    (*self)->expect.error = apr_table_make(p, 2);
    (*self)->match.dot= apr_table_make(p, 2);
    (*self)->match.headers = apr_table_make(p, 2);
    (*self)->match.body = apr_table_make(p, 2);
    (*self)->match.error = apr_table_make(p, 2);
    (*self)->match.exec = apr_table_make(p, 2);
    (*self)->grep.dot= apr_table_make(p, 2);
    (*self)->grep.headers = apr_table_make(p, 2);
    (*self)->grep.body = apr_table_make(p, 2);
    (*self)->grep.error = apr_table_make(p, 2);
    (*self)->grep.exec = apr_table_make(p, 2);
    (*self)->sockets = apr_hash_make(p);
    (*self)->headers_allow = NULL;
    (*self)->headers_filter = NULL;
    (*self)->params = store_make(p);
    (*self)->retvars = store_make(p);
    (*self)->locals = store_make(p);
    (*self)->vars = store_copy(global->vars, p);
    (*self)->modules = apr_hash_copy(p, global->modules);
    (*self)->blocks = global->blocks;
    (*self)->logger = global->logger;
    (*self)->flags = global->flags;
    (*self)->listener_addr = apr_pstrdup(p, APR_ANYADDR);
  
    store_set((*self)->vars, "__LOG_LEVEL", apr_itoa((*self)->pbody, 
  		logger_get_mode(global->logger)));
    
    worker_log((*self), LOG_DEBUG, 
  			 "worker_new: pool: %"APR_UINT64_T_HEX_FMT", pbody: %"APR_UINT64_T_HEX_FMT, 
  			 (*self)->pbody, (*self)->pbody);
  }
  if (global->mutex) apr_thread_mutex_unlock(global->mutex);
}

/**
 * Clone thread data object 
 *
 * @param self OUT thread data object
 * @param orig IN thread data object to copy from 
 *
 * @return an apr status
 */
void worker_clone(worker_t ** self, worker_t * orig) {
  global_t *global = orig->global;
  
  worker_new(self, orig->additional, global, orig->interpret);
  
  if (global->mutex) apr_thread_mutex_lock(global->mutex);
  {
    apr_pool_t *p;
    p = (*self)->pbody;
    (*self)->flags = orig->flags;
    (*self)->lines = my_table_deep_copy(p, orig->lines);
    (*self)->listener = NULL;
    (*self)->vars = store_copy(orig->vars, p);
    (*self)->listener_addr = apr_pstrdup(p, orig->listener_addr);
    (*self)->group = orig->group;
  
    worker_log((*self), LOG_DEBUG, 
               "worker_clone: pool: %"APR_UINT64_T_HEX_FMT", pbody: %"APR_UINT64_T_HEX_FMT, 
               (*self)->pbody, (*self)->pbody);
  }
  if (global->mutex) apr_thread_mutex_unlock(global->mutex);
}

/**
 * Destroy thread data object
 *
 * @param worker IN thread data object
 */
void worker_destroy(worker_t * worker) {
  worker_log(worker, LOG_DEBUG, 
             "worker_destroy: %"APR_UINT64_T_HEX_FMT", pbody: %"APR_UINT64_T_HEX_FMT, 
             worker->pbody, worker->pbody);
  apr_pool_destroy(worker->heartbeat);
}

/**
 * Clone thread data object 
 *
 * @param worker IN thread data object
 * @param line IN command line
 *
 * @return an apr status
 */
apr_status_t worker_add_line(worker_t * worker, const char *file_and_line,
                             char *line) {
  apr_table_addn(worker->lines, file_and_line, line);
  return APR_SUCCESS;
}

/**
 * Send buf with len
 * 
 * @param self IN thread data object
 * @param buf IN buffer to send
 * @param len IN no bytes of buffer to send
 *
 * @return apr status
 */
apr_status_t worker_socket_send(worker_t *worker, char *buf, 
                                apr_size_t len) {

  worker_log(worker, LOG_DEBUG, 
             "send socket: %"APR_UINT64_T_HEX_FMT" transport: %"APR_UINT64_T_HEX_FMT, 
             worker->socket, worker->socket->transport);
  return transport_write(worker->socket->transport, buf, len);
}

/**
 * Hop over headers till empty line
 *
 * @param worker IN worker object
 * @param start IN start index
 *
 * @return current index
 */
static int worker_hop_over_headers(worker_t *worker, int start) {
  int i = start;
  apr_table_entry_t *e =
    (apr_table_entry_t *) apr_table_elts(worker->cache)->elts;
  while (i < apr_table_elts(worker->cache)->nelts && e[i].val[0]) {
    ++i;
  }
  ++i;
  return i;
}

/**
 * get the length of the cached line
 *
 * @param worker IN worker object
 * @param cached_line IN a table entry of cache
 * @param len OUT length of cached_line
 *
 * @return length of this table entry
 */
apr_status_t worker_get_line_length(worker_t *worker,
                                    apr_table_entry_t cached_line,
                                    apr_size_t *len) {
  line_t line; 

  apr_status_t status = APR_SUCCESS;
  line.info = cached_line.key;
  line.buf = cached_line.val;
  *len = 0;

  /* if there are modules which do have their own format */
  if ((status = htt_run_line_get_length(worker, &line)) != APR_SUCCESS) {
    return status;
  }

  /* do not forget the \r\n */
  if (strncasecmp(line.info, "NOCRLF", 6) != 0) {
    *len += 2;
  }
  if (strncasecmp(line.info, "NOCRLF:", 7) == 0) { 
    *len += apr_atoi64(&line.info[7]);
  }
  else {
    *len += strlen(line.buf);
  }

  return status;
}

/**
 * flush partial data 
 *
 * @param worker IN worker object
 * @param from IN start cache line
 * @param to IN end cache line
 * @param ptmp IN temporary pool
 *
 * @return an apr status
 */
apr_status_t worker_flush_part(worker_t *worker, int from, int to, 
                               apr_pool_t *ptmp) {
  int i;
  int len;
  int nocrlf = 0;

  apr_status_t status = APR_SUCCESS;

  apr_table_entry_t *e =
    (apr_table_entry_t *) apr_table_elts(worker->cache)->elts;

  /* iterate through all cached lines and send them */
  for (i = from; i < to; ++i) {
    line_t line; 
    line.info = e[i].key;
    line.buf = e[i].val;
    /* use in this case the copied key */
    if (strstr(line.info, "resolve")) {
      int unresolved;
      /* do only local var resolve the only var pool which could have new vars
       * with values
       */
      /* replace all vars */
      line.buf = worker_replace_vars(worker, line.buf, &unresolved, ptmp); 
    }
    if((status = htt_run_line_flush(worker, &line)) != APR_SUCCESS) {
      return status;
    }
    if (strncasecmp(line.info, "NOCRLF:", 7) == 0) { 
      line.len = apr_atoi64(&line.info[7]);
      if (nocrlf) {
	worker_log_buf(worker, LOG_INFO, '+', line.buf, line.len);
      }
      else {
	worker_log_buf(worker, LOG_INFO, '>', line.buf, line.len);
      }
      nocrlf = 1;
    }
    else if (strcasecmp(line.info, "NOCRLF") == 0) {
      line.len = strlen(line.buf);
      if (nocrlf) {
	worker_log_buf(worker, LOG_INFO, '+', line.buf, line.len);
      }
      else {
	worker_log_buf(worker, LOG_INFO, '>', line.buf, line.len);
      }
      nocrlf = 1;
    } 
    else {
      line.len = strlen(line.buf);
      if (nocrlf) {
	worker_log_buf(worker, LOG_INFO, '+', line.buf, line.len);
      }
      else {
	worker_log_buf(worker, LOG_INFO, '>', line.buf, line.len);
      }
      nocrlf = 0;
    }

    if ((status = worker_socket_send(worker, line.buf, line.len)) 
	!= APR_SUCCESS) {
      goto error;
    }
    if((status = htt_run_line_sent(worker, &line)) != APR_SUCCESS) {
      return status;
    }
    worker->sent += line.len;
    if (strncasecmp(line.info, "NOCRLF", 6) != 0) {
      len = 2;
      if ((status = worker_socket_send(worker, "\r\n", len)) != APR_SUCCESS) {
	goto error;
      }
      worker->sent += len;
    }
  }

error:
  return status;
}

/**
 * Flush a chunk part
 * 
 * @param worker IN worker object
 * @param chunked IN chunk info to flush before data
 * @param from IN start cache line
 * @param to IN end cache line
 * @param ptmp IN temporary pool
 *
 * @param apr status
 */
apr_status_t worker_flush_chunk(worker_t *worker, char *chunked, int from, int to,
                                apr_pool_t *ptmp) {
  apr_status_t status;
  int len;

  if (chunked) {
    worker_log_buf(worker, LOG_INFO, '>', chunked, strlen(chunked));
  }

  if (chunked) {
    len = strlen(chunked);
    if ((status = worker_socket_send(worker, chunked, len)) != APR_SUCCESS) {
      return status;
    }
    worker->sent += len;
  }

  return worker_flush_part(worker, from, to, ptmp);
}

/**
 * Calculate content length
 *
 * @param worker IN worker object
 * @param start IN start index
 * @param len OUT content length
 *
 * @return apr status
 */
static apr_status_t worker_get_content_length(worker_t *worker, int start, 
                                              apr_size_t *len) { 
  apr_status_t status = APR_SUCCESS;
  int i = start;
  apr_table_entry_t *e =
    (apr_table_entry_t *) apr_table_elts(worker->cache)->elts;

  *len = 0;
  for (; i < apr_table_elts(worker->cache)->nelts; ++i) {
    apr_size_t tmp_len;
    if ((status = worker_get_line_length(worker, e[i], &tmp_len)) 
	!= APR_SUCCESS) {
      return status;
    }
    *len += tmp_len;
  }
  return status;
}

/**
 * Do automatic 100 continue
 *
 * @param worker IN worker object
 * @param body_start IN index of body start
 * @param ptmp IN temporary pool
 *
 * @return apr status
 */
static apr_status_t worker_do_auto_100_continue(worker_t *worker, 
                                                int body_start,
                                                apr_pool_t *ptmp) {
  apr_status_t status = APR_SUCCESS;

  /* flush headers and empty line but not body */
  if ((status = worker_flush_part(worker, 0, body_start, ptmp)) 
      != APR_SUCCESS) {
    return status;
  }
  /* wait for a 100 continue response */
  if ((status = command_EXPECT(NULL, worker, "headers \"HTTP/1.1 100 Continue\"", ptmp)) 
      != APR_SUCCESS) {
    return status;
  }
  /* do skip call flush in command _WAIT */
  worker->flags |= FLAGS_SKIP_FLUSH;
  if ((status = command_WAIT(NULL, worker, "", ptmp)) != APR_SUCCESS) {
    return status;
  }
  /* do not skip flush */
  worker->flags &= ~FLAGS_SKIP_FLUSH;
  /* send body then */
  if ((status = worker_flush_part(worker, body_start, 
				  apr_table_elts(worker->cache)->nelts, ptmp))
      != APR_SUCCESS) { 
    return status;
  }
  return status;
}

/**
 * flush data 
 *
 * @param self IN thread data object
 * @param ptmp IN temporary pool
 *
 * @return an apr status
 */
apr_status_t worker_flush(worker_t * self, apr_pool_t *ptmp) {
  apr_size_t len;
  const char *hdr;

  int i = 0;
  int body_start = 0;
  int icap_body = 0;
  int icap_body_start = 0;
  int start = 0;
  char *chunked = NULL;
  int ct_len = 0;

  apr_status_t status = APR_SUCCESS;
  apr_table_entry_t *e =
    (apr_table_entry_t *) apr_table_elts(self->cache)->elts;

  /* test if we should skip it */
  if (self->flags & FLAGS_SKIP_FLUSH) {
    return APR_SUCCESS;
  }

  if (!self->socket) {
    goto error;
  }
  
  /* hop over icap headers if there are any */
  if (apr_table_get(self->cache, "Content-Length") && 
      (hdr = apr_table_get(self->cache, "Encapsulated"))) {
    char *nv;
    char *last;
    char *copy = apr_pstrdup(self->pbody, hdr);

    /* start counting till last body of ICAP message */
    i = 0;
    apr_strtok(copy, ":", &last);
    nv = apr_strtok(NULL, ",", &last);
    while (nv) {
      i = worker_hop_over_headers(self, i);
      nv = apr_strtok(NULL, ",", &last);
    }
    start = 1;
  }

  /* callculate body if Content-Length: AUTO */
  if (apr_table_get(self->cache, "Content-Length")) {
    if (!start) {
      i = worker_hop_over_headers(self, i);
    }
    body_start = i;

    if ((status = worker_get_content_length(self, i, &len)) != APR_SUCCESS) {
      return status;
    }

    apr_table_set(self->cache, "Content-Length",
                  apr_psprintf(self->pbody, "Content-Length: %"APR_SIZE_T_FMT, len));

    ct_len = len;
  }

  /* callculate headers and optional body of ICAP message */
  if ((hdr = apr_table_get(self->cache, "Encapsulated"))) {
    char *nv;
    char *last;
    char *res = NULL;
    char *copy = apr_pstrdup(self->pbody, hdr);

    /* restart counting */
    i = 0;
    len = 0;
    apr_strtok(copy, ":", &last);
    nv = apr_strtok(NULL, ",", &last);
    while (nv) {
      char *var;
      char *val;

      var = apr_strtok(nv, "=", &val);
      apr_collapse_spaces(var, var);
      apr_collapse_spaces(val, val);
      if (strstr(var, "body")) {
	icap_body = 1;
      }
      if (val && strncmp(val, "AUTO", 4) == 0) {
        while (i < apr_table_elts(self->cache)->nelts && e[i].val[0]) {
	  apr_size_t tmp_len;
	  if ((status = worker_get_line_length(self, e[i], &tmp_len)) 
	      != APR_SUCCESS) {
	    return status;
	  }
	  len += tmp_len;
	  ++i;
	}
	/* count also the empty line */
	len += 2;
	val = apr_itoa(self->pbody, len);
	++i;
      }
      else {
	i = worker_hop_over_headers(self, i);
      }

      if (!res) {
	res = apr_pstrcat(self->pbody, var, "=", val, NULL); 
      }
      else {
	res = apr_pstrcat(self->pbody, res, ", ", var, "=", val, NULL); 
      }
      nv = apr_strtok(NULL, ",", &last);
    }
    apr_table_setn(self->cache, "Encapsulated",
                   apr_psprintf(self->pbody, "Encapsulated: %s", res));

    /* only chunk body automatic if Content-Length: AUTO */
    if (icap_body && apr_table_get(self->cache, "Content-Length")) {
      icap_body_start = i;
      chunked = apr_psprintf(self->pbody, "%x\r\n", ct_len);
    }
  }
  else if (apr_table_get(self->cache, "Content-Length") && 
           apr_table_get(self->cache, "100-Continue")) {
    /* do this only if Content-Length and 100-Continue is set */
    status = worker_do_auto_100_continue(self, body_start, ptmp); 
    goto error;
  }

  if (apr_table_get(self->cache, "Cookie")) {
    if (self->socket->cookie) {
      apr_table_set(self->cache, "Cookie", self->socket->cookie);
    }
    else {
      apr_table_unset(self->cache, "Cookie");
    }
  }

  /* this is one chunk */
  if (apr_table_get(self->cache, "CHUNKED")) {
    apr_table_unset(self->cache, "CHUNKED");
    len = 0;
    for (; i < apr_table_elts(self->cache)->nelts; ++i) {
      /* do not forget the \r\n */
      if (strncasecmp(e[i].key, "NOCRLF", 6) != 0) {
	len += 2;
      }
      if (strncasecmp(e[i].key, "NOCRLF:", 7) == 0) { 
	len += apr_atoi64(&e[i].key[7]);
      }
      else {
	len += strlen(e[i].val);
      }
    }
    chunked = apr_psprintf(self->pbody, "\r\n%x\r\n", (unsigned int)len);
  }
  if (icap_body) {
    /* send all except the req/res body */
    if ((status = worker_flush_part(self, 0, icap_body_start, ptmp)) 
	!= APR_SUCCESS) {
      goto error;
    }
    if ((status = worker_flush_chunk(self, chunked, icap_body_start, 
	                             apr_table_elts(self->cache)->nelts, ptmp))
	!= APR_SUCCESS) {
      goto error;
    }
    if (chunked) {
      chunked = apr_psprintf(self->pbody, "\r\n0\r\n\r\n");
      status = worker_flush_chunk(self, chunked, 0, 0, ptmp); 
    }
  }
  else {
    status = worker_flush_chunk(self, chunked, 0, 
	                        apr_table_elts(self->cache)->nelts, ptmp);
  }

error:
  apr_pool_clear(self->pcache);
  self->cache = apr_table_make(self->pcache, 20);

  return status;
}

/**
 * write worker data to file with worker->name
 *
 * @param worker IN thread data object
 *
 * @return an apr status
 */
apr_status_t worker_to_file(worker_t * worker) {
  apr_status_t status;
  apr_file_t *fp;
  apr_table_entry_t *e;
  char *line;
  char *copy;
  int i;

  if ((status =
       apr_file_open(&fp, worker->name, APR_CREATE | APR_WRITE, APR_OS_DEFAULT,
		     worker->pbody)) != APR_SUCCESS) {
    return status;
  }

  e = (apr_table_entry_t *) apr_table_elts(worker->lines)->elts;
  for (i = 0; i < apr_table_elts(worker->lines)->nelts; i++) {
    line = e[i].val;
    copy = worker_replace_vars(worker, line, NULL, worker->pbody); 
    apr_file_printf(fp, "%s\n", &copy[1]);
  }

  apr_file_close(fp);

  return APR_SUCCESS;
}

/**
 * Register transport to socket
 *
 * @param socket IN htt socket
 * @param transport IN transport object for read/write
 * @return APR_SUCCESS
 */
apr_status_t transport_register(socket_t *socket, transport_t *transport) {
  if (socket) {
    socket->transport = transport;
  }
  return APR_SUCCESS;
}

/**
 * Unregister transport from socket
 *
 * @param socket IN htt socket
 * @return APR_SUCCESS
 */
apr_status_t transport_unregister(socket_t *socket, transport_t *transport) {
  if (socket) {
    socket->transport = NULL;
  }
  return APR_SUCCESS;
}

/**
 * Get current transport from socket
 *
 * @param socket IN htt socket
 * @return transport
 */
transport_t *transport_get_current(socket_t *socket) {
  return socket->transport;
}

/**
 * builtin finally for cleanup stuff
 * @param worker IN thread object
 */
void worker_finally_cleanup(worker_t *worker) {
  sh_t *sh = module_get_config(worker->config, SH_CONFIG);
  if (sh && sh->tmpf) {
    const char *name;

    if (apr_file_name_get(&name, sh->tmpf) == APR_SUCCESS) {
      apr_file_close(sh->tmpf);
      apr_file_remove(name, sh->pool);
      module_set_config(worker->config, apr_pstrdup(sh->pool, SH_CONFIG), NULL);
      apr_pool_destroy(sh->pool);
    }
  }

}

APR_HOOK_STRUCT(
  APR_HOOK_LINK(line_get_length)
  APR_HOOK_LINK(line_flush)
  APR_HOOK_LINK(line_sent)
  APR_HOOK_LINK(client_port_args)
  APR_HOOK_LINK(pre_connect)
  APR_HOOK_LINK(connect)
  APR_HOOK_LINK(post_connect)
  APR_HOOK_LINK(accept)
  APR_HOOK_LINK(pre_close)
  APR_HOOK_LINK(close)
  APR_HOOK_LINK(WAIT_begin)
  APR_HOOK_LINK(read_pre_headers)
  APR_HOOK_LINK(read_status_line)
  APR_HOOK_LINK(read_header)
  APR_HOOK_LINK(read_buf)
  APR_HOOK_LINK(WAIT_end)
)


APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, line_get_length, 
                                      (worker_t *worker, line_t *line), 
				      (worker, line), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, line_flush, 
                                      (worker_t *worker, line_t *line), 
				      (worker, line), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, line_sent, 
                                      (worker_t *worker, line_t *line), 
				      (worker, line), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, client_port_args, 
                                      (worker_t *worker, char *portinfo, 
				       char **new_portinfo, char *rest_of_line), 
				      (worker, portinfo, new_portinfo, rest_of_line), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, pre_connect, 
                                      (worker_t *worker), 
				      (worker), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, connect, 
                                      (worker_t *worker), 
				      (worker), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, post_connect, 
                                      (worker_t *worker), 
				      (worker), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, accept, 
                                      (worker_t *worker, char *rest_of_line), 
				      (worker, rest_of_line), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, pre_close, 
                                      (worker_t *worker), 
				      (worker), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, close, 
                                      (worker_t *worker, char *info, char **new_info), 
				      (worker, info, new_info), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, WAIT_begin, 
                                      (worker_t *worker), 
				      (worker), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, read_pre_headers, 
                                      (worker_t *worker), 
				      (worker), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, read_status_line, 
                                      (worker_t *worker, char *line), 
				      (worker, line), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, read_header, 
                                      (worker_t *worker, char *line), 
				      (worker, line), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, read_buf, 
                                      (worker_t *worker, char *buf, apr_size_t len), 
				      (worker, buf, len), APR_SUCCESS)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, WAIT_end, 
                                      (worker_t *worker, apr_status_t status), 
				      (worker, status), APR_SUCCESS)


