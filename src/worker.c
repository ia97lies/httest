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
 * Implementation of the HTTP Test Tool worker.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/ssl.h>

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

#include <pcre.h>
#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#include "defines.h"
#include "util.h"
#include "regex.h"
#include "file.h"
#include "socket.h"
#include "ssl.h"
#include "worker.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/

typedef struct url_escape_seq {
  char c;
  char *esc;
  apr_size_t len;
} url_escape_seq_t;

typedef struct write_buf_to_file_s {
  char *buf;
  apr_size_t len;
  apr_file_t *fp;
} write_buf_to_file_t;

typedef struct tunnel_s {
  apr_pool_t *pool;
  sockreader_t *sockreader;
  socket_t *sendto;
} tunnel_t;

/************************************************************************
 * Globals 
 ***********************************************************************/

url_escape_seq_t url_escape_seq[] = {
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
 * Implementation
 ***********************************************************************/

static apr_status_t socket_send(socket_t *socket, char *buf, apr_size_t len);

/**
 * set a variable either as local or global
 * make a copy and replace existing
 *
 * @param worker IN thread object
 * @param var IN variable name
 * @param val IN value
 */
void varset(worker_t * worker, const char *var, const char *val) {
  const char *ret;
  if ((ret = apr_table_get(worker->retvars, var))) {
    /* if retvar exist do mapping and store it in vars */
    apr_table_set(worker->vars, ret, val);  
  }
  else if (apr_table_get(worker->locals, var)) {
    apr_table_set(worker->locals, var, val);
  }
  else if (apr_table_get(worker->params, var)) {
    apr_table_set(worker->params, var, val);
  }
  else {
    apr_table_set(worker->vars, var, val);
  }
}

/**
 * set a variable either as local or global
 * make no copy but replace existing
 *
 * @param worker IN thread object
 * @param var IN variable name
 * @param val IN value
 */
void varsetn(worker_t * worker, const char *var, const char *val) {
  if (apr_table_get(worker->locals, var)) {
    apr_table_setn(worker->locals, var, val);
  }
  else if (apr_table_get(worker->params, var)) {
    apr_table_setn(worker->params, var, val);
  }
  else {
    apr_table_setn(worker->vars, var, val);
  }
}

/**
 * get a variable either as local or global
 *
 * @param worker IN thread object
 * @param var IN variable name
 *
 * @return value
 */
const char *varget(worker_t* worker, const char *var) {
  const char *val;
  if ((val = apr_table_get(worker->locals, var))) {
    return val;
  }
  else if ((val = apr_table_get(worker->params, var))) {
    return val;
  }
  else {
    return apr_table_get(worker->vars, var);
  }
}

/**
 * a simple log mechanisme
 *
 * @param self IN thread data object
 * @param log_mode IN log mode
 *                    LOG_DEBUG for a lot of infos
 *                    LOG_INFO for much infos
 *                    LOG_ERR for only very few infos
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */
void worker_log(worker_t * self, int log_mode, char *fmt, ...) {
  char *tmp;
  va_list va;

  va_start(va, fmt);
  if (self->log_mode >= log_mode) {
    if (log_mode == LOG_ERR) {
      tmp = apr_pvsprintf(self->pcmd, fmt, va);
      fprintf(stderr, "\n%-88s", tmp);
      fflush(stderr);
    }
    else {
      fprintf(stdout, "\n%s", self->prefix);
      vfprintf(stdout, fmt, va);
      fflush(stdout);
    }
  }
  va_end(va);
}

/**
 * a simple error log mechanisme
 *
 * @param self IN thread data object
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */
void worker_log_error(worker_t * self, char *fmt, ...) {
  char *tmp;
  va_list va;

  va_start(va, fmt);
  if (self->log_mode >= LOG_ERR) {
    tmp = apr_pvsprintf(self->pcmd, fmt, va);
    tmp = apr_psprintf(self->pcmd, "%s: error: %s", self->file_and_line,
	               tmp);
    fprintf(stderr, "\n%-88s", tmp);
    fflush(stderr);
  }
}

/**
 * a simple log buf mechanisme
 *
 * @param self IN thread data object
 * @param log_mode IN log mode
 *                    LOG_DEBUG for a lot of infos
 *                    LOG_INFO for much infos
 *                    LOG_ERR for only very few infos
 * @param buf IN buf to print (binary data allowed)
 * @param prefix IN prefix before buf
 * @param len IN buf len
 */
void worker_log_buf(worker_t * self, int log_mode, char *buf,
                    char *prefix, int len) {
  int i;
  char *null="<null>";

  FILE *fd = stdout;

  if (!buf) {
    buf = null;
    len = strlen(buf);
  }
  
  if (log_mode == LOG_ERR) {
    fd = stderr;
  }
  if (self->log_mode >= log_mode) {
    i = 0;
    fprintf(fd, "\n%s%s", self->prefix, prefix);
    while (i < len) {
      while (i < len && buf[i] != '\r' && buf[i] != '\n') {
	if (buf[i] >= 0x20) {
	  fprintf(fd, "%c", buf[i]);
	}
	else {
	  fprintf(fd, "0x%02x ", (unsigned char)buf[i]);
	}
        i++;
      }
      while (i < len && (buf[i] == '\r' || buf[i] == '\n')) {
	if (i != len -1) {
	  if (buf[i] == '\n') {
	    fprintf(fd, "%c", buf[i]);
	    fprintf(fd, "%s%s", self->prefix, prefix);
	  }
	}
	i++;
      }
      fflush(fd);
    }
  }
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
      status = socket_send(tunnel->sendto, buf, len);
    }
  } while (status == APR_SUCCESS);

  if (APR_STATUS_IS_EOF(status)) {
    status = APR_SUCCESS;
  }
  apr_thread_exit(thread, APR_SUCCESS);
  return NULL;
}

/**
 * Buffer converter depends on the worker->flags
 *
 * @param worker IN thread data object
 * @param buf INOUT buffer to rewrite
 * @param len INOUT buffer len 
 */
void worker_buf_convert(worker_t *self, char **buf, apr_size_t *len) {
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
    apr_pool_create(&pool, NULL);
    hexbuf = NULL;
    for (j = 0; j < *len; j++) {
      if (hexbuf == NULL) {
	 hexbuf = apr_psprintf(pool, "%02X", (*buf)[j]);
      }
      else {
	 hexbuf = apr_psprintf(pool, "%s%02X", hexbuf, (*buf)[j]);
      }
    }
    *buf = apr_pstrdup(self->pcmd, hexbuf);
    *len = strlen(*buf);
    apr_pool_destroy(pool);
  }
}


#ifdef USE_SSL
/**
 * worker ssl handshake client site
 *
 * @param worker IN thread data object
 *
 * @return apr status
 */
apr_status_t worker_ssl_handshake(worker_t * worker) {
  apr_status_t status;
  char *error;
  
  if ((status = ssl_handshake(worker->socket->ssl, &error, worker->pool)) 
      != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "%s", error);
  }
  
  if (worker->flags & FLAGS_SSL_LEGACY) {
#if (OPENSSL_VERSION_NUMBER >= 0x009080cf)
#ifdef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    worker->socket->ssl->s3->flags |= SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION; 
#else 	 
    SSL_set_options(worker->socket->ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif
#endif
  }

  return status;
}

/**
 * Get server ctx with loaded cert and key file
 *
 * @param self IN thread object data
 *
 * @return APR_SUCCESS or APR_ECONNABORTED
 */
apr_status_t worker_ssl_ctx(worker_t * self, char *certfile, char *keyfile, char *ca, int check) {
  worker_log(self, LOG_DEBUG, "cert: %s; key: %s; ca: %s\n", 
             certfile?certfile:"(null)",
             keyfile?keyfile:"(null)",
             ca?ca:"(null)");
  if (!self->ssl_ctx) {
    if (!(self->ssl_ctx = SSL_CTX_new(self->meth))) {
      worker_log(self, LOG_ERR, "Could not initialize SSL Context.");
      return APR_EINVAL;
    }
  }
  if (self->ssl_ctx) {
    if (certfile && SSL_CTX_use_certificate_file(self->ssl_ctx, certfile, 
	                                         SSL_FILETYPE_PEM) <= 0 && 
	check) { 
      worker_log(self, LOG_ERR, "Could not load RSA server certifacte \"%s\"",
	         certfile);
      return APR_EINVAL;
    }
    if (keyfile && SSL_CTX_use_PrivateKey_file(self->ssl_ctx, keyfile, 
	                                       SSL_FILETYPE_PEM) <= 0 && 
	check) {
      worker_log(self, LOG_ERR, "Could not load RSA server private key \"%s\"",
	         keyfile);
      return APR_EINVAL;
    }
    if (ca && !SSL_CTX_load_verify_locations(self->ssl_ctx, ca,
					     NULL) && check) {
      worker_log(self, LOG_ERR, "Could not load CA file \"%s\"", ca);
      return APR_EINVAL;
    }

    if (certfile && keyfile&& check && 
	!SSL_CTX_check_private_key(self->ssl_ctx)) {
      worker_log(self, LOG_ERR, "Private key does not match the certificate public key");
      return APR_EINVAL;
    }
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(worker->ssl_ctx,1);
#endif
 }
  return APR_SUCCESS;
}

/**
 * Get method 
 *
 * @param self IN thread object data
 * @param sslstr IN SSL|SSL2|SSL3|TLS1
 *
 * @return APR_SUCCESS or APR_ECONNABORTED
 */
int worker_set_method(worker_t * worker, char *sslstr) {
  int is_ssl = 0;
  if (strcasecmp(sslstr, "SSL") == 0) {
    is_ssl = 1;
    worker->meth = SSLv23_client_method();
  }
  else if (strcasecmp(sslstr, "SSL2") == 0) {
    is_ssl = 1;
    worker->meth = SSLv2_client_method();
  }
  else if (strcasecmp(sslstr, "SSL3") == 0) {
    is_ssl = 1;
    worker->meth = SSLv3_client_method();
  }
  else if (strcasecmp(sslstr, "TLS1") == 0) {
    is_ssl = 1;
    worker->meth = TLSv1_client_method();
  }
  return is_ssl;
}

/**
 * Do a ssl accept
 *
 * @param worker IN thread data object
 *
 * @return APR_SUCCESS
 */
apr_status_t worker_ssl_accept(worker_t * worker) {
  apr_status_t status;
  char *error;

  if (worker->socket->is_ssl) {
    if (!worker->socket->ssl) {
      BIO *bio;
      apr_os_sock_t fd;

      if ((worker->socket->ssl = SSL_new(worker->ssl_ctx)) == NULL) {
	worker_log(worker, LOG_ERR, "SSL_new failed.");
	status = APR_ECONNREFUSED;
      }
      SSL_set_ssl_method(worker->socket->ssl, worker->meth);
      ssl_rand_seed();
      apr_os_sock_get(&fd, worker->socket->socket);
      bio = BIO_new_socket(fd, BIO_NOCLOSE);
      SSL_set_bio(worker->socket->ssl, bio, bio);
    }
    else {
      return APR_SUCCESS;
    }
  }
  else {
    return APR_SUCCESS;
  }

  if ((status = ssl_accept(worker->socket->ssl, &error, worker->pool)) 
      != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "%s", error);
  }
  return status;
}
#endif

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

  if (!worker->socket || !worker->socket->socket) {
    return APR_ENOSOCKET;
  }
  
  /* give the other side a little time to finish closing 10 ms */
  apr_sleep(10000);
  
  if ((status = apr_socket_timeout_set(worker->socket->socket, 1000)) 
      != APR_SUCCESS) {
    return status;
  }

#ifdef USE_SSL
  if (worker->socket->ssl) {
    status = SSL_read(worker->socket->ssl, &worker->socket->peek[worker->socket->peeklen], len);
    if (status <= 0) {
      int scode = SSL_get_error(worker->socket->ssl, status);

      if (scode == SSL_ERROR_ZERO_RETURN) {
        status = APR_ECONNABORTED; 
	goto go_out;
      }
      else if (scode != SSL_ERROR_WANT_WRITE && scode != SSL_ERROR_WANT_READ) {
        status = APR_ECONNABORTED; 
	goto go_out;
      }
      else {
	status = APR_SUCCESS;
	goto go_out;
      }
    }
    else {
      worker->socket->peeklen += len;
      status = APR_SUCCESS;
      goto go_out;
    }
  }
  else
#endif
  {
    status = apr_socket_recv(worker->socket->socket, 
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
  }

go_out:
  apr_socket_timeout_set(worker->socket->socket, worker->socktmo);

  return status;
}

/**
 * replace variables in a line
 *
 * @param worker IN thread data object
 * @param line IN line to replace in
 *
 * @return new line 
 */
char * worker_replace_vars(worker_t * worker, apr_pool_t *pool, char *line) {
  char *new_line;

  /* replace all locals first */
  new_line = my_replace_vars(pool, line, worker->locals, 0); 
  /* replace all parameters first */
  new_line = my_replace_vars(pool, line, worker->params, 0); 
  /* replace all vars */
  new_line = my_replace_vars(pool, new_line, worker->vars, 1); 

  return new_line;
}

/**
 * gets values from data and store it in the variable table
 *
 * @param worker IN thread data object
 * @param regexs IN table of regular expressions to get the values from data
 * @param data IN data to match
 *
 * @return APR_SUCCESS
 */
apr_status_t worker_match(worker_t * worker, apr_table_t * regexs, 
                          const char *data, apr_size_t len) {
  int rc;
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

  if (!data) {
    return APR_SUCCESS;
  }

  vtbl = apr_table_make(worker->pcmd, 2);
  
  e = (apr_table_entry_t *) apr_table_elts(regexs)->elts;
  for (i = 0; i < apr_table_elts(regexs)->nelts; ++i) {
    /* prepare vars if multiple */
    apr_table_clear(vtbl);
    tmp = apr_pstrdup(worker->pcmd, e[i].key);
    var = apr_strtok(tmp, " ", &last);
    while (var) {
      apr_table_set(vtbl, var, var);
      var = apr_strtok(NULL, " ", &last);
    }

    n = apr_table_elts(vtbl)->nelts;
    if (n > 10) {
      worker_log(worker, LOG_ERR, "Too many vars defined for _MATCH statement, max 10 vars allowed");
      return APR_EINVAL;
    }
    
    if (e[i].val
        && (rc =
            regexec((regex_t *) e[i].val, data, len, n + 1, regmatch,
                    PCRE_MULTILINE)) == 0) {
      v = (apr_table_entry_t *) apr_table_elts(vtbl)->elts;
      for (j = 0; j < n; j++) {
	val =
	  apr_pstrndup(worker->pool, &data[regmatch[j + 1].rm_so],
		       regmatch[j + 1].rm_eo - regmatch[j + 1].rm_so);
	varset(worker, v[j].key, val);
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

  return APR_SUCCESS;
}

/**
 * checks if data contains a given pattern
 *
 * @param self IN thread data object
 * @param regexs IN table of regular expressions
 * @param data IN data to check
 *
 * @return APR_SUCCESS
 */
apr_status_t worker_expect(worker_t * self, apr_table_t * regexs, 
                           const char *data, apr_size_t len) {
  int rc;
  apr_table_entry_t *e;
  int i;

  if (!data) {
    return APR_SUCCESS;
  }

  e = (apr_table_entry_t *) apr_table_elts(regexs)->elts;
  for (i = 0; i < apr_table_elts(regexs)->nelts; ++i) {
    if (e[i].val
        && (rc =
            regexec((regex_t *) e[i].val, data, len, 0, NULL,
                    PCRE_MULTILINE)) == 0) {
    }
  }

  return APR_SUCCESS;
}

apr_status_t worker_validate_match(worker_t * self, apr_table_t *match, 
                                   char *error_prefix, apr_status_t status) {
  apr_table_entry_t *e;
  int i;

  e = (apr_table_entry_t *) apr_table_elts(match)->elts;
  for (i = 0; i < apr_table_elts(match)->nelts; ++i) {
    if (!regdidmatch((regex_t *) e[i].val)) {
      worker_log(self, LOG_ERR, "%s: Did expect %s", error_prefix, e[i].key);
      if (status == APR_SUCCESS) {
	status = APR_EINVAL;
      }
    }
  }
  apr_table_clear(match);
  return status;
}

apr_status_t worker_validate_expect(worker_t * self, apr_table_t *expect, 
                                    char *error_prefix, apr_status_t status) {
  apr_table_entry_t *e;
  int i;

  e = (apr_table_entry_t *) apr_table_elts(expect)->elts;
  for (i = 0; i < apr_table_elts(expect)->nelts; ++i) {
    if (e[i].key[0] != '!' && !regdidmatch((regex_t *) e[i].val)) {
      worker_log(self, LOG_ERR, "%s: Did expect \"%s\"", error_prefix, 
	         e[i].key);
      if (status == APR_SUCCESS) {
	status = APR_EINVAL;
      }
    }
    if (e[i].key[0] == '!' && regdidmatch((regex_t *) e[i].val)) {
      worker_log(self, LOG_ERR, "%s: Did not expect \"%s\"", error_prefix, 
	         &e[i].key[1]);
      if (status == APR_SUCCESS) {
	status = APR_EINVAL;
      }
    }
  }
  apr_table_clear(expect);
  return status;
}

/**
 * Do check for if all defined expects are handled 
 *
 * @param self IN worker thread object
 * @param status IN current status
 *
 * @return current status or APR_EINVAL if there are unhandled expects
 */
apr_status_t worker_check_expect(worker_t * self, apr_status_t status) {
  status = worker_validate_match(self, self->match.dot, "MATCH .", 
                                 status);
  status = worker_validate_match(self, self->match.headers, "MATCH headers", 
                                 status);
  status = worker_validate_match(self, self->match.body, "MATCH body", 
                                 status);
  status = worker_validate_expect(self, self->expect.dot, "EXPECT .", 
                                 status);
  status = worker_validate_expect(self, self->expect.headers, "EXPECT headers", 
                                 status);
  status = worker_validate_expect(self, self->expect.body, "EXPECT body", 
                                 status);
  /* check if match sequence is empty */
  if (self->match_seq && self->match_seq[0] != 0) {
    worker_log(self, LOG_ERR, "The following match sequence \"%s\" was not in correct order", self->match_seq);
    return APR_EINVAL;
  }
  return status;
}

/**
 * Check for error expects handling
 *
 * @param self IN worker thread object
 * @param status IN current status
 *
 * @return current status or APR_INVAL
 */
apr_status_t worker_check_error(worker_t *self, apr_status_t status) {
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

  error = apr_psprintf(self->pcmd, "%s(%d)",
		     my_status_str(self->pcmd, status), status);

  worker_match(self, self->match.error, error, strlen(error));
  worker_match(self, self->grep.error, error, strlen(error));
  worker_expect(self, self->expect.error, error, strlen(error));

  if (apr_table_elts(self->expect.error)->nelts) {
    status = APR_SUCCESS;
    e = (apr_table_entry_t *) apr_table_elts(self->expect.error)->elts;
    for (i = 0; i < apr_table_elts(self->expect.error)->nelts; ++i) {
      if (e[i].key[0] != '!' && !regdidmatch((regex_t *) e[i].val)) {
	worker_log(self, LOG_ERR, "EXPECT: Did expect error \"%s\"", e[i].key);
	status = APR_EINVAL;
	goto error;
      }
      if (e[i].key[0] == '!' && regdidmatch((regex_t *) e[i].val)) {
	worker_log(self, LOG_ERR, "EXPECT: Did not expect error \"%s\"", &e[i].key[1]);
	status = APR_EINVAL;
	goto error;
      }
    }
    apr_table_clear(self->expect.error);
  }
 
  if (apr_table_elts(self->match.error)->nelts) {
    status = APR_SUCCESS;
    e = (apr_table_entry_t *) apr_table_elts(self->match.error)->elts;
    for (i = 0; i < apr_table_elts(self->match.error)->nelts; ++i) {
      if (!regdidmatch((regex_t *) e[i].val)) {
	worker_log(self, LOG_ERR, "MATCH error: Did expect %s", e[i].key);
	status = APR_EINVAL;
      }
    }
    apr_table_clear(self->match.error);
  }

error:
  if (status == APR_SUCCESS) {
    worker_log(self, LOG_INFO, "%s %s", self->name, error);
  }
  else {
    worker_log_error(self, "%s %s", self->name, error);
  }
  return status;
}

/**
 * Test for unused expects and matchs
 *
 * @param self IN thread data object
 *
 * @return APR_SUCCESS or APR_EGENERAL
 */
apr_status_t worker_test_unused(worker_t * self) {
  if (apr_table_elts(self->match.dot)->nelts) {
    worker_log(self, LOG_ERR, "There are unused MATCH .");
    return APR_EGENERAL;
  }
  if (apr_table_elts(self->match.headers)->nelts) {
    worker_log(self, LOG_ERR, "There are unused MATCH headers");
    return APR_EGENERAL;
  }
  if (apr_table_elts(self->match.body)->nelts) {
    worker_log(self, LOG_ERR, "There are unused MATCH body");
    return APR_EGENERAL;
  }
  if (apr_table_elts(self->match.exec)->nelts) {
    worker_log(self, LOG_ERR, "There are unused MATCH exec");
    return APR_EGENERAL;
  }
  if (apr_table_elts(self->expect.dot)->nelts) {
    worker_log(self, LOG_ERR, "There are unused EXPECT .");
    return APR_EGENERAL;
  }
  if (apr_table_elts(self->expect.headers)->nelts) {
    worker_log(self, LOG_ERR, "There are unused EXPECT headers");
    return APR_EGENERAL;
  }
  if (apr_table_elts(self->expect.body)->nelts) {
    worker_log(self, LOG_ERR, "There are unused EXPECT body");
    return APR_EGENERAL;
  }

  return APR_SUCCESS;
}

/**
 * Test for unused expects errors and matchs
 *
 * @param self IN thread data object
 *
 * @return APR_SUCCESS or APR_EGENERAL
 */
apr_status_t worker_test_unused_errors(worker_t * self) {
  if (apr_table_elts(self->expect.error)->nelts) { 
    worker_log(self, LOG_ERR, "There are unused EXPECT ERROR");
    return APR_EGENERAL;
  }

  if (apr_table_elts(self->match.error)->nelts) {
    worker_log(self, LOG_ERR, "There are unused MATCH ERROR");
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
apr_status_t worker_conn_close(worker_t * self, int ssl) {
  apr_status_t status;
#ifdef USE_SSL
  int i;
#endif

  if (!self->socket || !self->socket->socket) {
    return APR_ENOSOCKET;
  }

  if (self->socket->socket_state == SOCKET_CLOSED) {
    return APR_SUCCESS;
  }
  
#ifdef USE_SSL
  if (ssl && self->socket->is_ssl) {
    if (self->socket->ssl) {
      for (i = 0; i < 4; i++) {
	if (SSL_shutdown(self->socket->ssl) != 0) {
	  break;
	}
      }
      SSL_free(self->socket->ssl);
      self->socket->ssl = NULL;
    }
    self->socket->is_ssl = 0;
  }
#endif
  if ((status = apr_socket_close(self->socket->socket)) != APR_SUCCESS) {
    return status;
  }
  self->socket->socket_state = SOCKET_CLOSED;
  self->socket->socket = NULL;

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

  for (hi = apr_hash_first(self->pcmd, self->sockets); hi; hi = apr_hash_next(hi)) {
    apr_hash_this(hi, NULL, NULL, &s);
    self->socket = s;
    worker_conn_close(self, 1);
  }
  self->socket = cur;
  if (self->listener) {
    apr_socket_close(self->listener);
  }
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

static apr_status_t worker_handle_buf(worker_t *worker, apr_pool_t *pool, 
                                      char *buf, apr_size_t len) {
  apr_status_t status = APR_SUCCESS;
  apr_size_t inlen;
  apr_exit_why_e exitwhy;
  int exitcode;
  write_buf_to_file_t write_buf_to_file;
  apr_threadattr_t *tattr;
  apr_thread_t *thread;
  bufreader_t *br;
  char *line;
  apr_status_t tmp_status;

  if (buf) {
    worker_buf_convert(worker, &buf, &len);
    if (worker->flags & FLAGS_PIPE_IN) {
      worker->flags &= ~FLAGS_PIPE_IN;
      inlen = len;
      if ((status = file_write(worker->proc.in, buf, inlen))
	  != APR_SUCCESS) {
	goto out_err;
      }
      apr_file_close(worker->proc.in);
      apr_proc_wait(&worker->proc, &exitcode, &exitwhy, APR_WAIT);
      if (exitcode != 0) {
	status = APR_EGENERAL;
	goto out_err;
      }
    }
    else if (worker->flags & FLAGS_FILTER) {
      worker_log(worker, LOG_DEBUG, "write to stdin, read from stdout");
      worker->flags &= ~FLAGS_FILTER;
      /* start write thread */
      write_buf_to_file.buf = buf;
      write_buf_to_file.len = len;
      write_buf_to_file.fp = worker->proc.in;
      if ((status = apr_threadattr_create(&tattr, pool)) != APR_SUCCESS) {
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
			     &write_buf_to_file, worker->pcmd)) != APR_SUCCESS) {
	goto out_err;
      }
      /* read from worker->proc.out to buf */
      if ((status = bufreader_new(&br, worker->proc.out, worker->pcmd)) == APR_SUCCESS) {
	apr_size_t len;

	bufreader_read_eof(br, &line, &len);
	if (line) {
	  worker_log_buf(worker, LOG_INFO, line, "<", len);
	  worker_match(worker, worker->match.dot, line, len);
	  worker_match(worker, worker->match.body, line, len);
	  worker_match(worker, worker->grep.dot, line, len);
	  worker_match(worker, worker->grep.body, line, len);
	  worker_expect(worker, worker->expect.dot, line, len);
	  worker_expect(worker, worker->expect.body, line, len);
	}
      }
      if (status == APR_EOF) {
	status = APR_SUCCESS;
      }
      apr_thread_join(&tmp_status, thread);
      apr_proc_wait(&worker->proc, &exitcode, &exitwhy, APR_WAIT);
      if (exitcode != 0) {
	status = APR_EGENERAL;
	goto out_err;
      }
      /* tag it "done" */
      buf = NULL;
    }
    if (buf) {
      worker_log_buf(worker, LOG_INFO, buf, "<", len);
      worker_match(worker, worker->match.dot, buf, len);
      worker_match(worker, worker->match.body, buf, len);
      worker_match(worker, worker->grep.dot, buf, len);
      worker_match(worker, worker->grep.body, buf, len);
      worker_expect(worker, worker->expect.dot, buf, len);
      worker_expect(worker, worker->expect.body, buf, len);
    }
  }
out_err:
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
 * Wait for data (same as command_recv)
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN unused 
 *
 * @return an apr status
 */
apr_status_t command_WAIT(command_t * self, worker_t * worker,
                          char *data) {
  char *copy;
  int matches;
  int expects;
  char *line;
  char *buf;
  apr_status_t status;
  sockreader_t *sockreader;
  apr_pool_t *pool;
  char *last;
  char *key;
  const char *val = "";
  apr_size_t len;
  apr_ssize_t recv_len = -1;
  apr_size_t peeklen;

  buf = NULL;
  len = 0;
  matches = 0;
  expects = 0;

  COMMAND_OPTIONAL_ARG;

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    return status;
  }

  if (apr_isdigit(copy[0])) {
    recv_len = apr_atoi64(copy);
  }
  else {
    recv_len = -1;
  }

  apr_pool_create(&pool, NULL);

  if (worker->recorder->on == RECORDER_PLAY) {
    worker->sockreader = worker->recorder->sockreader;
  }

  if (worker->sockreader == NULL) {
    peeklen = worker->socket->peeklen;
    worker->socket->peeklen = 0;
    if ((status = sockreader_new(&sockreader, worker->socket->socket,
#ifdef USE_SSL
				 worker->socket->is_ssl ? worker->socket->ssl : NULL,
#endif
				 worker->socket->peek, peeklen, pool)) != APR_SUCCESS) {
      goto out_err;
    }
  }
  else {
    sockreader = worker->sockreader;
  }

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
    worker->headers = apr_table_make(worker->pool, 5);
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

  /** Status line, make that a little fuzzy in reading trailing empty lines of last
   *  request */
  while ((status = sockreader_read_line(sockreader, &line)) == APR_SUCCESS && 
      line[0] == 0);
  if (line[0] != 0) { 
    if (worker->recorder->on == RECORDER_RECORD &&
	worker->recorder->flags & RECORDER_RECORD_STATUS) {
      sockreader_push_line(worker->recorder->sockreader, line);
    }
    worker_log(worker, LOG_INFO, "<%s", line);
    worker_match(worker, worker->match.dot, line, strlen(line));
    worker_match(worker, worker->match.headers, line, strlen(line));
    worker_match(worker, worker->grep.dot, line, strlen(line));
    worker_match(worker, worker->grep.headers, line, strlen(line));
    worker_expect(worker, worker->expect.dot, line, strlen(line));
    worker_expect(worker, worker->expect.headers, line, strlen(line));

    if (!strstr(line, "HTTP/") && !strstr(line, "ICAP/")) {
      apr_table_add(worker->headers, "Connection", "close");
      status = sockreader_push_line(sockreader, line);
      goto http_0_9;
    }
  }
  else {
    if (line[0] == 0) {
      worker_log(worker, LOG_INFO, "<%s", line);
      worker_log_error(worker, "No status line received");
      status = APR_EINVAL;
      goto out_err;
    }
    else {
      worker_log(worker, LOG_INFO, "<%s", line);
      worker_log_error(worker, "Network error");
      goto out_err;
    }
  }
 
  /** get headers */
  while ((status = sockreader_read_line(sockreader, &line)) == APR_SUCCESS && 
         line[0] != 0) {
    if (worker->recorder->on == RECORDER_RECORD &&
	worker->recorder->flags & RECORDER_RECORD_HEADERS) {
      sockreader_push_line(worker->recorder->sockreader, line);
    }
    worker_log(worker, LOG_INFO, "<%s", line);
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
	status = APR_EGENERAL;
	goto out_err;
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
  if (line[0] == 0) {
    worker_log(worker, LOG_INFO, "<");
  }

http_0_9:
  if (status == APR_SUCCESS) {
    /* if recv len is specified use this */
    if (recv_len > 0) {
      len = recv_len;
      if ((status = worker_check_error(worker, 
	   content_length_reader(sockreader, &buf, &len, val))) 
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
      if ((status = worker_check_error(worker, 
	   content_length_reader(sockreader, &buf, &len, val))) 
	  != APR_SUCCESS) {
	goto out_err;
      }
    }
    else if ((val = apr_table_get(worker->headers, "Transfer-Encoding"))) {
      if ((status = worker_check_error(worker, 
	   transfer_enc_reader(sockreader, &buf, &len, val))) != APR_SUCCESS) {
	goto out_err;
      }
    }
    else if ((val = apr_table_get(worker->headers, "Encapsulated"))) {
      if ((status = worker_check_error(worker,
	   encapsulated_reader(sockreader, &buf, &len, val,
	                       apr_table_get(worker->headers, "Preview"))))
	  != APR_SUCCESS) {
	goto out_err;
      }
    }
    else if (worker->flags & FLAGS_CLIENT && 
	     (val = apr_table_get(worker->headers, "Connection"))) {
      if ((status = worker_check_error(worker,
	   eof_reader(sockreader, &buf, &len, val))) != APR_SUCCESS) {
	goto out_err;
      }
    }
    if ((status = worker_handle_buf(worker, pool, buf, len)) != APR_SUCCESS) {
      goto out_err;
    }
    if (worker->recorder->on == RECORDER_RECORD &&
	worker->recorder->flags & RECORDER_RECORD_BODY) {
      sockreader_push_line(worker->recorder->sockreader, "");
      sockreader_push_back(worker->recorder->sockreader, buf, len);
    }
    if (worker->flags & FLAGS_AUTO_CLOSE) {
      val = apr_table_get(worker->headers, "Connection");
      if (val && strcasecmp(val, "close") == 0) {
	command_CLOSE(self, worker, "do not test expects");
      }
    }
    if (worker->flags & FLAGS_AUTO_COOKIE) {
      /* get all set cookie and store them in cookie line */
      worker_set_cookie(worker);
    }
  }

out_err:
  if (worker->recorder->on == RECORDER_PLAY) {
    apr_pool_destroy(worker->recorder->pool);
    worker->recorder->on = RECORDER_OFF;
    worker->sockreader = NULL;
  }
  else {
    ++worker->req_cnt;
  }
  status = worker_check_expect(worker, status);

  apr_pool_destroy(pool);
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
apr_status_t command_RESWAIT(command_t * self, worker_t * worker, char * data) {
  apr_status_t status;
  do {
    status = command_RES(self, worker, "");
    if(status != APR_SUCCESS) {
      return status;
    }
    status = command_WAIT(self, worker, "");
    if(status == APR_EOF) {
      /* EOF = client failed to send data */
      command_CLOSE(self, worker, "do not test expects");
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

  socket = 
    apr_hash_get(self->sockets, apr_pstrcat(self->pcmd, hostname, portname, 
	                                    NULL),
	         APR_HASH_KEY_STRING);

  if (!socket) {
    socket = apr_pcalloc(self->pool, sizeof(*socket));
    socket->socket_state = SOCKET_CLOSED;
    tag = apr_pstrdup(self->pbody, portname);
    apr_hash_set(self->sockets, apr_pstrcat(self->pbody, hostname, tag,
	                                    NULL),
	         APR_HASH_KEY_STRING, socket);
  }

  self->socket = socket;
}

/**
 * Do an ssl connect on a connected socket
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN aditional data
 *
 * @return an apr status
 */
apr_status_t command_SSL_CONNECT(command_t *self, worker_t *worker, 
		                 char *data) {
  char *copy;
  char *last;
  char *sslstr;
  int is_ssl;
  BIO *bio;
  apr_os_sock_t fd;

  COMMAND_NEED_ARG("SSL|SSL2|SSL3|TLS1 [<cert-file> <key-file>]");

  sslstr = apr_strtok(copy, " ", &last);

#ifndef USE_SSL
	return APR_SUCCESS;
#else
  is_ssl = worker_set_method(worker, sslstr);
  if (!is_ssl) {
    worker_log(worker, LOG_ERR, "%s is not supported", sslstr);
    return APR_EGENERAL;
  }
  worker->socket->is_ssl = is_ssl;

  if (worker->socket->socket_state == SOCKET_CONNECTED) {
    if (worker->socket->is_ssl) {
      char *cert;
      char *key;
      char *ca;
      apr_status_t status;

      cert = apr_strtok(NULL, " ", &last);
      key = apr_strtok(NULL, " ", &last);
      ca = apr_strtok(NULL, " ", &last);
      if ((status = worker_ssl_ctx(worker, cert, key, ca, 1)) != APR_SUCCESS) {
	return status;
      }

      if ((worker->socket->ssl = SSL_new(worker->ssl_ctx)) == NULL) {
	worker_log(worker, LOG_ERR, "SSL_new failed.");
	return APR_ECONNREFUSED;
      }
      SSL_set_ssl_method(worker->socket->ssl, worker->meth);
      ssl_rand_seed();
      apr_os_sock_get(&fd, worker->socket->socket);
      bio = BIO_new_socket(fd, BIO_NOCLOSE);
      SSL_set_bio(worker->socket->ssl, bio, bio);
      if (worker->socket->sess) {
	SSL_set_session(worker->socket->ssl, worker->socket->sess);
	SSL_SESSION_free(worker->socket->sess);
	worker->socket->sess = NULL;
      }
      SSL_set_connect_state(worker->socket->ssl);

      if ((status = worker_ssl_handshake(worker)) != APR_SUCCESS) {
	return status;
      }
    }
#endif
  }
  else {
    worker_log_error(worker, "Can not do a SSL connect, cause no TCP connection available");
    return APR_EGENERAL;
  }
  return APR_SUCCESS;
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
                                char *data) {
  apr_status_t status;
  apr_sockaddr_t *remote_addr;
  char *portname;
  char *sslstr;
  char *portstr;
  char *hostname;
  char *tag;
  char *last;
  int port;
  char *copy;
  int is_ssl;
  int family = APR_INET;

  COMMAND_NEED_ARG("Need hostname and port");

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    return status;
  }

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    return status;
  }

  hostname = apr_strtok(copy, " ", &last);
  portname = apr_strtok(NULL, " ", &last);
  portstr = apr_pstrdup(worker->pool, portname);

  if (!hostname) {
    worker_log(worker, LOG_ERR, "no host name specified");
    return APR_EGENERAL;
  }
  
  if (!portname) {
    worker_log(worker, LOG_ERR, "no portname name specified");
    return APR_EGENERAL;
  }

#ifdef USE_SSL
  sslstr = apr_strtok(portstr, ":", &tag);
  is_ssl = worker_set_method(worker, sslstr);
  if (!is_ssl) {
    portstr = sslstr;
  }
  else {
    portstr = tag;
  }
#endif

  worker_log(worker, LOG_DEBUG, "get socket \"%s:%s\"", hostname, portname);
  worker_get_socket(worker, hostname, portname);

  /* remove tag from port */
  portstr = apr_strtok(portstr, ":", &tag);
  if (!portstr) {
    if (is_ssl) {
      worker_log(worker, LOG_ERR, "no SSL port specified");
    }
    else {
      worker_log(worker, LOG_ERR, "no port specified");
    }
    return APR_EGENERAL;
  }
  port = apr_atoi64(portstr);

  if (worker->socket->socket_state == SOCKET_CLOSED) {
    worker->socket->is_ssl = is_ssl;

#ifdef USE_SSL
    if (worker->socket->is_ssl) {
      char *cert;
      char *key;
      char *ca;

      cert = apr_strtok(NULL, " ", &last);
      key = apr_strtok(NULL, " ", &last);
      ca = apr_strtok(NULL, " ", &last);
      if ((status = worker_ssl_ctx(worker, cert, key, ca, 1)) 
	  != APR_SUCCESS) {
	return status;
      }
      SSL_CTX_set_options(worker->ssl_ctx, SSL_OP_ALL);
      SSL_CTX_set_options(worker->ssl_ctx, SSL_OP_SINGLE_DH_USE);
#if (OPENSSL_VERSION_NUMBER >= 0x0090806f)
      SSL_CTX_set_options(worker->ssl_ctx, SSL_OP_NO_TICKET);
#endif
    }
#endif
#if APR_HAVE_IPV6
    /* hostname/address must be surrounded in square brackets */
    if((hostname[0] == '[') && (hostname[strlen(hostname)-1] == ']')) {
      family = APR_INET6;
      hostname++;
      hostname[strlen(hostname)-1] = '\0';
    }
#endif
    if ((status = apr_socket_create(&worker->socket->socket, family,
				    SOCK_STREAM, APR_PROTO_TCP,
                                    worker->pool)) != APR_SUCCESS) {
      worker->socket->socket = NULL;
      return status;
    }
    if ((status =
         apr_socket_opt_set(worker->socket->socket, APR_TCP_NODELAY,
                            1)) != APR_SUCCESS) {
      return status;
    }

    if ((status =
         apr_socket_timeout_set(worker->socket->socket, worker->socktmo)) != APR_SUCCESS) {
      return status;
    }

#ifdef USE_SSL
    if (worker->socket->is_ssl) {
      BIO *bio;
      apr_os_sock_t fd;

      if ((worker->socket->ssl = SSL_new(worker->ssl_ctx)) == NULL) {
	worker_log(worker, LOG_ERR, "SSL_new failed.");
	status = APR_ECONNREFUSED;
      }
      SSL_set_ssl_method(worker->socket->ssl, worker->meth);
      ssl_rand_seed();
      apr_os_sock_get(&fd, worker->socket->socket);
      bio = BIO_new_socket(fd, BIO_NOCLOSE);
      SSL_set_bio(worker->socket->ssl, bio, bio);
      if (worker->socket->sess) {
	SSL_set_session(worker->socket->ssl, worker->socket->sess);
	SSL_SESSION_free(worker->socket->sess);
	worker->socket->sess = NULL;
      }
      SSL_set_connect_state(worker->socket->ssl);
    }
#endif
    if ((status =
         apr_sockaddr_info_get(&remote_addr, hostname, AF_UNSPEC, port,
                               APR_IPV4_ADDR_OK, worker->pool))
        != APR_SUCCESS) {
      return status;
    }

    if ((status =
         apr_socket_connect(worker->socket->socket, remote_addr)) 
				!= APR_SUCCESS) {
      return status;
    }

    if ((status =
         apr_socket_opt_set(worker->socket->socket, APR_SO_KEEPALIVE,
                            1)) != APR_SUCCESS) {
      return status;
    }

    worker->socket->socket_state = SOCKET_CONNECTED;
#ifdef USE_SSL
    if (worker->socket->is_ssl) {
      if ((status = worker_ssl_handshake(worker)) != APR_SUCCESS) {
				return status;
      }
    }
#endif
  }

  /* reset the matcher tables */
  apr_table_clear(worker->match.dot);
  apr_table_clear(worker->match.headers);
  apr_table_clear(worker->match.body);
  apr_table_clear(worker->match.error);
  apr_table_clear(worker->expect.dot);
  apr_table_clear(worker->expect.headers);
  apr_table_clear(worker->expect.body);
  apr_table_clear(worker->expect.error);

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
                                char *data) {
  apr_status_t status;

  COMMAND_NO_ARG;

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    return status;
  }

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    return status;
  }

  worker_get_socket(worker, "Default", "0");
  worker->socket->is_ssl = worker->is_ssl;

  if (worker->socket->socket_state == SOCKET_CLOSED) {
    worker_log(worker, LOG_DEBUG, "--- accept");
    if (!worker->listener) {
      worker_log_error(worker, "Server down");
      return APR_EGENERAL;
    }

    if ((status =
         apr_socket_accept(&worker->socket->socket, worker->listener,
                           worker->pool)) != APR_SUCCESS) {
      worker->socket->socket = NULL;
      return status;
    }
    if ((status =
           apr_socket_timeout_set(worker->socket->socket, worker->socktmo)) 
	!= APR_SUCCESS) {
      return status;
    }
#ifdef USE_SSL
    if ((status = worker_ssl_accept(worker)) != APR_SUCCESS) {
      return status;
    }
#endif
    worker->socket->socket_state = SOCKET_CONNECTED;
  }

  apr_table_clear(worker->match.dot);
  apr_table_clear(worker->match.headers);
  apr_table_clear(worker->match.body);
  apr_table_clear(worker->match.error);
  apr_table_clear(worker->expect.dot);
  apr_table_clear(worker->expect.headers);
  apr_table_clear(worker->expect.body);
  apr_table_clear(worker->expect.error);

  return APR_SUCCESS;
}

/**
 * Sleep for a given time (ms)
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN time to wait in ms
 *
 * @return an apr status
 */
apr_status_t command_SLEEP(command_t * self, worker_t * worker,
                                  char *data) {
  apr_status_t status;
  char *copy;

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    return status;
  }

  COMMAND_NEED_ARG("Time not specified");
 
  apr_sleep(apr_atoi64(copy) * 1000);
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
                                   char *data) {
  char *last;
  char *type;
  char *match;
  regex_t *compiled;
  const char *err;
  int off;
  char *copy;
  char *interm;

  COMMAND_NEED_ARG("Type and regex not specified");

  type = apr_strtok(copy, " ", &last);
  
  match = my_unescape(last, &last);

  if (!type) {
    worker_log(worker, LOG_ERR, "Type not specified");
    return APR_EGENERAL;
  }
  
  if (!match) {
    worker_log(worker, LOG_ERR, "Regex not specified");
    return APR_EGENERAL;
  }

  interm = apr_pstrdup(worker->pool, match);

  if (match[0] == '!') {
    ++match;
  }

  if (!(compiled = pregcomp(worker->pool, match, &err, &off))) {
    worker_log(worker, LOG_ERR, "EXPECT regcomp failed: \"%s\"", last);
    return APR_EINVAL;
  }

  if (strcmp(type, ".") == 0) {
    apr_table_addn(worker->expect.dot, interm, (char *) compiled);
  }
  else if (strcasecmp(type, "Headers") == 0) {
    apr_table_addn(worker->expect.headers, interm, (char *) compiled);
  }
  else if (strcasecmp(type, "Body") == 0) {
    apr_table_addn(worker->expect.body, interm, (char *) compiled);
  }
  else if (strcasecmp(type, "Exec") == 0) {
    apr_table_addn(worker->expect.exec, interm, (char *) compiled);
  }
  else if (strcasecmp(type, "Error") == 0) {
    apr_table_addn(worker->expect.error, interm, (char *) compiled);
  }
  else if (strncasecmp(type, "Var(", 4) == 0) {
    const char *val;
    char *var;
    
    var= apr_strtok(type, "(", &last);
    var = apr_strtok(NULL, ")", &last);
    val = varget(worker, var);
    if (val) {
      if (!worker->tmp_table) {
	worker->tmp_table = apr_table_make(worker->pool, 1);
      }
      apr_table_clear(worker->tmp_table);
      apr_table_addn(worker->tmp_table, interm, (char *) compiled);
      worker_expect(worker, worker->tmp_table, val, strlen(val));
      return worker_validate_expect(worker, worker->tmp_table, "EXPECT var", 
	                            APR_SUCCESS);
    }
    else {
      worker_log(worker, LOG_ERR, "Variable \"%s\" do not exist", var);
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
 * Close socket
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return an apr status
 */
apr_status_t command_CLOSE(command_t * self, worker_t * worker,
                                  char *data) {
  apr_status_t status;
  char *copy;
  int ssl = 1;

  COMMAND_OPTIONAL_ARG;

  if (strcmp(copy, "TCP") == 0) {
    ssl = 0;
  }

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
    worker_conn_close(worker, 1);
    return status;
  }

  if (strcmp(copy, "do not test expects") != 0) {
    if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
      worker_conn_close(worker, 1);
      return status;
    }
  }

  if ((status = worker_conn_close(worker, ssl)) != APR_SUCCESS) {
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
                                    char *data) {
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
 * @param data IN "%s %s %s" type match variable
 *
 * @return an apr status
 */
apr_status_t command_MATCH(command_t * self, worker_t * worker,
                                  char *data) {
  char *last;
  char *type;
  char *match;
  char *vars;
  char *key;
  regex_t *compiled;
  const char *err;
  int off;
  char *copy;

  COMMAND_NEED_ARG("Type, regex and variable not specified");

  type = apr_strtok(copy, " ", &last);
  
  match = my_unescape(last, &last);
  
  vars = apr_strtok(NULL, "", &last);

  if (!type) {
    worker_log(worker, LOG_ERR, "Type not specified");
    return APR_EGENERAL;
  }

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

  key = apr_pstrdup(worker->pool, vars);

  if (!(compiled = pregcomp(worker->pool, match, &err, &off))) {
    worker_log(worker, LOG_ERR, "MATCH regcomp failed: %s", last);
    return APR_EINVAL;
  }
  if (strcmp(type, ".") == 0) {
    apr_table_addn(worker->match.dot, key, (char *) compiled);
  }
  else if (strcasecmp(type, "Headers") == 0) {
    apr_table_addn(worker->match.headers, key, (char *) compiled);
  }
  else if (strcasecmp(type, "Body") == 0) {
    apr_table_addn(worker->match.body, key, (char *) compiled);
  }
  else if (strcasecmp(type, "Error") == 0) {
    apr_table_addn(worker->match.error, key, (char *) compiled);
  }
  else if (strcasecmp(type, "Exec") == 0) {
    apr_table_addn(worker->match.exec, key, (char *) compiled);
  }
  else if (strncasecmp(type, "Var(", 4) == 0) {
    const char *val;
    char *var;
    
    var= apr_strtok(type, "(", &last);
    var = apr_strtok(NULL, ")", &last);
    val = varget(worker, var);
    if (val) {
      if (!worker->tmp_table) {
	worker->tmp_table = apr_table_make(worker->pool, 1);
      }
      apr_table_clear(worker->tmp_table);
      apr_table_addn(worker->tmp_table, key, (char *) compiled);
      worker_match(worker, worker->tmp_table, val, strlen(val));
      return worker_validate_match(worker, worker->tmp_table, "MATCH var", 
	                           APR_SUCCESS);
    }
    else {
      /* this should cause an error? */
    }
  }
  else {
    worker_log(worker, LOG_ERR, "Match type %s do not exist", type);
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
                          char *data) {
  char *last;
  char *type;
  char *grep;
  char *vars;
  char *key;
  regex_t *compiled;
  const char *err;
  int off;
  char *copy;

  COMMAND_NEED_ARG("Type, regex and variable not specified");

  type = apr_strtok(copy, " ", &last);
  
  grep = my_unescape(last, &last);
  
  vars = apr_strtok(NULL, "", &last);

  if (!type) {
    worker_log(worker, LOG_ERR, "Type not specified");
    return APR_EGENERAL;
  }

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

  key = apr_pstrdup(worker->pool, vars);

  if (!(compiled = pregcomp(worker->pool, grep, &err, &off))) {
    worker_log(worker, LOG_ERR, "MATCH regcomp failed: %s", last);
    return APR_EINVAL;
  }
  if (strcmp(type, ".") == 0) {
    apr_table_addn(worker->grep.dot, key, (char *) compiled);
  }
  else if (strcasecmp(type, "Headers") == 0) {
    apr_table_addn(worker->grep.headers, key, (char *) compiled);
  }
  else if (strcasecmp(type, "Body") == 0) {
    apr_table_addn(worker->grep.body, key, (char *) compiled);
  }
  else if (strcasecmp(type, "Error") == 0) {
    apr_table_addn(worker->grep.error, key, (char *) compiled);
  }
  else if (strcasecmp(type, "Exec") == 0) {
    apr_table_addn(worker->grep.exec, key, (char *) compiled);
  }
  else if (strncasecmp(type, "Var(", 4) == 0) {
    const char *val;
    char *var;
    
    var= apr_strtok(type, "(", &last);
    var = apr_strtok(NULL, ")", &last);
    val = varget(worker, var);
    if (val) {
      if (!worker->tmp_table) {
	worker->tmp_table = apr_table_make(worker->pool, 1);
      }
      apr_table_clear(worker->tmp_table);
      apr_table_addn(worker->tmp_table, key, (char *) compiled);
      worker_match(worker, worker->tmp_table, val, strlen(val));
    }
    else {
      /* this should cause an error? */
    }
  }
  else {
    worker_log(worker, LOG_ERR, "Grep type %s do not exist", type);
    return APR_ENOENT;
  }

  return APR_SUCCESS;
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
apr_status_t command_SET(command_t * self, worker_t * worker,
                                char *data) {
  char *vars_last;
  const char *vars_key;
  const char *vars_val;
  char *copy;
  int i;

  COMMAND_NEED_ARG("Variable and value not specified");
  
  vars_key = apr_strtok(copy, "=", &vars_last);
  for (i = 0; vars_key[i] != 0 && strchr(VAR_ALLOWED_CHARS, vars_key[i]); i++); 
  if (vars_key[i] != 0) {
    worker_log(worker, LOG_ERR, "Char '%c' is not allowed in \"%s\"", vars_key[i], vars_key);
    return APR_EINVAL;
  }

  vars_val = apr_strtok(NULL, "", &vars_last);

  if (!vars_key) {
    worker_log(worker, LOG_ERR, "Key not specified");
    return APR_EGENERAL;
  }

  if (!vars_val) {
    worker_log(worker, LOG_ERR, "Value not specified");
    return APR_EGENERAL;
  }
  
  varset(worker, vars_key, vars_val);

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
                                 char *data) {
  char *copy;

  if (!worker->socket || !worker->socket->socket) {
    return APR_ENOSOCKET;
  }
    
  copy = apr_pstrdup(worker->pcmd, data); 
  copy = worker_replace_vars(worker, worker->pcmd, copy);
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
  else {
    apr_table_add(worker->cache, "TRUE", copy);
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
                                  char *data) {
  apr_status_t status;

  COMMAND_NO_ARG;

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
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
                                  char *data) {
  apr_status_t status;

  COMMAND_NO_ARG;

  apr_table_add(worker->cache, "CHUNKED", "CHUNKED");

  if ((status = worker_flush(worker)) != APR_SUCCESS) {
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
apr_status_t worker_file_to_http(worker_t *self, apr_file_t *file, int flags) {
  apr_status_t status;
  apr_size_t len;
  char *buf;

  while (1) {
    if (flags & FLAGS_CHUNKED) {
      len = self->chunksize;
    }
    else {
      len = BLOCK_MAX;
    }
    buf = apr_pcalloc(self->pcache, len + 1);
    if ((status = apr_file_read(file, buf, &len)) != APR_SUCCESS) {
      break;
    }
    buf[len] = 0;
    apr_table_addn(self->cache, 
		   apr_psprintf(self->pcache, "NOCRLF:%d", len), buf);
    if (flags & FLAGS_CHUNKED) {
      worker_log(self, LOG_DEBUG, "--- chunk size: %d", len);
      apr_table_add(self->cache, "CHUNKED", "CHUNKED");
      if ((status = worker_flush(self)) != APR_SUCCESS) {
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
                                 char *data) {
  char *copy;
  apr_status_t status;
  apr_procattr_t *attr;
  bufreader_t *br;
  const char *progname;
  char **args;
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

  if ((status = apr_tokenize_to_argv(copy, &args, worker->pbody)) 
      != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Could not tokenize the command line");
    return status;
  }

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

  if ((status = apr_proc_create(&worker->proc, progname, (const char **)args, NULL, attr,
                                worker->pbody)) != APR_SUCCESS) {
    return status;
  }

  if (flags & FLAGS_PIPE) {
    worker_log(worker, LOG_DEBUG, "write stdout to http: %s", progname);
    if ((status = worker_file_to_http(worker, worker->proc.out, flags)) != APR_SUCCESS) {
      return status;
    }
  }
  else if (!(worker->flags & FLAGS_PIPE_IN) && !(worker->flags & FLAGS_FILTER)) {
    apr_size_t len = 0;
    char *buf = NULL;

    worker_log(worker, LOG_DEBUG, "read stdin: %s", progname);
    if ((status = bufreader_new(&br, worker->proc.out, worker->pbody)) == APR_SUCCESS) {
      bufreader_read_eof(br, &buf, &len);
      if (buf) {
	worker_log(worker, LOG_INFO, "<%s", buf);
	worker_match(worker, worker->match.exec, buf, len);
	worker_match(worker, worker->grep.exec, buf, len);
	worker_expect(worker, worker->expect.exec, buf, len);
      }
    }

    if (buf && status == APR_EOF) {
	worker_log(worker, LOG_INFO, "<%s", buf);
	worker_match(worker, worker->match.exec, buf, len);
	worker_match(worker, worker->grep.exec, buf, len);
	worker_expect(worker, worker->expect.exec, buf, len);
    }
    
    status = APR_SUCCESS;
    status = worker_validate_match(worker, worker->match.exec, "MATCH exec", 
	                           status);
    status = worker_validate_expect(worker, worker->expect.exec, "EXPECT exec", 
	                            status);
  }

  if (!(worker->flags & FLAGS_PIPE_IN) && !(worker->flags & FLAGS_FILTER)) {
    worker_log(worker, LOG_DEBUG, "wait for: %s", progname);
    apr_proc_wait(&worker->proc, &exitcode, &exitwhy, APR_WAIT);

    apr_file_close(worker->proc.out);

    if (exitcode != 0) {
      status = APR_EGENERAL;
    }
  }

  return status;
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
                                     char *data) {
  char *copy;
  char *last;
  char *filename;
  apr_status_t status;
  int flags;
  apr_file_t *fp;

  COMMAND_NEED_ARG("Need a file name");

  filename = apr_strtok(copy, " ", &last);

  flags = worker->flags;
  worker->flags &= ~FLAGS_PIPE;
  worker->flags &= ~FLAGS_CHUNKED;
  
  if ((status =
       apr_file_open(&fp, filename, APR_READ, APR_OS_DEFAULT,
		     worker->pcmd)) != APR_SUCCESS) {
    fprintf(stderr, "\nCan not send file: File \"%s\" not found", copy);
    return APR_ENOENT;
  }
  
  if (flags & FLAGS_PIPE) {
    if ((status = worker_file_to_http(worker, fp, flags)) != APR_SUCCESS) {
      return status;
    }
  }

  apr_file_close(fp);

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
                                 char *data) {
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
                                   char *data) {
  char *copy;

  copy = apr_pstrdup(worker->pcmd, data); 
  copy = worker_replace_vars(worker, worker->pcmd, copy);
  worker_log(worker, LOG_CMD, "%s%s", self->name, copy); 

  apr_table_add(worker->cache, "NOCRLF", copy);

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
                                      char *data) {
  char *copy;

  COMMAND_NEED_ARG("Need a variable name");

  if (worker_sockstate(worker) == APR_SUCCESS) {
    varset(worker, copy, "CONNECTED");
  }
  else {
    varset(worker, copy, "CLOSED");
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
apr_status_t command_HEADER(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *method;
  char *header;
  char *last;

  COMMAND_NEED_ARG("Need method ALLOW or FILTER and a header name");

  method = apr_strtok(copy, " ", &last);
  header = apr_strtok(NULL, " ", &last);
  
  if (strcasecmp(method, "ALLOW") == 0) {
    if (!worker->headers_allow) {
      worker->headers_allow = apr_table_make(worker->pool, 10);
    }
    apr_table_add(worker->headers_allow, header, method);
  }
  else if (strcasecmp(method, "FILTER") == 0) {
    if (!worker->headers_filter) {
      worker->headers_filter = apr_table_make(worker->pool, 5);
    }
    apr_table_add(worker->headers_filter, header, method);
  }
  else {
    return APR_ENOTIMPL;
  }

  return APR_SUCCESS;
}

/**
 * RAND command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN header name (spaces are possible) 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_RAND(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *val;
  char *last;
  int start;
  int end;
  int result;

  COMMAND_NEED_ARG("Need a start and end number and a variable"); 
  
  val = apr_strtok(copy, " ", &last);
  start = apr_atoi64(val);
  val = apr_strtok(NULL, " ", &last);
  end = apr_atoi64(val);
  val = apr_strtok(NULL, " ", &last);

  if (val == NULL) {
    worker_log(worker, LOG_ERR, "No variable name specified");
    return APR_EINVAL;
  }
  
  result = start + (rand() % (end - start)); 

  varset(worker, val, apr_itoa(worker->pool, result));

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
apr_status_t command_DEBUG(command_t *self, worker_t *worker, char *data) {
  char *copy;
  
  COMMAND_OPTIONAL_ARG;

  worker_log(worker, LOG_ERR, "%s", copy);

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
  apr_sockaddr_t *local_addr;

  apr_status_t status = APR_SUCCESS;

  worker_get_socket(worker, "Default", "0");
  
  if (worker->listener) {
    worker_log_error(worker, "Server allready up");
    return APR_EGENERAL;
  }

  if ((status = apr_sockaddr_info_get(&local_addr, worker->listener_addr, APR_UNSPEC,
                                      worker->listener_port, APR_IPV4_ADDR_OK, worker->pool))
      != APR_SUCCESS) {
    goto error;
  }

  if ((status = apr_socket_create(&worker->listener, local_addr->family, SOCK_STREAM,
                                  APR_PROTO_TCP, worker->pool)) != APR_SUCCESS)
  {
    worker->listener = NULL;
    goto error;
  }

  status = apr_socket_opt_set(worker->listener, APR_SO_REUSEADDR, 1);
  if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
    goto error;
  }
  
  worker_log(worker, LOG_DEBUG, "--- bind");
  if ((status = apr_socket_bind(worker->listener, local_addr)) != APR_SUCCESS) {
    goto error;
  }

  worker_log(worker, LOG_DEBUG, "--- listen");
  if ((status = apr_socket_listen(worker->listener, backlog)) != APR_SUCCESS) {
    goto error;
  }

  worker->socket->socket_state = SOCKET_CLOSED;

error:
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
apr_status_t command_UP(command_t *self, worker_t *worker, char *data) {
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
apr_status_t command_DOWN(command_t *self, worker_t *worker, char *data) {
  apr_status_t status;

  COMMAND_NO_ARG;

  if (!worker->listener) {
    worker_log_error(worker, "Server allready down", self->name);
    return APR_EGENERAL;
  }
  
  if ((status = apr_socket_close(worker->listener)) != APR_SUCCESS) {
    return status;
  }
  worker->listener = NULL;
  return status;
}

/**
 * TIME command stores time in a variable [ms]
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN variable name 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_TIME(command_t *self, worker_t *worker, char *data) {
  char *copy;

  COMMAND_NEED_ARG("Need a variable name to store time");
  
  varset(worker, copy, apr_off_t_toa(worker->pool, apr_time_as_msec(apr_time_now())));

  return APR_SUCCESS;
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
apr_status_t command_LOG_LEVEL(command_t *self, worker_t *worker, char *data) {
  char *copy;

  COMMAND_NEED_ARG("Need a number between 0 and 4");

  worker->log_mode = apr_atoi64(copy);

  return APR_SUCCESS;
}

/**
 * SYNC command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
apr_status_t command_SYNC(command_t *self, worker_t *worker, char *data) {
  apr_time_t sec;
  apr_time_t nxt_sec;
  apr_time_t now;

  /* get current time */
  now = apr_time_now();
  /* get next second */
  sec = apr_time_sec(now) + 1;
  /* next second in us */
  nxt_sec = apr_time_from_sec(sec);
  /* sleep until next sec */
  apr_sleep(nxt_sec - now);
  
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
apr_status_t command_RECV(command_t *self, worker_t *worker, char *data) {
  char *copy;
  apr_pool_t *pool;
  apr_status_t status;
  apr_size_t recv_len;
  apr_size_t peeklen;
  sockreader_t *sockreader;
  char *buf;
  char *last;
  char *val;

  int poll = 0;

  COMMAND_NEED_ARG("Need a number or POLL");

  /* get first value, can be either POLL or a number */
  val = apr_strtok(copy, " ", &last);
  if (strcasecmp(val, "POLL") == 0) {
    poll = 1;
    /* recv_len to max and timeout to min */
    recv_len = BLOCK_MAX;
    /* set timout to specified socket tmo */
    if ((status =
           apr_socket_timeout_set(worker->socket->socket, worker->socktmo)) 
	!= APR_SUCCESS) {
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

  apr_pool_create(&pool, NULL);

  if (worker->sockreader == NULL) {
    peeklen = worker->socket->peeklen;
    worker->socket->peeklen = 0;
    if ((status = sockreader_new(&sockreader, worker->socket->socket,
#ifdef USE_SSL
				 worker->socket->is_ssl ? worker->socket->ssl : NULL,
#endif
				 worker->socket->peek, peeklen, pool)) != APR_SUCCESS) {
      goto out_err;
    }
  }
  else {
    sockreader = worker->sockreader;
  }

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

  if ((status = worker_handle_buf(worker, pool, buf, recv_len)) 
      != APR_SUCCESS) {
    goto out_err;
  }

out_err:
  if (strcasecmp(last, "DO_NOT_CHECK") != 0) {
    status = worker_check_expect(worker, status);
  }
  apr_pool_destroy(pool);

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
apr_status_t command_READLINE(command_t *self, worker_t *worker, char *data) {
  apr_pool_t *pool;
  apr_status_t status;
  apr_size_t peeklen;
  apr_size_t len;
  sockreader_t *sockreader;
  char *buf;
  char *copy;

  COMMAND_OPTIONAL_ARG;

  apr_pool_create(&pool, NULL);

  if (worker->sockreader == NULL) {
    peeklen = worker->socket->peeklen;
    worker->socket->peeklen = 0;
    if ((status = sockreader_new(&sockreader, worker->socket->socket,
#ifdef USE_SSL
				 worker->socket->is_ssl ? worker->socket->ssl : NULL,
#endif
				 worker->socket->peek, peeklen, pool)) != APR_SUCCESS) {
      goto out_err;
    }
  }
  else {
    sockreader = worker->sockreader;
  }

  if ((status = sockreader_read_line(sockreader, &buf)) != APR_SUCCESS) {
    goto out_err;
  }

  if (buf) {
    len = strlen(buf);
    if ((status = worker_handle_buf(worker, pool, buf, len)) 
	!= APR_SUCCESS) {
      goto out_err;
    }
  }

out_err:
  if (strcasecmp(copy, "DO_NOT_CHECK") != 0) {
    status = worker_check_expect(worker, status);
  }
  apr_pool_destroy(pool);

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
apr_status_t command_CHECK(command_t *self, worker_t *worker, char *data) {
  apr_status_t status = worker_check_expect(worker, APR_SUCCESS);
  return status;
}

/**
 * OP command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN left op right var
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_OP(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *last;
  char *left;
  char *op;
  char *right;
  char *var;
  apr_int64_t ileft;
  apr_int64_t iright;
  apr_int64_t result;

  COMMAND_NEED_ARG("<left> ADD|SUB|MUL|DIV <right> <variable> expected");

  /* split into left, op, right, var */
  left = apr_strtok(copy, " ", &last);
  op = apr_strtok(NULL, " ", &last);
  right = apr_strtok(NULL, " ", &last);
  var = apr_strtok(NULL, " ", &last);

  /* do checks */
  if (!left || !op || !right || !var) {
    worker_log(worker, LOG_ERR, "<left> ADD|SUB|MUL|DIV <right> <variable> expected", copy);
    return APR_EINVAL;
  }

  /* get integer value */
  ileft = apr_atoi64(left);
  iright = apr_atoi64(right);

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
  varset(worker, var, apr_off_t_toa(worker->pool, result));
  
  return APR_SUCCESS;
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
apr_status_t command_WHICH(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *result;

  COMMAND_NEED_ARG("<variable> expected");
 
  result  = apr_psprintf(worker->pool, "%d", worker->which);
  varset(worker, copy, result);
  
  return APR_SUCCESS;
}

/**
 * CERT command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN cert, key and optional ca file
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_CERT(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *last;

  COMMAND_NEED_ARG("<cert-file> <key-file> [<ca-file>]");
  
  if (worker->ssl_ctx) {
    char *cert;
    char *key;
    char *ca;

    cert = apr_strtok(copy, " ", &last);
    key = apr_strtok(NULL, " ", &last);
    ca = apr_strtok(NULL, " ", &last);
    worker_ssl_ctx(worker, cert, key, ca, 1);
  }
  else {
    worker_log(worker, LOG_ERR, "Can not set cert, ssl not enabled in CLIENT/SERVER");
    return APR_EINVAL;
  }
  
  return APR_SUCCESS;
}

/**
 * verify callback for peer cert verification for debugging purpose
 * @param cur_ok IN current ok state
 * @param ctx IN X509 store context
 */
int debug_verify_callback(int cur_ok, X509_STORE_CTX *ctx) {
  char buf[256];
  X509 *err_cert;
  int err, depth;

  err_cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);

  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
  fprintf(stdout, "\nverify error:num=%d:%s:depth=%d:%s",
	  err, X509_verify_cert_error_string(err), depth, buf);
  return cur_ok;
}

/**
 * VERIFY_PEER command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_VERIFY_PEER(command_t *self, worker_t *worker, char *data) {
  return command_RENEG(self, worker, "verify");
}

/**
 * RENEG command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_RENEG(command_t *self, worker_t *worker, char *data) {
#ifdef USE_SSL
  int rc;
  char *copy;

  if (worker->foreign_cert) {
    X509_free(worker->foreign_cert);
  }
  
  worker->foreign_cert = NULL;

  COMMAND_OPTIONAL_ARG;

  if (!worker->socket->is_ssl || !worker->socket->ssl) {
    worker_log(worker, LOG_ERR, 
	       "No ssl connection established can not verify peer");
    return APR_ENOSOCKET;
  }

  if (worker->flags & FLAGS_SERVER) {
    if (strcasecmp(copy, "verify") == 0) {
      /* if we are server request the peer cert */
      if (worker->log_mode >= LOG_DEBUG) {
	SSL_set_verify(worker->socket->ssl,
		       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		       debug_verify_callback);
      }
      else {
	SSL_set_verify(worker->socket->ssl,
		       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		       NULL);
      }
    }

    if (worker->flags & FLAGS_SSL_LEGACY) {
#if (OPENSSL_VERSION_NUMBER >= 0x009080cf)
#ifdef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
      worker->socket->ssl->s3->flags |= SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
#else
      SSL_set_options(worker->socket->ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif
#endif
    }

    if((rc = SSL_renegotiate(worker->socket->ssl) <= 0)) {
      worker_log(worker, LOG_ERR, "SSL renegotiation a error: %d", rc);
      return APR_EACCES;
    }
    worker_ssl_handshake(worker);
    worker->socket->ssl->state=SSL_ST_ACCEPT;
    worker_ssl_handshake(worker);

    if (strcasecmp(copy, "verify") == 0) {
      worker->foreign_cert = SSL_get_peer_certificate(worker->socket->ssl);
      if (!worker->foreign_cert) {
	worker_log(worker, LOG_ERR, "No peer certificate");
	return APR_EACCES;
      }
    }
  }
  else {
    if (strcasecmp(copy, "verify") == 0) {
      worker->foreign_cert = SSL_get_peer_certificate(worker->socket->ssl);
      if (!worker->foreign_cert) {
	worker_log(worker, LOG_ERR, "No peer certificate");
	return APR_EACCES;
      }

      if((rc = SSL_get_verify_result(worker->socket->ssl)) != X509_V_OK) {
	worker_log(worker, LOG_ERR, "SSL peer verify failed: %s(%d)",
	X509_verify_cert_error_string(rc), rc);
	return APR_EACCES;
      }
    }
  }
#endif

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
apr_status_t command_ONLY_PRINTABLE(command_t *self, worker_t *worker, char *data) {
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
apr_status_t command_PRINT_HEX(command_t *self, worker_t *worker, char *data) {
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
apr_status_t command_SH(command_t *self, worker_t *worker, char *data) {
  char *copy;
  apr_size_t len;
  char *name;
  char *old;

  apr_status_t status = APR_SUCCESS;
  
  COMMAND_NEED_ARG("Either shell commands or END");

  if (strcasecmp(copy, "END")== 0) {
    if (worker->tmpf) {
      /* get file name */
      if ((status = apr_file_name_get((const char **)&name, worker->tmpf)) != APR_SUCCESS) {
	return status;
      }

      if ((status = apr_file_perms_set(name, 0x700)) != APR_SUCCESS) {
	return status;
      }

      /* close file */
      apr_file_close(worker->tmpf);
      worker->tmpf = NULL;

      /* exec file */
      old = self->name;
      self->name = apr_pstrdup(worker->pcmd, "_EXEC"); 
      status = command_EXEC(self, worker, apr_pstrcat(worker->pcmd, "./", name, NULL));
      self->name = old;
      
      apr_file_remove(name, worker->pcmd);
    }
  }
  else {
    if (!worker->tmpf) {
      name = apr_pstrdup(worker->pcmd, "httXXXXXX");
      if ((status = apr_file_mktemp(&worker->tmpf, name, 
	                            APR_CREATE | APR_READ | APR_WRITE | 
				    APR_EXCL, 
				    worker->pbody))
	  != APR_SUCCESS) {
	worker_log(worker, LOG_ERR, "Could not mk temp file %s(%d)", 
	           my_status_str(worker->pool, status), status);
	return status;
      }
    }
    
    len = strlen(copy);
    if ((status = file_write(worker->tmpf, copy, len)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not write to temp file");
      return status;
    }
    len = 1;
    if ((status = file_write(worker->tmpf, "\n", len)) != APR_SUCCESS) {
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
apr_status_t command_ADD_HEADER(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *header;
  char *value;

  COMMAND_NEED_ARG("<header> <value>");

  if (!worker->headers_add) {
    worker->headers_add = apr_table_make(worker->pool, 12);
  }

  header = apr_strtok(copy, " ", &value);
  apr_table_add(worker->headers_add, header, value);

  return APR_SUCCESS;
}

/**
 * DETACH command to run process in background
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_DETACH(command_t *self, worker_t *worker, char *data) {
  return apr_proc_detach(1);
}

/**
 * PID command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN variable
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_PID(command_t *self, worker_t *worker, char *data) {
  char *copy;

  COMMAND_NEED_ARG("<variable>");

  varset(worker, copy, apr_psprintf(worker->pool, "%u", getpid()));
  
  return APR_SUCCESS;
}

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

/**
 * URLENC command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN string and variable name
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t command_URLENC(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *string;
  char *result;
  char *last;
  char *var;
  int i;
  int j;
  int k;
  apr_size_t len;

  COMMAND_NEED_ARG("\"<string>\" <variable>");

  string = my_unescape(copy, &last);
  var = apr_strtok(NULL, "", &last);
  if (!var) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }
  apr_collapse_spaces(var, var);

  len = strlen(string);
  /* allocate worste case -> every char enc with pattern %XX */
  result = apr_pcalloc(worker->pcmd, 3 * len + 1);

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

  varset(worker, var, result);

  return APR_SUCCESS;
}

/**
 * URLDEC command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN string and variable name
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t command_URLDEC(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *string;
  char *last;
  char *var;
  char c;
  int i;
  int j;
  apr_size_t len;
  char *inplace;

  COMMAND_NEED_ARG("\"<string>\" <variable>");

  string = my_unescape(copy, &last);
  var = apr_strtok(NULL, "", &last);
  if (!var) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }
  apr_collapse_spaces(var, var);

  inplace = string;
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

  varset(worker, var, inplace);

  return APR_SUCCESS;
}

/**
 * HTMLDEC command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN string and variable name
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t command_HTMLDEC(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *string;
  char *last;
  char *var;
  char c;
  int i;
  int j;
  apr_size_t len;
  char *inplace;

  COMMAND_NEED_ARG("\"<string>\" <variable>");

  string = my_unescape(copy, &last);
  var = apr_strtok(NULL, "", &last);
  if (!var) {
      worker_log(worker, LOG_ERR, "Variable not specified");
      return APR_EGENERAL;
    }
  apr_collapse_spaces(var, var);

  inplace = string;
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

  varset(worker, var, inplace);

  return APR_SUCCESS;
}

/**
 * B64ENC command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN string and variable name
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t command_B64ENC(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *string;
  char *last;
  char *var;
  apr_size_t len;
  char *base64;

  COMMAND_NEED_ARG("\"<string>\" <variable>");

  string = my_unescape(copy, &last);
  var = apr_strtok(NULL, "", &last);
  if (!var) {
      worker_log(worker, LOG_ERR, "Variable not specified");
      return APR_EGENERAL;
    }
  apr_collapse_spaces(var, var);

  len = apr_base64_encode_len(strlen(string));
  base64 = apr_pcalloc(worker->pcmd, len + 1);
  apr_base64_encode(base64, string, strlen(string));
  
  varset(worker, var, base64);

  return APR_SUCCESS;
}

/**
 * BASE64DEC command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN string and variable name
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t command_B64DEC(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *string;
  char *last;
  char *var;
  apr_size_t len;
  char *plain;

  COMMAND_NEED_ARG("\"<string>\" <variable>");

  string = my_unescape(copy, &last);
  var = apr_strtok(NULL, "", &last);
  if (!var) {
      worker_log(worker, LOG_ERR, "Variable not specified");
      return APR_EGENERAL;
    }
  apr_collapse_spaces(var, var);

  len = apr_base64_decode_len(string);
  plain = apr_pcalloc(worker->pcmd, len + 1);
  apr_base64_decode(plain, string);
  
  varset(worker, var, plain);

  return APR_SUCCESS;
}

/**
 * STRFTIME command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN time [ms] "format" variable
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t command_STRFTIME(command_t *self, worker_t *worker, char *data) {
  apr_status_t status;
  char *copy;
  char *time;
  char *fmt;
  char *var;
  char *type;
  char *last;
  char *timefmt;
  apr_size_t len;
  apr_time_exp_t  tm;
  apr_time_t timems;

  COMMAND_NEED_ARG("<time> \"<format>\" <variable> [Local|GMT]");

  time = apr_strtok(copy, " ", &last);
  fmt = my_unescape(last, &last);
  var = apr_strtok(NULL, " ", &last);
  type = apr_strtok(NULL, " ", &last);

  if (!time) {
    worker_log(worker, LOG_ERR, "Time not specified");
    return APR_EGENERAL;
  }
  if (!fmt) {
    worker_log(worker, LOG_ERR, "Format not specified");
    return APR_EGENERAL;
  }
  if (!var) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }
  apr_collapse_spaces(var, var);

  timems = apr_atoi64(time);
  
  timefmt = apr_pcalloc(worker->pcmd, 255);
  
  if (type && strncasecmp(type, "Local", 5) == 0) {
    if ((status = apr_time_exp_lt(&tm, timems * 1000)) != APR_SUCCESS) { 
      return status;
    }
  }
  else {
    if ((status = apr_time_exp_gmt(&tm, timems * 1000)) != APR_SUCCESS) { 
      return status;
    }
  }
  
  if ((status = apr_strftime(timefmt, &len, 254, fmt, &tm)) != APR_SUCCESS) {
    return status;
  }

  varset(worker, var, timefmt);
  
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
apr_status_t command_TUNNEL(command_t *self, worker_t *worker, char *data) {
  apr_status_t status;
  apr_status_t rc;
  apr_threadattr_t *tattr;
  apr_thread_t *client_thread;
  apr_thread_t *backend_thread;
  tunnel_t client;
  tunnel_t backend;
  apr_size_t peeklen;

  if (!(worker->flags & FLAGS_SERVER)) {
    worker_log_error(worker, "This command is only valid in a SERVER");
    return APR_EGENERAL;
  }

  if (worker->socket->socket_state == SOCKET_CLOSED) {
    worker_log_error(worker, "Socket to client is closed\n");
    return APR_ECONNREFUSED;
  }

  worker_log(worker, LOG_DEBUG, "--- tunnel\n");

  apr_pool_create(&client.pool, NULL);
  apr_pool_create(&backend.pool, NULL);

  /* client side */
  if ((status = apr_socket_timeout_set(worker->socket->socket, 100000)) 
      != APR_SUCCESS) {
    goto error1;
  }
  if (worker->sockreader == NULL) {
    peeklen = worker->socket->peeklen;
    worker->socket->peeklen = 0;
    sockreader_new(&client.sockreader, worker->socket->socket,
#ifdef USE_SSL
		   worker->socket->is_ssl ? worker->socket->ssl : NULL,
#endif
		   worker->socket->peek, peeklen, client.pool);
    if (status != APR_SUCCESS && !APR_STATUS_IS_TIMEUP(status)) {
      goto error1;
    }
  }
  else {
    client.sockreader = worker->sockreader;
  }
  backend.sendto = worker->socket;

  /* backend side */
  if ((status = command_REQ(self, worker, data)) != APR_SUCCESS) {
    goto error1;
  }
  if ((status = apr_socket_timeout_set(worker->socket->socket, 100000)) 
      != APR_SUCCESS) {
    goto error2;
  }
  sockreader_new(&backend.sockreader, worker->socket->socket,
#ifdef USE_SSL
		 worker->socket->is_ssl ? worker->socket->ssl : NULL,
#endif
		 NULL, 0, backend.pool);
  if (status != APR_SUCCESS && !APR_STATUS_IS_TIMEUP(status)) {
    goto error2;
  }
  client.sendto = worker->socket;

  /* need two threads reading/writing from/to backend */
  if ((status = apr_threadattr_create(&tattr, worker->pool)) != APR_SUCCESS) {
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
	                          &client, worker->pool)) != APR_SUCCESS) {
    goto error2;
  }

  if ((status = apr_thread_create(&backend_thread, tattr, streamer, 
	                          &backend, worker->pool)) != APR_SUCCESS) {
    goto error2;
  }

  rc = apr_thread_join(&status, client_thread);
  if (status != APR_SUCCESS) {
    goto error2;
  }
  rc = apr_thread_join(&status, backend_thread);
  if (status != APR_SUCCESS) {
    goto error2;
  }

error2:
  command_CLOSE(self, worker, "do not test expects");
error1:
  worker_get_socket(worker, "Default", "0");
  apr_pool_destroy(client.pool);
  apr_pool_destroy(backend.pool);
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
apr_status_t command_BREAK(command_t *self, worker_t *worker, char *data) {
  /* singal break for loop */
  COMMAND_NO_ARG;
  return -1;
}

/**
 * TIMER command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN variable name
 *
 * @return APR_SUCCESS
 */
apr_status_t command_TIMER(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *last;
  char *cmd;
  char *var;

  apr_time_t cur = apr_time_now();

  COMMAND_NEED_ARG("<variable> expected");
  cmd = apr_strtok(copy, " ", &last);
  var = apr_strtok(NULL, " ", &last);
 
  if (strcasecmp(cmd, "GET") == 0) {
    /* nothing special to do */
  }
  else if (strcasecmp(cmd, "RESET") == 0) {
    worker->start_time = apr_time_now();
  }
  else {
    worker_log_error(worker, "Timer command %s not implemented", cmd);
  }

  if (var && var[0] != 0) {
    varset(worker, var, 
		  apr_off_t_toa(worker->pool, apr_time_as_msec(cur - worker->start_time)));
  }
  return APR_SUCCESS;
}

/**
 * SSL_LEGACY command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_SSL_LEGACY(command_t *self, worker_t *worker, char *data) {
#ifdef USE_SSL
   char *copy;

  COMMAND_NEED_ARG("on|off");
 
  if (strcasecmp(copy,  "on") == 0) {
    worker->flags |= FLAGS_SSL_LEGACY;
  }
  else {
    worker->flags &= ~FLAGS_SSL_LEGACY;
  }
#endif
  return APR_SUCCESS;
}

/**
 * SSL_SECURE_RENEG_SUPPORTED command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_SSL_SECURE_RENEG_SUPPORTED(command_t *self, worker_t *worker, char *data) {
#if (define USE_SSL && OPENSSL_VERSION_NUMBER >= 0x009080ff)
   char *copy;

  COMMAND_NEED_ARG("variable");
  if (SSL_get_secure_renegotiation_support(worker->socket->ssl)) {
    return APR_SUCCESS;
  }
  else {
    return APR_EINVAL;
  }
#else
  return APR_EINVAL;
#endif
}

/**
 * SSL_SECURE_RENEG_SUPPORTED command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_SSL_ENGINE(command_t *self, worker_t *worker, char *data) {
#ifdef USE_SSL
#ifndef OPENSSL_NO_ENGINE
  char *copy;
  BIO *bio_err = BIO_new_fp(stderr,BIO_NOCLOSE);

  COMMAND_NEED_ARG("<engine> openssl engine");

  if (!setup_engine(bio_err, copy, worker->log_mode == LOG_DEBUG ? 1 : 0)) {
    worker_log(worker, LOG_ERR, "Could not initialize engine \"%s\".", copy);
    return APR_EINVAL;
  }
#endif
#endif
  return APR_SUCCESS;
}

/**
 * SSL_SESSION_ID command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_SSL_SESSION_ID(command_t *self, worker_t *worker, char *data) {
  char *copy;
  SSL_SESSION *sess;
  char *val;

  COMMAND_NEED_ARG("<variable>");

  if (!worker->socket || !worker->socket->ssl) {
    worker_log_error(worker, "Need an ssl connection");
    return APR_ENOSOCKET;
  }

  sess = SSL_get_session(worker->socket->ssl);

  if (sess) {
    val = apr_pcalloc(worker->pool, apr_base64_encode_len(sess->session_id_length));
    apr_base64_encode_binary(val, sess->session_id, sess->session_id_length);

    varset(worker, copy, val);
  }
  else {
    return APR_ENOENT;
  }

  return APR_SUCCESS;
}

/**
 * SSL_CERT_VAL command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_SSL_CERT_VAL(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *last;
  char *cmd;
  char *var;
  char *val = NULL;

  COMMAND_NEED_ARG("<ssl variable> <variable>");

  cmd = apr_strtok(copy, " ", &last);
  var = apr_strtok(NULL, " ", &last);
  
  if (!worker->foreign_cert) {
    worker_log(worker, LOG_ERR, "no peer cert");
    return APR_EINVAL;
  }
  
  val = ssl_var_lookup_ssl_cert(worker->pcmd, worker->foreign_cert, cmd);

  if (!val) {
    worker_log(worker, LOG_ERR, "SSL value for \"%s\" not found", cmd);
    return APR_ENOENT;
  }

  varset(worker, var, val);

  return APR_SUCCESS;
}

/**
 * SSL_BUF_2_CERT command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_SSL_BUF_2_CERT(command_t *self, worker_t *worker, char *data) {
  char *copy;
  BIO *mem;
  COMMAND_NEED_ARG("<pem cert>");

  if (worker->foreign_cert) {
    X509_free(worker->foreign_cert);
  }
  
  mem = BIO_new_mem_buf(copy, strlen(copy));
  worker->foreign_cert = PEM_read_bio_X509(mem,NULL,NULL,NULL);

  if (!worker->foreign_cert) {
    worker_log_error(worker, "Not a valid cert (PEM)");
    return APR_EINVAL;
  }
  return APR_SUCCESS;
}

/**
 * SSL_USE_CERT command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
apr_status_t command_SSL_USE_CERT(command_t *self, worker_t *worker, char *data) {
  if (!worker->ssl_ctx) {
    worker_log_error(worker, "You are not in a ssl context");
    return APR_EINVAL;
  }

  if (!worker->foreign_cert) {
    worker_log_error(worker, "No cert to use, get a cert with _RENEG, _SSL_BUF_2_CERT");
    return APR_EINVAL;
  }

  if (SSL_CTX_use_certificate(worker->ssl_ctx, worker->foreign_cert) <=0) {
    worker_log_error(worker, "Can not use this cert");
    return APR_EINVAL;
  }
  return APR_SUCCESS;
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
apr_status_t command_AUTO_CLOSE(command_t *self, worker_t *worker, char *data) {
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
apr_status_t command_AUTO_COOKIE(command_t *self, worker_t *worker, char *data) {
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
 * PROC_WAIT command 
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN named process to wait for 
 *
 * @return APR_SUCCESS or apr error code
 * @note: only for unix systems
 */
#if APR_HAS_FORK
apr_status_t command_PROC_WAIT(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *var;
  char *last;
  apr_status_t status = APR_SUCCESS;

  COMMAND_NEED_ARG("<name>*");

  if (!worker->procs) {
    worker_log_error(worker, "No processes to wait for");
    return APR_EINVAL;
  }

  var = apr_strtok(copy, " ", &last);
  while (var) {
    int exitcode;
    apr_exit_why_e why;
    apr_proc_t *proc = apr_hash_get(worker->procs, var, APR_HASH_KEY_STRING);
    if (!proc) {
      worker_log_error(worker, "Process \"%s\" do not exist", var);
      return APR_EINVAL;
    }
    apr_proc_wait(proc, &exitcode, &why, APR_WAIT); 
    if (exitcode != 0) {
      worker_log_error(worker, "Process \"%s\" FAILED", var);
      status = APR_EINVAL;
    }
    var = apr_strtok(NULL, " ", &last);
  }

  return status;
}
#endif

/**
 * MARK command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN name of this mark
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_MARK(command_t *self, worker_t *worker, char *data) {
  /* lookup if Mark is allread set */
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
apr_status_t command_MATCH_SEQ(command_t *self, worker_t *worker, char *data) {
  char *copy;
  COMMAND_NEED_ARG("<var-sequence>*");
  worker->match_seq = apr_pstrdup(worker->pool, copy);
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
apr_status_t command_RECORD(command_t *self, worker_t *worker, char *data) {
  char *copy;
  COMMAND_NEED_ARG("RES [ALL] {STATUS|HEADERS|BODY}*");

  if (strncmp(copy, "RES", 3) != 0) {
    worker_log_error(worker, "Only response recording supported yet");
    return APR_EINVAL;
  }

  if (strstr(copy, "ALL")) {
    worker->recorder->flags = RECORDER_RECORD_ALL;
  }
  if (strstr(copy, "STATUS")) {
    worker->recorder->flags |= RECORDER_RECORD_STATUS;
  }
  if (strstr(copy, "HEADERS")) {
    worker->recorder->flags |= RECORDER_RECORD_HEADERS;
  }
  if (strstr(copy, "BODY")) {
    worker->recorder->flags |= RECORDER_RECORD_BODY;
  }

  /* start or restart recorder */
  if (!worker->recorder) { 
    worker->recorder = apr_pcalloc(worker->pbody, sizeof(recorder_t));
  }

  if (worker->recorder->on) {
    /* restart the recorder by dropping the sockreader pool */
    apr_pool_destroy(worker->recorder->pool);
  }

  apr_pool_create(&worker->recorder->pool, worker->pbody);

  /* setup a sockreader for recording */
  sockreader_new(&worker->recorder->sockreader, NULL, NULL, NULL, 0, 
                 worker->recorder->pool);

  worker->recorder->on = RECORDER_RECORD;

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
apr_status_t command_PLAY(command_t *self, worker_t *worker, char *data) {
  COMMAND_NO_ARG;
  /* if recorded data available do play back */
  if (worker->recorder->on == RECORDER_RECORD) {
    worker->recorder->on = RECORDER_PLAY;
  }
  else {
    worker_log_error(worker, "Can not play cause recorder is not in recording mode");
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
apr_status_t command_LOCAL(command_t *self, worker_t *worker, char *data) {
  char *copy;
  char *last;
  char *var;
  COMMAND_NEED_ARG("<var> (\" \" <var>)*");

  var = apr_strtok(copy, " ", &last);
  while (var) {
    apr_table_set(worker->locals, var, NULL);
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
apr_status_t command_USE(command_t *self, worker_t *worker, char *data) {
  char *copy;
  COMMAND_NEED_ARG("<module>");

  if (!(worker->blocks = apr_hash_get(worker->modules, copy, APR_HASH_KEY_STRING))) {
    worker_log_error(worker, "Could not finde module \"%s\"", copy);
    return APR_EINVAL;
  }

  return APR_SUCCESS;
}

/**
 * STORE_SSL_SESSION command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN <module>
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_SSL_GET_SESSION(command_t *self, worker_t *worker, char *data) {
  char *copy;
  COMMAND_NEED_ARG("<variable>");

  if (!worker->socket || !worker->socket->socket) {
    return APR_ENOSOCKET;
  }

#ifdef USE_SSL
  if (worker->socket->is_ssl) {
    if (worker->socket->ssl) {
      apr_size_t b64_len;
      char *b64_str;
      apr_size_t enc_len;
      unsigned char *enc;
      unsigned char *tmp;
      SSL_SESSION *sess = SSL_get_session(worker->socket->ssl);
      /* serialize to a variable an store it */
      enc_len = i2d_SSL_SESSION(sess, NULL);
      enc = apr_pcalloc(worker->pcmd, enc_len);
      tmp = enc;
      enc_len = i2d_SSL_SESSION(sess, &tmp);
      b64_len = apr_base64_encode_len(enc_len);
      b64_str = apr_pcalloc(worker->pbody, b64_len);
      apr_base64_encode_binary(b64_str, enc, enc_len);
      varset(worker, copy, b64_str);
    }
  }
#endif

  return APR_SUCCESS;
}

/**
 * SET_SSL_SESSION command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN <module>
 *
 * @return APR_SUCCESS or apr error code
 */
apr_status_t command_SSL_SET_SESSION(command_t *self, worker_t *worker, char *data) {
  char *copy;
  COMMAND_NEED_ARG("<base 64 encoded ssl session string>");

  if (!worker->socket) {
    return APR_ENOSOCKET;
  }

#ifdef USE_SSL
  {
    apr_size_t enc_len;
    unsigned char *enc;
    const unsigned char *tmp;
    const char *b64_str = copy;
    if (b64_str) {
      enc_len = apr_base64_decode_len(b64_str);
      enc = apr_pcalloc(worker->pcmd, enc_len);
      apr_base64_decode_binary(enc, b64_str);
      tmp = enc;
      worker->socket->sess = d2i_SSL_SESSION(NULL, &tmp, enc_len);
    }
    else {
      worker_log_error(worker, "Variable \"%s\" do not exist", copy);
      return APR_ENOENT;
    }
  }
#endif

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
apr_status_t command_IGNORE_BODY(command_t *self, worker_t *worker, char *data) {
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
    worker_log_error(worker, "Do not understand \"%s\"", copy);
    return APR_EINVAL;
  }
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
 * @return an apr status
 */
apr_status_t worker_new(worker_t ** self, char *additional,
                        char *prefix, global_t *global, 
			interpret_f interpret) {
  apr_pool_t *p;

  apr_pool_create(&p, NULL);
  (*self) = apr_pcalloc(p, sizeof(worker_t));
  (*self)->heartbeat = p;
  apr_pool_create(&p, (*self)->heartbeat);
  (*self)->pbody = p;
  apr_pool_create(&p, (*self)->heartbeat);
  (*self)->pool = p;
  apr_pool_create(&p, (*self)->heartbeat);
  (*self)->pcmd = p;
  apr_pool_create(&p, (*self)->heartbeat);
  (*self)->pcache = p;
  /* this stuff muss last until END so take pbody pool for this */
  p = (*self)->pbody;
  (*self)->config = apr_hash_make(p);
  (*self)->interpret = interpret;
  (*self)->filename = apr_pstrdup(p, "<none>");
  (*self)->socktmo = global->socktmo;
  (*self)->prefix = apr_pstrdup(p, prefix);
  (*self)->additional = apr_pstrdup(p, additional);
  (*self)->sync_cond = global->cond;
  (*self)->sync_mutex = global->sync;
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
  (*self)->recorder = apr_pcalloc(p, sizeof(recorder_t));
#if APR_HAS_FORK
  (*self)->procs = NULL;
#endif
  (*self)->headers_allow = NULL;
  (*self)->headers_filter = NULL;
  (*self)->params = apr_table_make(p, 4);
  (*self)->retvars = apr_table_make(p, 4);
  (*self)->locals = apr_table_make(p, 4);
  (*self)->vars = my_table_deep_copy(p, global->vars);
  (*self)->modules = global->modules;
  (*self)->blocks = global->blocks;
  (*self)->start_time = apr_time_now();
  (*self)->log_mode = global->log_mode;
  (*self)->flags = global->flags;
#ifdef USE_SSL
  (*self)->bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
  (*self)->bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
#endif
  (*self)->listener_addr = apr_pstrdup(p, APR_ANYADDR);

  apr_table_add((*self)->vars, "__LOG_LEVEL", apr_itoa((*self)->pool, 
	        global->log_mode));
  
  worker_log(*self, LOG_DEBUG, "worker_new: pool: %p, pcmd: %p\n", (*self)->pool, (*self)->pcmd);
  return APR_SUCCESS;
}

/**
 * Clone thread data object 
 *
 * @param self OUT thread data object
 * @param orig IN thread data object to copy from 
 *
 * @return an apr status
 */
apr_status_t worker_clone(worker_t ** self, worker_t * orig) {
  apr_pool_t *p;

  apr_pool_create(&p, NULL);
  (*self) = apr_pcalloc(p, sizeof(worker_t));
  memcpy(*self, orig, sizeof(worker_t));
  (*self)->heartbeat = p;
  apr_pool_create(&p, (*self)->heartbeat);
  (*self)->pbody = p;
  apr_pool_create(&p, (*self)->heartbeat);
  (*self)->pool = p;
  apr_pool_create(&p, (*self)->heartbeat);
  (*self)->pcmd = p;
  apr_pool_create(&p, (*self)->heartbeat);
  (*self)->pcache = p;
  /* this stuff muss last until END so take pbody pool for this */
  p = (*self)->pbody;
  (*self)->config = apr_hash_copy(p, orig->config);
  (*self)->interpret = orig->interpret;
  (*self)->flags = orig->flags;
  (*self)->prefix = apr_pstrdup(p, orig->prefix);
  (*self)->additional = apr_pstrdup(p, orig->additional);
  (*self)->lines = my_table_deep_copy(p, orig->lines);
  (*self)->cache = my_table_deep_copy((*self)->pcache, orig->cache);
  (*self)->expect.dot = my_table_swallow_copy(p, orig->expect.dot);
  (*self)->expect.headers = my_table_swallow_copy(p, orig->expect.headers);
  (*self)->expect.body = my_table_swallow_copy(p, orig->expect.body);
  (*self)->expect.exec = my_table_swallow_copy(p, orig->expect.exec);
  (*self)->expect.error = my_table_swallow_copy(p, orig->expect.error);
  (*self)->match.dot = my_table_swallow_copy(p, orig->match.dot);
  (*self)->match.headers = my_table_swallow_copy(p, orig->match.headers);
  (*self)->match.body = my_table_swallow_copy(p, orig->match.body);
  (*self)->match.error = my_table_swallow_copy(p, orig->match.error);
  (*self)->match.exec = my_table_swallow_copy(p, orig->match.exec);
  (*self)->grep.dot = my_table_swallow_copy(p, orig->grep.dot);
  (*self)->grep.headers = my_table_swallow_copy(p, orig->grep.headers);
  (*self)->grep.body = my_table_swallow_copy(p, orig->grep.body);
  (*self)->grep.error = my_table_swallow_copy(p, orig->grep.error);
  (*self)->grep.exec = my_table_swallow_copy(p, orig->grep.exec);
  (*self)->start_time = orig->start_time;
  (*self)->listener = NULL;
  (*self)->sockets = apr_hash_make(p);
  (*self)->recorder = apr_pcalloc(p, sizeof(recorder_t));
#if APR_HAS_FORK
  (*self)->procs = NULL;
#endif
  if (orig->headers_allow) {
    (*self)->headers_allow = my_table_deep_copy(p, orig->headers_allow);
  }
  if (orig->headers_filter) {
    (*self)->headers_filter = my_table_deep_copy(p, orig->headers_filter);
  }
  (*self)->params = apr_table_make(p, 4);
  (*self)->retvars = apr_table_make(p, 4);
  (*self)->locals = apr_table_make(p, 4);
  (*self)->vars = my_table_deep_copy(p, orig->vars);
#ifdef USE_SSL
  (*self)->bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
  (*self)->bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
#endif
  (*self)->listener_addr = apr_pstrdup(p, orig->listener_addr);

  worker_log(*self, LOG_DEBUG, "worker_clone: pool: %p, pcmd: %p\n", (*self)->pool, (*self)->pcmd);
  return APR_SUCCESS;
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
apr_status_t worker_body(worker_t **body, worker_t *worker, char *command) {
  char *file_and_line;
  char *line = "";
  apr_table_entry_t *e; 
  apr_pool_t *p;
  char *end;
  char *kind;
  int ends;
  int end_len;
  int kind_len;

  /* create body */
  apr_pool_create(&p, NULL);
  end = apr_pstrcat(p, "_END ", command, NULL);
  end_len = strlen(end);
  kind = apr_pstrcat(p, "_", command, NULL);
  kind_len = strlen(kind);
  ends = 1;
  (*body) = apr_pcalloc(p, sizeof(worker_t));
  memcpy(*body, worker, sizeof(worker_t));
  /* give it an own heartbeat :) */
  (*body)->heartbeat = p;
  apr_pool_create(&(*body)->pcmd, p);

  /* fill lines */
  (*body)->lines = apr_table_make(p, 20);
  e = (apr_table_entry_t *) apr_table_elts(worker->lines)->elts;
  for (worker->cmd += 1; worker->cmd < apr_table_elts(worker->lines)->nelts; worker->cmd++) {
    file_and_line = e[worker->cmd].key;
    line = e[worker->cmd].val;
    /* count numbers of same kinds to include all their ends */
    if (strlen(line) >= kind_len && strncmp(line, kind, kind_len) == 0) {
      ++ends;
      worker_log(worker, LOG_DEBUG, "Increment loops: %d for line %s", ends, line);
    }
    /* check end and if it is our end */
    if (ends == 1 && strlen(line) >= end_len && strncmp(line, end, end_len) == 0) {
      break;
    }
    /* no is not our end, decrement ends */
    else if (strlen(line) >= end_len && strncmp(line, end, end_len) == 0) {
      --ends;
      worker_log(worker, LOG_DEBUG, "Decrement loops: %d for line %s", ends, line);
    }
    apr_table_addn((*body)->lines, file_and_line, line);
  }
  /* check for end */
  if (strlen(line) < end_len || strncmp(line, end, end_len) != 0) {
    worker_log(worker, LOG_ERR, "Compilation failed: no %s found", end);
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
void worker_body_end(worker_t *body, worker_t *worker) {
  worker->flags = body->flags;
  /* write back sockets and state */
  worker->socket = body->socket;
  worker->listener = body->listener;

  /* destroy body */
  worker_destroy(body);
}

/**
 * Destroy thread data object
 *
 * @param self IN thread data object
 */
void worker_destroy(worker_t * self) {
  worker_log(self, LOG_DEBUG, "worker_destroy: %p, pcmd: %p", self->pool, self->pcmd);
  apr_pool_destroy(self->heartbeat);
}

/**
 * Clone thread data object 
 *
 * @param self IN thread data object
 * @param line IN command line
 *
 * @return an apr status
 */
apr_status_t worker_add_line(worker_t * self, const char *file_and_line,
                             char *line) {
  apr_table_add(self->lines, file_and_line, line);
  return APR_SUCCESS;
}

/**
 * local socket send
 *
 * @param sockett IN socket 
 * @param buf IN buffer to send
 * @param len IN no bytes of buffer to send
 *
 * @return apr status
 */
static apr_status_t socket_send(socket_t *socket, char *buf,
                                apr_size_t len) {
  apr_status_t status = APR_SUCCESS;
  apr_size_t total = len;
  apr_size_t count = 0;

#ifdef USE_SSL
  if (socket->is_ssl) {
    apr_size_t e_ssl;
  tryagain:
    apr_sleep(1);
    e_ssl = SSL_write(socket->ssl, buf, len);
    if (e_ssl != len) {
      int scode = SSL_get_error(socket->ssl, e_ssl);
      if (scode == SSL_ERROR_WANT_WRITE) {
	goto tryagain;
      }
      status = APR_ECONNABORTED;
      goto error;
    }
  }
  else
#endif
  {
    while (total != count) {
      len = total - count;
      if ((status = apr_socket_send(socket->socket, &buf[count], &len)) 
	  != APR_SUCCESS) {
	goto error;
      }
      count += len;
    }
  }

error:
  return status;
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
apr_status_t worker_socket_send(worker_t *self, char *buf, 
                                apr_size_t len) {
  return socket_send(self->socket, buf, len);
}

/**
 * flush partial data 
 *
 * @param self IN thread data object
 *
 * @return an apr status
 */

apr_status_t worker_flush_part(worker_t *self, char *chunked, int from, int to) {
  int i;
  int len;

  apr_status_t status = APR_SUCCESS;

  apr_table_entry_t *e =
    (apr_table_entry_t *) apr_table_elts(self->cache)->elts;

  if (chunked) {
    worker_log_buf(self, LOG_INFO, chunked, ">", strlen(chunked));
  }

  if (chunked) {
    len = strlen(chunked);
    if ((status = worker_socket_send(self, chunked, len)) != APR_SUCCESS) {
      goto error;
    }
    self->sent += len;
  }
  /* iterate through all cached lines and send them */
  for (i = from; i < to; ++i) {
    if (strncasecmp(e[i].key, "NOCRLF:", 7) == 0) { 
      len = apr_atoi64(&e[i].key[7]);
      worker_log_buf(self, LOG_INFO, e[i].val, ">", len);
    }
    else {
      len = strlen(e[i].val);
      worker_log(self, LOG_INFO, ">%s %s", e[i].val, 
	         strcasecmp(e[i].key, "NOCRLF") ? "" : e[i].key);
    }

    if ((status = worker_socket_send(self, e[i].val, len)) 
	!= APR_SUCCESS) {
      goto error;
    }
    self->sent += len;
    if (strncasecmp(e[i].key, "NOCRLF", 6) != 0) {
      len = 2;
      if ((status = worker_socket_send(self, "\r\n", len)) != APR_SUCCESS) {
	goto error;
      }
      self->sent += len;
    }
  }

error:
  return status;
}

/**
 * flush data 
 *
 * @param self IN thread data object
 *
 * @return an apr status
 */
apr_status_t worker_flush(worker_t * self) {
  apr_size_t len;
  const char *hdr;

  int i = 0;
  int icap_body = 0;
  int icap_body_start = 0;
  int start = 0;
  char *chunked = NULL;
  int ct_len = 0;

  apr_status_t status = APR_SUCCESS;
  apr_table_entry_t *e =
    (apr_table_entry_t *) apr_table_elts(self->cache)->elts;

  if (!self->socket || !self->socket->socket) {
    goto error;
  }
  
  /* hop over icap headers if there are any */
  if (apr_table_get(self->cache, "Content-Length") && 
      (hdr = apr_table_get(self->cache, "Encapsulated"))) {
   char *nv;
    char *last;
    char *copy = apr_pstrdup(self->pcmd, hdr);

    /* start counting till last body of ICAP message */
    i = 0;
    len = 0;
    apr_strtok(copy, ":", &last);
    nv = apr_strtok(NULL, ",", &last);
    while (nv) {
      /* hop over headers an do not count user did set a value */
      while (i < apr_table_elts(self->cache)->nelts && e[i].val[0]) {
	++i;
      }
      ++i;
      nv = apr_strtok(NULL, ",", &last);
    }
    start = 1;
  }

  /* callculate body if Content-Length: AUTO */
  if (apr_table_get(self->cache, "Content-Length")) {
    /* calculate body len */
    len = 0;
    for (; i < apr_table_elts(self->cache)->nelts; ++i) {
      /* easy way to jump over headers */
      if (!start && !e[i].val[0]) {
        /* start body len */
        start = 1;
      }
      else if (start) {
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
    }

    apr_table_set(self->cache, "Content-Length",
                  apr_psprintf(self->pool, "Content-Length: %d", len));

    ct_len = len;
  }

  /* callculate headers and optional body of ICAP message */
  if ((hdr = apr_table_get(self->cache, "Encapsulated"))) {
    char *nv;
    char *last;
    char *res = NULL;
    char *copy = apr_pstrdup(self->pcmd, hdr);

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
	  ++i;
	}
	/* count also the empty line */
	len += 2;
	val = apr_itoa(self->pcmd, len);
	++i;
      }
      else {
        /* hop over headers an do not count user did set a value */
        while (i < apr_table_elts(self->cache)->nelts && e[i].val[0]) {
	  ++i;
	}
	++i;
      }

      if (!res) {
	res = apr_pstrcat(self->pcmd, var, "=", val, NULL); 
      }
      else {
	res = apr_pstrcat(self->pcmd, res, ", ", var, "=", val, NULL); 
      }
      nv = apr_strtok(NULL, ",", &last);
    }
    apr_table_setn(self->cache, "Encapsulated",
                   apr_psprintf(self->pool, "Encapsulated: %s", res));

    /* only chunk body automatic if Content-Length: AUTO */
    if (icap_body && apr_table_get(self->cache, "Content-Length")) {
      icap_body_start = i;
      chunked = apr_psprintf(self->pool, "%x\r\n", ct_len);
    }
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
    chunked = apr_psprintf(self->pool, "\r\n%x\r\n", len);
  }
  if (icap_body) {
    /* send all except the req/res body */
    status = worker_flush_part(self, NULL, 0, icap_body_start); 
    status = worker_flush_part(self, chunked, icap_body_start, apr_table_elts(self->cache)->nelts); 
    if (chunked) {
      chunked = apr_psprintf(self->pool, "\r\n0\r\n\r\n");
      status = worker_flush_part(self, chunked, 0, 0); 
    }
  }
  else {
    status = worker_flush_part(self, chunked, 0, apr_table_elts(self->cache)->nelts); 
  }

error:
  {
//    apr_pool_t *parent = apr_pool_parent_get(self->pcache);
//    apr_pool_destroy(self->pcache);
//    apr_pool_create(&self->pcache, parent);
    apr_pool_clear(self->pcache);
    self->cache = apr_table_make(self->pcache, 20);
  }

  return status;
}

/**
 * write worker data to file with worker->name
 *
 * @param self IN thread data object
 *
 * @return an apr status
 */
apr_status_t worker_to_file(worker_t * self) {
  apr_status_t status;
  apr_file_t *fp;
  apr_table_entry_t *e;
  char *line;
  int i;

  if ((status =
       apr_file_open(&fp, self->name, APR_CREATE | APR_WRITE, APR_OS_DEFAULT,
		     self->pcmd)) != APR_SUCCESS) {
    return status;
  }

  e = (apr_table_entry_t *) apr_table_elts(self->lines)->elts;
  for (i = 0; i < apr_table_elts(self->lines)->nelts; i++) {
    line = e[i].val;
    apr_file_printf(fp, "%s\n", &line[1]);
  }

  apr_file_close(fp);

  return APR_SUCCESS;
}
