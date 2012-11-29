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
 * Implementation of the HTTP Test Proxy.
 */

/* affects include files on Solaris */
#define BSD_COMP

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/ssl.h>

#include <apr.h>
#include <apr_lib.h>
#include <apr_signal.h>
#include <apr_strings.h>
#include <apr_getopt.h>
#include <apr_portable.h>
#include <apr_errno.h>
#include <apr_thread_proc.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_hash.h>

#include "defines.h"
#include "ssl.h"
#include "regex.h"
#include "file.h"
#include "socket.h"
#include "worker.h"
#include "conf.h"
#include "util.h"
#include "module.h"

/************************************************************************
 * Defines 
 ***********************************************************************/
#define BLOCK_MAX 8192

/************************************************************************
 * Typedefs 
 ***********************************************************************/
typedef struct self_s {
  apr_pool_t *pool;
  apr_file_t *ofp;
  char *timeout;
  int port;
  worker_t *client;
  char *url_filter;
  regex_t *url_filter_regex;
  apr_thread_mutex_t *mutex;
  char *host_var;
  char *port_var;
  char *uri_var;
  char *host_port_var;
  char *cookie_pre;
  char *pre;
  char *post;
  int flags;
#define SELF_FLAGS_NONE 0
#define SELF_FLAGS_SKIP_COOKIE_FIRST_TIME 1
#define SELF_FLAGS_GOT_SET_COOKIE 2
  int log_mode;
} self_t;

typedef struct request_s {
  apr_pool_t *pool;
  char *host;
  char *port;
  char *method;
  char *url;
  char *version;
  char *protocol;
  char *request_line;
  apr_table_t *headers;
  apr_size_t len;
  char *body;
  int is_ssl;
} request_t;

typedef struct response_s {
  apr_pool_t *pool;
  char *version;
  char *status_text;
  int status;
  char *status_line;
  apr_table_t *headers;
  apr_size_t len;
  char *body;
} response_t;

apr_status_t tcp_module_init(global_t *global);
/************************************************************************
 * Implementation 
 ***********************************************************************/
char *none = "";
int new_session = 0;

/**
 * Helper
 */

/**
 * get the status string
 *
 * @param p IN pool
 * @param rc IN status to print
 *
 * @return status string
 */
static char *get_status_str(apr_pool_t * p, apr_status_t rc) {
  char *text = apr_pcalloc(p, 201);
  apr_strerror(rc, text, 200);
  return text;
}

apr_getopt_option_t options[] = {
  { "version", 'v', 0, "Print version number and exit" },
  { "help", 'h', 0, "Display usage information (this message)" },
  { "port", 'p', 1, "Port" },
  { "dest", 'd', 1, "Destination file, default file is \"file\"" },
  { "url-filter", 'u', 1, "URL filter regex default is none (blacklist)" },
  { "log-level", 'l', 1, "Log level 0-4" },
  { "host-var", 'H', 1, "Variable name for host" },
  { "port-var", 'P', 1, "Variable name for port" },
  { "root-var", 'U', 1, "Web application root variable name" },
  { "host-header-var", 'A', 1, "Variable name for host header value" },
  { "socket-tmo", 't', 1, "Socket timeout [ms], default 30000 ms" },
  { "header-file", 'i', 1, "File with header text" },
  { "trailer-file", 'e', 1, "File with trailer text" },
  { "cookie-prefix", 'c', 1, "Cookie variable prefix, default is COOKIE_" },
  { "config", 'C', 1, "Configuration file" },
  { NULL, 0, 0, NULL },
};

/** 
 * display usage information
 *
 * @progname IN name of the programm
 */
static void usage(const char *progname) {
  int i = 0;

  fprintf(stdout, "%s do record a HTTP session as a httest script", progname);
  fprintf(stdout, "\nUsage: %s [OPTIONS]\n", progname);
  fprintf(stdout, "\nOptions:");
  while (options[i].optch) {
    if (options[i].optch <= 255) {
      fprintf(stdout, "\n  -%c --%-15s %s", options[i].optch, options[i].name,
	      options[i].description);
    }
    else {
      fprintf(stdout, "\n     --%-15s %s", options[i].name, 
	      options[i].description);
    }
    i++;
  }
  fprintf(stdout, "\n\nExample: %s -p 8888 -d init -H HOST -P PORT -u \"(.*\\.png\\;.*$)|(.*\\.css\\;.*$)|(.*\\.ico\\;.*$)|(.*\\.js\\;.*$)\"\n", progname);
  fprintf(stdout, "\n");
}


/**
 * print given file to the output file
 *
 * @param self IN self pointer
 * @param file IN file name to read from
 */
static void print_file(self_t *self, char *file) {
  apr_status_t status;
  apr_file_t *fp;
  apr_pool_t *pool;
  bufreader_t *br;
  char *line;

  if (!file) {
    return;
  }
  
  apr_pool_create(&pool, NULL);
  
  if ((status =
       apr_file_open(&fp, file, APR_READ, APR_OS_DEFAULT, pool)) 
      != APR_SUCCESS) {
    fprintf(stderr, "\nWarning: Can not open file '%s': %s(%d)\n", file, 
	    get_status_str(pool, status), status);
    return;
  }

  if ((status = bufreader_new(&br, fp, pool)) != APR_SUCCESS) {
    fprintf(stderr, "\nWarning: Could not create bufreader: %s(%d)\n", 
	    get_status_str(self->pool, status), status);
    return;
  }
  
  apr_file_printf(self->ofp, "\n");
  while ((status = bufreader_read_line(br, &line)) == APR_SUCCESS) {
    apr_file_printf(self->ofp, "%s\n", line);
  }
  
  apr_file_close(fp);

  apr_pool_destroy(pool);
}

/**
 * Call command
 * 
 * @param cmd IN command
 * @param func IN function
 * @param name IN displayed name (optional may be NULL)
 * @param params IN parameter line for the called function
 *
 * @return apr status
 */
static apr_status_t call_command(worker_t *worker, void *func, char *name, char *params) {
  command_t cmd;
  cmd.name = name;
  cmd.func = (command_f)func;
  return cmd.func(&cmd, worker, params, worker->pbody);
} 

/**
 * Wait for request 
 *
 * @param worker IN worker object
 * @param r IN request record
 *
 * @return an apr status
 */
static apr_status_t wait_request(worker_t * worker, request_t *r) {
  char *line;
  apr_status_t status;
  sockreader_t *sockreader;
  char *last;
  char *key;
  apr_size_t peeklen;

  const char *val = "";
  int i = 0;

  r->len = 0;
  r->body = NULL;

  peeklen = worker->socket->peeklen;
  worker->socket->peeklen = 0;
  if ((status = sockreader_new(&sockreader, worker->socket->transport,
                               worker->socket->peek, peeklen, r->pool)) != APR_SUCCESS) {
    goto out_err;
  }

  r->headers = apr_table_make(r->pool, 10);

  while ((status = sockreader_read_line(sockreader, &line)) == APR_SUCCESS && 
         line[0] != 0) {
    /** get request line */
    if (i == 0) {
      worker_log(worker, LOG_INFO, "Requested url: %s", line);
      r->method = apr_strtok(line, " ", &r->url);
      if (strcasecmp(r->method, "CONNECT") != 0) {
	r->protocol = apr_strtok(NULL, "://", &r->url);
	r->host = apr_strtok(NULL, "/", &r->url);
	/* if url is empty do it special */
	if (r->url[0] == ' ') {
	  r->url[0] = 0;
	  r->version = apr_strtok(&r->url[1], " ", &last);
	}
	else {
	  r->url = apr_strtok(r->url, " ", &r->version);
	}
	r->host = apr_strtok(r->host, ":", &last);
	if (strcasecmp(r->protocol, "https") == 0) {
	  r->is_ssl = 1;
	}
	else {
	  r->is_ssl = 0;
	}
	if (last[0]) {
	  r->port = last;
	}
	else {
	  r->port = r->is_ssl ?
		    apr_pstrdup(r->pool, "443") : apr_pstrdup(r->pool, "80");
	}
	r->request_line = apr_psprintf(r->pool, "%s /%s %s", r->method, 
					  r->url, r->version);
      }
      else {
	worker_log(worker, LOG_ERR, "SSL tunneling is not supported");
        call_command(worker, command_DATA, "_HTTP/1.1 400 Bad Request", "");
        call_command(worker, command_DATA, "__", "");
        call_command(worker, command_CLOSE, "_CLOSE", "");
      }
    }
    else {
      /* headers */
      worker_log(worker, LOG_INFO, "<%s", line);
      key = apr_strtok(line, ":", &last);
      val = last;
      if (val) {
	if (strncasecmp(key, "Proxy-", 6) == 0) {
	  key = apr_strtok(key, "-", &last);
	  key = apr_strtok(NULL, "-", &last);
	}
	/* ignore If-Modified-Since and If-Match */
	apr_table_add(r->headers, key, &val[1]);
      }
    }
    ++i;
  }

  /* get transfer type */
  if ((val = apr_table_get(r->headers, "Content-Length"))) {
    r->len = apr_atoi64(val);
    status = content_length_reader(sockreader, &r->body, &r->len, val);
  }
  else if ((val = apr_table_get(r->headers, "Transfer-Encoding"))) {
    status = transfer_enc_reader(sockreader, &r->body, &r->len, val);
  }
out_err:
  return APR_SUCCESS;
}

/**
 * Wait for data (same as command_recv)
 *
 * @param worker IN worker object
 * @param r IN response record
 *
 * @return an apr status
 */
static apr_status_t wait_response(worker_t * worker, response_t *r) {
  char *line;
  apr_status_t status;
  sockreader_t *sockreader;
  char *last;
  char *key;
  apr_size_t peeklen;

  const char *val = "";
  int i = 0;

  r->body = NULL;
  r->len = 0;

  if ((status = worker_flush(worker, worker->pbody)) != APR_SUCCESS) {
    return status;
  }

  peeklen = worker->socket->peeklen;
  worker->socket->peeklen = 0;
  if ((status = sockreader_new(&sockreader, worker->socket->transport,
                               worker->socket->peek, peeklen, r->pool)) != APR_SUCCESS) {
    goto out_err;
  }

  r->headers = apr_table_make(r->pool, 10);

  while ((status = sockreader_read_line(sockreader, &line)) == APR_SUCCESS && 
         line[0] != 0) {
    /** get request line */
    if (i == 0) {
      r->status_line = line;
    }
    else {
      /* headers */
      key = apr_strtok(line, ":", &last);
      val = last;
      if (val) {
	if (strncasecmp(key, "Proxy-", 6) == 0) {
	  key = apr_strtok(key, "-", &last);
	  key = apr_strtok(NULL, "-", &last);
	}
	apr_table_add(r->headers, key, &val[1]);
      }
    }
    ++i;
  }

  /* get transfer type */
  if ((val = apr_table_get(r->headers, "Content-Length"))) {
    r->len = apr_atoi64(val);
    status = content_length_reader(sockreader, &r->body, &r->len, val);
  }
  else if ((val = apr_table_get(r->headers, "Transfer-Encoding"))) {
    status = transfer_enc_reader(sockreader, &r->body, &r->len, val);
  }
  else if ((val = apr_table_get(r->headers, "Encapsulated"))) {
    status = encapsulated_reader(sockreader, &r->body, &r->len, val, 
	                         apr_table_get(r->headers, "Preview"));
  }
  else if ((val = apr_table_get(r->headers, "Connection"))) {
    status = eof_reader(sockreader, &r->body, &r->len, val);
  }

out_err:
  return status;
}

/**
 * Connect to worker
 *
 * @param self IN self pointer
 * @param worker IN worker to connect to
 * @param p IN pool
 * @param host IN 
 * @param port IN 
 * @param write IN write script or not
 *
 * @return apr status
 */
static apr_status_t do_connect(self_t *self, worker_t *worker, apr_pool_t *p, 
                               int is_ssl, char *host, char *port, int write) {
  apr_status_t status;
  /* connect to server */
  if ((status = call_command(worker, command_REQ, "_REQ",
			     apr_psprintf(p, "%s %s%s", host, is_ssl ? "SSL:" : "", port)))
      != APR_SUCCESS) {
    return status;
  }
  if (write) {
    if (self->host_var) {
      host = apr_psprintf(self->pool, "$%s", self->host_var);
    }
    if (self->port_var) {
      port = apr_psprintf(self->pool, "%s$%s", is_ssl ? "SSL:" : "", self->port_var);
    }
    apr_file_printf(self->ofp, "\n\n_REQ %s %s", host, port);
  }
  return status;
}

/**
 * write request line 
 *
 * @param self IN self pointer
 * @param worker IN worker to connect to
 * @param p IN pool
 * @param request_line IN 
 * @param write IN write script or not
 *
 * @return apr status
 */
static apr_status_t do_request_line(self_t *self, worker_t *worker, apr_pool_t *p,
                                 char *request_line, int write) {
  apr_status_t status;
  char *tmp;
  char *last;

  /* write request line */
  if ((status = call_command(worker, command_DATA, "__", request_line)) 
      != APR_SUCCESS) {
    return status;
  }
  
  if (self->uri_var) {
    tmp = apr_strtok(request_line, " /", &last);
    apr_strtok(NULL, "/", &last);
    request_line = apr_pstrcat(worker->pbody, tmp, " $",self->uri_var, "/", last, NULL);
  }  
  if (write) {
    apr_file_printf(self->ofp, "\n__%s", request_line); 
  }

  return status;
}

/**
 * write headers
 *
 * @param self IN self pointer
 * @param worker IN worker to connect to
 * @param p IN pool
 * @param headers IN 
 * @param write IN write script or not
 *
 * @return apr status
 */
static apr_status_t do_headers(self_t *self, worker_t *worker, apr_pool_t *p,
                               apr_table_t *headers, int write) {
  apr_status_t status;
  apr_table_entry_t *e;
  const char *val;
  char *last;
  char *key;
  char *ignore;
  char *cookie;
  char *cookie_val;
  int i;

  /* write headers */
  e = (apr_table_entry_t *) apr_table_elts(headers)->elts;
  for (i = 0; i < apr_table_elts(headers)->nelts; ++i) {
    if (strcasecmp(e[i].key, "Cookie") == 0) {
      if (!(self->flags & SELF_FLAGS_SKIP_COOKIE_FIRST_TIME)) {
	if ((status = call_command(worker, command_DATA, "__",
				   apr_psprintf(p, "%s: %s", e[i].key, e[i].val)))
	    != APR_SUCCESS) {
	  goto error;
	}
      }
    }
    else {
      if ((status = call_command(worker, command_DATA, "__",
				 apr_psprintf(p, "%s: %s", e[i].key, e[i].val)))
	  != APR_SUCCESS) {
	goto error;
      }
    }
    if (write) {
      if (strcasecmp(e[i].key, "Content-Length") == 0) {
	apr_file_printf(self->ofp, "\n__Content-Length: AUTO");
      }
      else {
	if (strcasecmp(e[i].key, "Host") == 0) {
	  if (self->host_port_var) {
	    apr_file_printf(self->ofp, "\n__%s: $%s", e[i].key, self->host_port_var);
	  }
	}
	else if (strcasecmp(e[i].key, "Referer") == 0) {
	  /* skip this header */
	}
	else if (strcasecmp(e[i].key, "Cookie") == 0) {
	  if (!(self->flags & SELF_FLAGS_SKIP_COOKIE_FIRST_TIME)) {
	    apr_file_printf(self->ofp, "\n__Cookie: ");
	    cookie = apr_pstrdup(worker->pbody, e[i].val);
	    cookie = apr_strtok(cookie, ";", &last);
	    while (cookie) {
	      /* split key from key=val */
	      key = apr_strtok(cookie, "=", &ignore);
	      while (*key == ' ') ++key;
	      val = apr_strtok(NULL, "=", &ignore);
	      if (val) {
		cookie_val = apr_psprintf(worker->pbody, "%s=$%s%s", 
		                          key, self->cookie_pre, key);
	      }
	      else {
		cookie_val = apr_psprintf(worker->pbody, "%s", key);
	      }
	      /* get next one here so we can detect last one in the next if cond */
	      cookie = apr_strtok(NULL, ";", &last);
	      if (cookie) {
		apr_file_printf(self->ofp, "%s; ", cookie_val);
	      }
	      else {
		/* last one */
		apr_file_printf(self->ofp, "%s", cookie_val);
	      }
	    }
	  }
	}
	else {
	  apr_file_printf(self->ofp, "\n__%s: %s", e[i].key, e[i].val);
	}
      }
    }
  }

  /* empty line */
  if ((status = call_command(worker, command_DATA, "__", "")) != APR_SUCCESS) {
    goto error; 
  }
  if (write && (!(val = apr_table_get(headers, "Transfer-Encoding")) || 
      strcasecmp(val, "chunked") != 0)) {
    apr_file_printf(self->ofp, "\n__");
  }

error:
  self->flags &= ~SELF_FLAGS_SKIP_COOKIE_FIRST_TIME;
  return status;
}

/**
 * write body 
 *
 * @param self IN self pointer
 * @param worker IN worker to connect to
 * @param p IN pool
 * @param headers IN 
 * @param body IN
 * @param len IN body len
 * @param write IN write script or not
 *
 * @return apr status
 */
static apr_status_t do_body(self_t *self, worker_t *worker, apr_pool_t *p,
                            apr_table_t *headers, char *body, apr_size_t len, 
			    int write) {
  char *last;
  char *line;
  const char *val;
  int chunked = 0;

  apr_status_t status = APR_SUCCESS;

  /* write body */
  if (body) {
    if ((val = apr_table_get(headers, "Transfer-Encoding")) && 
	  strcasecmp(val, "chunked") == 0) {
      chunked = 1;
    }
    /* do pretty writting */
    if (write) {
      if (chunked) { 
	if ((status = call_command(worker, command_FLUSH, "_FLUSH", "")) != APR_SUCCESS) {
	  return status;
	}
	apr_file_printf(self->ofp, "\n_FLUSH");
      }
      line = apr_strtok(body, "\r\n", &last);
      while (line) {
	if ((status = call_command(worker, command_DATA, "__", line)) != APR_SUCCESS) {
	  return status;
	}
	apr_file_printf(self->ofp, "\n__%s", line);
	line = apr_strtok(NULL, "\r\n", &last);
      }
      if (chunked) {
	apr_file_printf(self->ofp, "\n_CHUNKED");
	apr_file_printf(self->ofp, "\n_CHUNKED");
	apr_file_printf(self->ofp, "\n__");
      }
    }
    else {
      worker_log(worker, LOG_INFO, "\n[Body len: %d]", len);
      if ((status = call_command(worker, command_FLUSH, "_FLUSH", "")) != APR_SUCCESS) {
	return status;
      }

      if (chunked) { 
	line = apr_psprintf(worker->pbody, "%x\r\n", len);
	if ((status = worker_socket_send(worker, line, strlen(line))) != APR_SUCCESS) {
	  return status;
	}
      }
      if ((status = worker_socket_send(worker, body, len)) != APR_SUCCESS) {
	return status;
      }
      if (chunked) {
	if ((status = worker_socket_send(worker, "\r\n0\r\n\r\n", 7)) != APR_SUCCESS) {
	  return status;
	}
      }
    }
  }

  return status;
}

/**
 * write status line 
 *
 * @param self IN self pointer
 * @param worker IN worker to connect to
 * @param p IN pool
 * @param status_line IN 
 * @param write IN write script or not
 *
 * @return apr status
 */
static apr_status_t do_status_line(self_t *self, worker_t *worker, 
                                   apr_pool_t *p, char *status_line, 
				   int write) {
  apr_status_t status;

  if ((status = call_command(worker, command_DATA, "__", status_line)) 
      != APR_SUCCESS) {
    return status;
  }

  if (write) {
    apr_file_printf(self->ofp, "\n_EXPECT . \"%s\"", status_line);
  }

  return status;
}

/**
 * Check if the filter let us write to the file
 *
 * @param self IN self pointer
 * @param url IN url to inspect
 *
 * @return 0 if filter matches filter url else return 1 
 */
static int do_check_url(self_t *self, const char *url) {
  if (self->url_filter_regex) {
    if ((regexec(self->url_filter_regex, url, strlen(url), 0, NULL, 0) == 0)) {
      return 0;
    }
  }
  return 1;
}

/**
 * Check if Connection: close is set
 *
 * @param headers IN headers to inspect
 *
 * @return 1 if Connection: close is set else 0
 */
static int do_check_close(apr_table_t *headers) {
  const char *connhdr;

  if ((connhdr = apr_table_get(headers, "Connection")) && 
      strcasecmp(connhdr, "close") == 0) {
    return 1;
  }

  return 0;
}

/**
 * Generate the neccessary _MATCH
 *
 * @param self IN self pointer
 * @param headers IN headers to inspect
 * @param write IN if 1 do write script
 *
 * @return apr status
 */
static apr_status_t do_matches(self_t *self, apr_table_t *headers, int write) {
  apr_table_entry_t *e;
  const char *val;
  int i;
  char *dup;
  char *cookie;
  char *last;
  char *ignore;
  char *key;

  if (!write) {
    return APR_SUCCESS;
  }
  
  /* write headers */
  e = (apr_table_entry_t *) apr_table_elts(headers)->elts;
  for (i = 0; i < apr_table_elts(headers)->nelts; ++i) {
    if (strcasecmp(e[i].key, "Set-Cookie") == 0) {
      dup = apr_pstrdup(self->pool, e[i].val);
      /* support only one cookie per Set-Cookie header */
      cookie = apr_strtok(dup, ";", &last);
      if (cookie) {
	/* split key from key=val */
	key = apr_strtok(cookie, "=", &ignore);
	val = apr_strtok(NULL, "=", &ignore);
	if (val) {
	  apr_file_printf(self->ofp, "\n_MATCH headers \"%s=([^;]*)\" %s%s", 
	                  key, self->cookie_pre, key);
	}
	else {
	  apr_file_printf(self->ofp, "\n_MATCH headers \"(%s)\" %s%s", key,
	                  self->cookie_pre, key);
	}
      }
    }
  }
  apr_file_printf(self->ofp, "\n_WAIT");
  return APR_SUCCESS;
}


/**
 * Proxy thread
 *
 * @param thread IN thread object 
 * @param selfv IN void pointer to self_t structure
 *
 * @return apr status
 */
static void *APR_THREAD_FUNC proxy_thread(apr_thread_t * thread, void *selfv) {
  apr_status_t status;
  apr_pool_t *pool;
  apr_pool_t *ptmp;
  worker_t *server;
  request_t request;
  response_t response;
  global_t global;

  int write = 1;
  self_t *self = selfv;
  worker_t *client = self->client;
  
  memset(&global, 0, sizeof(global));
  global.log_mode = self->log_mode;
  global.socktmo = 1000 * 300000;
  global.modules = apr_hash_make(self->pool);
  global.blocks = apr_hash_make(self->pool);
  
  if ((status = worker_new(&server, "", "", &global, NULL)) != APR_SUCCESS) {
    apr_thread_exit(thread, status);
  } 

  apr_pool_create(&ptmp, NULL);

  if ((status = call_command(client, command_TIMEOUT, "_TIMEOUT", "300000")) != APR_SUCCESS) {
    goto unlock;
  }

  if ((status = call_command(server, command_TIMEOUT, "_TIMEMOUT", "300000")) != APR_SUCCESS) {
    goto unlock;
  }

  /* as long we are connected */
  while ( 1 ) {
    /* create request and response objects */
    apr_pool_create(&pool, NULL);
    request.pool = pool;
    apr_pool_create(&pool, NULL);
    response.pool = pool;

    /* wait client request */
    if ((status = wait_request(client, &request)) != APR_SUCCESS) {
      /* connection failure break the loop */
      goto error;
    }

    /* check if filter matches Accept header */
    write = do_check_url(self, request.url);
    
    /* CS BEGIN */
    apr_thread_mutex_lock(self->mutex);
    worker_log(client, LOG_DEBUG, "Enter critical section");

    if ((status = do_connect(self, server, ptmp, request.is_ssl, request.host, 
	                     request.port, write)) != APR_SUCCESS) {
      apr_thread_exit(thread, status);
    }

    if ((status = do_request_line(self, server, ptmp, request.request_line, 
	                          write)) != APR_SUCCESS) {
      goto unlock;
    }

    if ((status = do_headers(self, server, ptmp, request.headers, write)) 
	!= APR_SUCCESS) {
      goto unlock;
    }
    
    if ((status = do_body(self, server, ptmp, request.headers, request.body, 
	                  request.len, write)) != APR_SUCCESS) {
      goto unlock;
    }

    if ((status = call_command(server, command_FLUSH, "_FLUSH", "")) != APR_SUCCESS) {
      goto unlock;
    }

    if ((status = wait_response(server, &response)) != APR_SUCCESS) {
      /* connection failure break the loop */
      goto unlock;
    }
    
    if ((status = do_status_line(self, client, ptmp, response.status_line,
	                         write)) != APR_SUCCESS) {
      goto unlock;
    }

    if ((status = do_headers(self, client, ptmp, response.headers, 0)) 
	!= APR_SUCCESS) {
      goto unlock;
    }

    if ((status = do_matches(self, response.headers, write)) != APR_SUCCESS) {
      goto unlock;
    }

    apr_thread_mutex_unlock(self->mutex);
    /* CS END */
    worker_log(client, LOG_DEBUG, "Leave critical section");

    if ((status = do_body(self, client, ptmp, response.headers, response.body,
	                  response.len, 0)) != APR_SUCCESS) { goto error;
      goto error;
    }

    if ((status = call_command(client, command_FLUSH, "_FLUSH", "")) != APR_SUCCESS) {
      goto error;
    }

    if (do_check_close(response.headers)) {
      break;
    }
    
    goto error;

unlock:
    apr_thread_mutex_unlock(self->mutex);
    /* CR END */

error:
    apr_pool_destroy(ptmp);
    apr_pool_destroy(request.pool);
    apr_pool_destroy(response.pool);
    if (status != APR_SUCCESS) {
      break;
    }
  }

  if (write) {
    /* CS BEGIN */
    apr_thread_mutex_lock(self->mutex);
    apr_file_printf(self->ofp, "\n_CLOSE");
    apr_thread_mutex_unlock(self->mutex);
    /* CR END */
  }

  /* close connection */
  call_command(client, command_CLOSE, "_CLOSE", "");
  call_command(server, command_CLOSE, "_CLOSE", "");

  apr_thread_exit(thread, APR_SUCCESS);
  return NULL;
}

/**
 * htproxy shell thread
 *
 * @param thread IN thread object
 * @param selfv IN void pointer to self_t structure
 *
 * @return
 */
static void *APR_THREAD_FUNC admin_thread(apr_thread_t * thread, void *selfv) {
  apr_status_t status;
  apr_file_t *ifp;
  bufreader_t *br;
  char *line;

  self_t *self = selfv;
  fprintf(stdout, "HTTP Test Proxy Shell\n");
  fprintf(stdout, "> ");
  fflush(stdout);

  if ((status = apr_file_open_stdin(&ifp, self->pool)) != APR_SUCCESS) {
    fprintf(stderr, "\nCould not open stdin: %s(%d)\n", 
	    get_status_str(self->pool, status), status);
    fflush(stderr);
    exit(1);
  }
  
  if ((status = bufreader_new(&br, ifp, self->pool)) != APR_SUCCESS) {
    fprintf(stderr, "\nCould not create bufreader: %s(%d)\n", 
	    get_status_str(self->pool, status), status);
    fflush(stderr);
    exit(1);
  }

  while ((status = bufreader_read_line(br, &line)) == APR_SUCCESS) {
    char *last;
    const char *file;
    char *cmd = NULL;
    apr_off_t offset;
    apr_size_t len;
    char *content;
    apr_pool_t *pool;

    apr_pool_create(&pool, NULL);
    
    if (line) {
      cmd = apr_strtok(line, " ", &last); 
    }

    if (!cmd || cmd[0] == 0) {
      goto next;
    }
    
    if (strcmp(cmd, "help") == 0 ||
	strcmp(cmd, "H") == 0) {
      fprintf(stdout, "\nHelp text");
      fprintf(stdout, "\n    H|help                    : This help text");
      fprintf(stdout, "\n    c|comment <text>          : Add comment to script");
      fprintf(stdout, "\n    e|expect <regex>          : Add expect before last _WAIT");
      fprintf(stdout, "\n    h|command <httest command>: Add custom httest command");
      fprintf(stdout, "\n    r|rotate <file name>      : Copy current file away");
      fprintf(stdout, "\n    n|new                     : New session");
      fprintf(stdout, "\n    q|quit                    : Exit");
      fprintf(stdout, "\n");
      fflush(stdout);
    }
    else if (strcmp(cmd, "comment") == 0 ||
	     strcmp(cmd, "c") == 0) {
      /* CS BEGIN */
      apr_thread_mutex_lock(self->mutex);

      if (last) {
	apr_file_printf(self->ofp, "\n# %s", last);
      }

      apr_thread_mutex_unlock(self->mutex);
      /* CS END */
    }
    else if (strcmp(cmd, "expect") == 0 ||
	     strcmp(cmd, "e") == 0) {
      /* CS BEGIN */
      apr_thread_mutex_lock(self->mutex);

      if (last) {
	/* seek over last _WAIT back */
	apr_finfo_t finfo;
	apr_off_t i = 1;

	apr_file_info_get(&finfo, APR_FINFO_SIZE, self->ofp);
	content = apr_pstrdup(pool, "");
	while (i < finfo.size) {
	  offset = -1 * i;
          apr_file_seek(self->ofp, APR_CUR, &offset);
	  len = i;
	  content = apr_pcalloc(pool, len);
	  apr_file_read(self->ofp, content, &len);
	  if (len >= 6 && strncmp(content, "\n_WAIT", 6) == 0) {
	    break;
	  }
	  ++i;
	} 
	if (strncmp(content, "\n_WAIT", 6) == 0) {
          status = apr_file_seek(self->ofp, APR_SET, &offset);
	  apr_file_printf(self->ofp, "\n_EXPECT . \"%s\"", last);
	  apr_file_write(self->ofp, content, &len);
	}
	else {
	  fprintf(stderr, "Warning: Can not add _EXPECT here\n");
	}
      }

      apr_thread_mutex_unlock(self->mutex);
      /* CS END */
    }
    else if (strcmp(cmd, "command") == 0 ||
	     strcmp(cmd, "h") == 0) {
      /* CS BEGIN */
      apr_thread_mutex_lock(self->mutex);

      if (last) {
	apr_file_printf(self->ofp, "\n%s", last);
      }

      apr_thread_mutex_unlock(self->mutex);
      /* CS END */
    }
    else if (strcmp(cmd, "rotate") == 0 ||
	     strcmp(cmd, "r") == 0) {
      /* CS BEGIN */
      apr_thread_mutex_lock(self->mutex);
      print_file(self, self->post);
      if (last) {
	if ((status = apr_file_name_get(&file, self->ofp)) == APR_SUCCESS) {
	  if ((status = apr_file_copy(file, last, APR_FILE_SOURCE_PERMS, 
			              pool)) != APR_SUCCESS) {
	    fprintf(stderr, "Could not copy \"%s\" to \"%s\": %s(%d)\n",
		    file, last, get_status_str(pool, status), status);
	  }
	  else {
	    apr_file_trunc(self->ofp, 0);
	    offset = 0;
	    apr_file_seek(self->ofp, APR_SET, &offset);
            print_file(self, self->pre);
	  }
	}
	else {
	  fprintf(stderr, "Can not get file name: %s(%d)\n",
		  get_status_str(pool, status), status);
	}
      }
      apr_thread_mutex_unlock(self->mutex);
      /* CS END */
    }
    else if (strcmp(cmd, "new") == 0 ||
	     strcmp(cmd, "n") == 0) {
      /* CS BEGIN */
      apr_thread_mutex_lock(self->mutex);
      new_session = 1;
      apr_thread_mutex_unlock(self->mutex);
      /* CS END */
    }
    else if (strcmp(cmd, "quit") == 0 ||
	     strcmp(cmd, "q") == 0) {
      status = APR_EOF;
      break;
    }
    else {
      fprintf(stderr, "Unknown command %s: Enter 'H' for help\n", cmd);
    }

next:
    fprintf(stdout, "> ");
    fflush(stdout);
    
    apr_pool_destroy(pool);
  }

  fprintf(stderr, "\n%s(%d)\n", 
	  get_status_str(self->pool, status), status);
  exit(0);
  return NULL;
}

/**
 * Proxy the request and write httest scrip
 *
 * @param self IN self pointer
 */
int proxy(self_t *self) {
  apr_status_t status;
  worker_t *listener;
  worker_t *client;
  self_t *this;
  apr_threadattr_t *tattr;
  apr_thread_t *thread;
  int i = 0;
  int off;
  const char *err;
  regex_t *compiled;
  global_t global;
    
  if ((status = apr_threadattr_create(&tattr, self->pool)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_stacksize_set(tattr, DEFAULT_THREAD_STACKSIZE))
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_detach_set(tattr, 0)) != APR_SUCCESS) {
    return status;
  }

  /** create a admin console thread */
  this = apr_pcalloc(self->pool, sizeof(*this));
  memcpy(this, self, sizeof(*this));
  if ((status =
       apr_thread_create(&thread, tattr, admin_thread,
			 this, this->pool)) != APR_SUCCESS) {
    return status;
  }

  memset(&global, 0, sizeof(global));
  global.pool = self->pool;
  global.log_mode = self->log_mode;
  global.socktmo = 1000 * 300000;
  global.modules = apr_hash_make(self->pool);
  global.blocks = apr_hash_make(self->pool);

  /**
   * Initialize tcp module
   */

  tcp_module_init(&global);

  if ((status = worker_new(&listener, "", "", &global, NULL)) != APR_SUCCESS) {
    return status;
  } 

  listener->listener_port = self->port;

  if ((status = call_command(listener, command_UP, "_UP", "")) != APR_SUCCESS) {
    return status;
  }

  while ( 1 ) {
    if ((status = call_command(listener, command_RES, "_RES", "")) != APR_SUCCESS) {
      return status;
    }

    /* test if main is back */
    
    if ((status = worker_new(&client, "", "                        ", &global, 
	                     NULL)) != APR_SUCCESS) {
      return status;
    } 

    worker_get_socket(client, "Default", "0");
    client->socket->socket_state = listener->socket->socket_state;
    client->socket->socket = listener->socket->socket;
    client->socket->transport = listener->socket->transport;

    /* new thread */
    this = apr_pcalloc(client->pbody, sizeof(*this));
    memcpy(this, self, sizeof(*this));
    this->pool = client->pbody;
    this->client = client;
    if (this->url_filter &&
	(compiled = pregcomp(self->pool, this->url_filter, &err, &off))) {
      this->url_filter_regex = compiled;
    }
    /* CS BEGIN */
    apr_thread_mutex_lock(self->mutex);
    if (new_session == 1) {
      this->flags |= SELF_FLAGS_SKIP_COOKIE_FIRST_TIME;
      new_session = 0;
    }
    apr_thread_mutex_unlock(self->mutex);
    /* CS END */
    if ((status =
	 apr_thread_create(&thread, tattr, proxy_thread,
			   this, this->pool)) != APR_SUCCESS) {
      return status;
    }

    /* bad hack should have a method for this */
    listener->socket->socket_state = SOCKET_CLOSED;
    
    ++i;
  }

  return 0;
}

/** 
 * sort out command-line args and call proxy
 *
 * @param argc IN number of arguments
 * @param argv IN argument array
 *
 * @return 0 if success
 */
int main(int argc, const char *const argv[]) {
  apr_status_t status;
  apr_getopt_t *opt;
  const char *optarg;
  int c;
  apr_pool_t *pool;
  self_t *self;

  apr_table_t *conf = NULL;
  const char *conf_file = NULL;
  const char *host_var = NULL;
  const char *port_var = NULL;
  const char *uri_var = NULL;  
  const char *host_port_var = NULL;
  int port = 8080;
  const char *dest = "file";
  const char *url_filter = NULL;
  int log_mode = 0;
  const char *tmo = "30000";
  const char *intro_file = NULL;
  const char *end_file = NULL;
  const char *cookie_pre = "COOKIE_";
  int flags = SELF_FLAGS_NONE;

  srand(apr_time_now()); 
  
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  /* block broken pipe signal */
#if !defined(WIN32)
  apr_signal_block(SIGPIPE);
#endif
  
  /* get options */
  apr_getopt_init(&opt, pool, argc, argv);
  while ((status = apr_getopt_long(opt, options, &c, &optarg)) 
        == APR_SUCCESS) {
    switch (c) {
    case 'h':
      usage(filename(pool, argv[0]));
      exit(0);
    case 'v':
      copyright(filename(pool, argv[0]));
      return 0;
      break;
    case 'd':
      dest = optarg;
      break;
    case 'p':
      port = apr_atoi64(optarg);
      break;
    case 'H':
      host_var = optarg;
      break;
    case 'A':
      host_port_var = optarg;
      break;
    case 'P':
      port_var = optarg;
      break;
    case 'l':
      log_mode = apr_atoi64(optarg);
      break;
    case 't':
      tmo = optarg;
      break;
    case 'i':
      intro_file = optarg;
      break;
    case 'e':
      end_file = optarg;
      break;
    case 'u':
      url_filter = optarg;
      break;
    case 'c':
      cookie_pre = optarg;
      break;
    case 'C':
      conf_file = apr_pstrdup(pool, optarg);
      break;
    case 'U':
      uri_var = optarg;
      break;
    }
  }

  /* test for wrong options */
  if (!APR_STATUS_IS_EOF(status)) {
    fprintf(stderr, "try \"%s --help\" to get more information\n", filename(pool, argv[0]));
    exit(1);
  }

#ifdef USE_SSL
  /* setup ssl library */
#ifdef RSAREF
  R_malloc_init();
#else
  CRYPTO_malloc_init();
#endif
  SSL_load_error_strings();
  SSL_library_init();
  ssl_util_thread_setup(pool);
#endif

  self = apr_pcalloc(pool, sizeof(*self));

  if ((status =
       apr_file_open(&self->ofp, dest, APR_READ|APR_WRITE|APR_CREATE|APR_TRUNCATE, 
	             APR_OS_DEFAULT, pool)) != APR_SUCCESS) {
    fprintf(stderr, "\nCan not open file '%s': %s(%d)\n", dest, 
	    get_status_str(pool, status), status);
    return status;
  }

  if ((status = apr_thread_mutex_create(&self->mutex, 
	                                APR_THREAD_MUTEX_DEFAULT,
                                        pool)) != APR_SUCCESS) {
    fprintf(stderr, "\nCan not create mutex: %s(%d)\n", 
	    get_status_str(pool, status), status);
    return status;
  }
  
  /* read config first */
  if (conf_file && (conf = conf_reader(pool, conf_file))) {
    int i;
    apr_table_entry_t *e;

    e = (apr_table_entry_t *) apr_table_elts(conf)->elts;
    /* iterate over and notify unknown stuff */
    for (i = 0; i < apr_table_elts(conf)->nelts; ++i) {
      if (strcmp(e[i].key, "Port") == 0) {
	port = apr_atoi64(e[i].val);
      }
      else if (strcmp(e[i].key, "Timeout") == 0) {
	tmo = e[i].val;
      }
      else if (strcmp(e[i].key, "HostVar") == 0) {
	host_var = e[i].val;
      }
      else if (strcmp(e[i].key, "PortVar") == 0) {
	port_var = e[i].val;
      }
      else if (strcmp(e[i].key, "HostPortVar") == 0) {
	host_port_var = e[i].val;
      }
      else if (strcmp(e[i].key, "CookieVarPrefix") == 0) {
	cookie_pre = e[i].val;
      }
      else if (strcmp(e[i].key, "ScriptHeader") == 0) {
	intro_file = e[i].val;
      }
      else if (strcmp(e[i].key, "ScriptTrailer") == 0) {
	end_file = e[i].val;
      }
      else if (strcmp(e[i].key, "UrlBlacklist") == 0) {
	url_filter = e[i].val;
      }
      else {
	fprintf(stderr, "\nUnknown parameter %s", e[i].key);
      }

    }
  }
  else if (conf_file) {
    return -1;
  }

  apr_hook_global_pool = pool; 

  /* overwrites config */
  self->pool = pool;
  self->port = port;
  self->log_mode = log_mode;
  self->timeout = apr_pstrdup(pool, tmo);
  self->host_var = host_var ? apr_pstrdup(pool, host_var) : NULL;
  self->port_var = port_var ? apr_pstrdup(pool, port_var) : NULL;
  self->uri_var = uri_var ? apr_pstrdup(pool, uri_var) : NULL;  
  self->host_port_var = host_port_var ? apr_pstrdup(pool, host_port_var) : NULL;
  self->cookie_pre = apr_pstrdup(pool, cookie_pre);
  self->pre = intro_file ? apr_pstrdup(pool, intro_file) : NULL;
  self->post = end_file ? apr_pstrdup(pool, end_file) : NULL;
  self->url_filter = url_filter ? apr_pstrdup(pool, url_filter) : NULL;
  self->flags = flags;

  fprintf(stdout, "Start proxy on port %d\n", port);
  
  print_file(self, self->pre);
    
  proxy(self);

  fprintf(stdout, "\n--normal end\n");

  return 0;
}

