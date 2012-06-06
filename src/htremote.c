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
/* contributor license agreements. 
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
 * Implementation of the HTTP Test Remote.
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
#include <apr_strings.h>
#include <apr_getopt.h>
#include <apr_errno.h>
#include <apr_thread_proc.h>
#include <apr_network_io.h>
#include <apr_signal.h>

#if APR_HAVE_STDLIB_H
#include <stdlib.h> /* for getpid() */
#endif

#include "util.h"

/************************************************************************
 * Defines 
 ***********************************************************************/
#define BLOCK_MAX 8192

#ifndef DEFAULT_THREAD_STACKSIZE
#define DEFAULT_THREAD_STACKSIZE 262144 
#endif

#define LISTENBACKLOG_DEFAULT 511

/************************************************************************
 * Typedefs 
 ***********************************************************************/
typedef struct connection_s {
  const char *cmd;
  apr_socket_t *socket;
} connection_t;

typedef struct stream_s {
  apr_pool_t *pool;
  apr_file_t *file;
  apr_socket_t *socket;
} stream_t;

/************************************************************************
 * Implementation 
 ***********************************************************************/
/**
 * display copyright information
 */
apr_getopt_option_t options[] = {
  { "version", 'v', 0, "Print version number and exit" },
  { "help", 'h', 0, "Display usage information (this message)" },
  { "port", 'p', 1, "Port" },
  { "command", 'e', 1, "Remote controlled command" },
  { "restart", 'r', 0, "Restart after command terminates" },
  { "thread", 't', 0, "Start a thread every connect and start command" },
  { NULL, 0, 0, NULL }
};

/** 
 * display usage information
 *
 * @progname IN name of the programm
 */
static void usage(const char *progname) {
  int i = 0;

  fprintf(stdout, "%s do start a command and stream the stdin and stdout/stderr"
          " over a socket. The htremote do act as a server, which could be read"
	  " line by line.\n", progname);
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
  fprintf(stdout, "\n");
  fprintf(stdout, "\nExample: \n"
          "%s -p 8080 -e \"./httproxy -p 8888 -d foo\"\n", progname);
}

/**
 * Input Stream
 *
 * @param streamv IN void to stream_t 
 *
 * @return 0;
 *
 * @note: thread return apr status
 */
static void * APR_THREAD_FUNC in_stream(apr_thread_t *self, void *streamv) {
  apr_status_t status;
  char buf[512+1];
  apr_size_t len;

  stream_t *stream = streamv;
  
  len = 512;
  while ((status = apr_socket_recv(stream->socket, buf, &len)) == APR_SUCCESS) {
    apr_file_write(stream->file, buf, &len);
    len = 512;
  }

  if (len != 0) {
    apr_file_write(stream->file, buf, &len);
  }
  
  if (status == APR_EOF) {
    status = APR_SUCCESS;
  }
  
  apr_file_close(stream->file);
  
  apr_thread_exit(self, status);
  apr_pool_destroy(stream->pool);
  return 0;
}

/**
 * Output Stream
 *
 * @param streamv IN void to stream_t 
 *
 * @return 0;
 *
 * @note: thread return apr status
 */
static void * APR_THREAD_FUNC out_stream(apr_thread_t *self, void *streamv) {
  apr_status_t status;
  char buf[512];
  apr_size_t len;

  stream_t *stream = streamv;
  
  len = 512;
  while ((status = apr_file_read(stream->file, buf, &len)) == APR_SUCCESS) {
    int i = 0;
    apr_size_t l;
    while (i < len) {
      l = len - i;
      apr_socket_send(stream->socket, &buf[i], &l);
      fprintf(stdout, "%s", apr_pstrndup(stream->pool, &buf[i], l));
      fflush(stdout);
      i += l;
    }
    len = 512;
  }

  if (len != 0) {
    int i = 0;
    apr_size_t l;
    while (i < len) {
      l = len - i;
      apr_socket_send(stream->socket, &buf[i], &l);
      i += l;
    }
  }
  
  if (status == APR_EOF) {
    status = APR_SUCCESS;
  }

  apr_thread_exit(self, status);
  apr_pool_destroy(stream->pool);
  return 0;
}

/**
 * Input stream to process
 *
 * @param pool IN pool
 * @param socket IN socket to read from
 * @param in IN input file desc
 * @param thread OUT thread handle
 *
 * @return apr status
 */
static apr_status_t create_in_stream(apr_socket_t *socket, apr_file_t *in, 
                                     apr_thread_t **thread) {
  apr_status_t status;
  apr_threadattr_t *tattr;
  stream_t *stream;
  apr_pool_t *pool;

  apr_pool_create(&pool, NULL);

  if ((status = apr_threadattr_create(&tattr, pool)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_stacksize_set(tattr, DEFAULT_THREAD_STACKSIZE))
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_detach_set(tattr, 1)) != APR_SUCCESS) {
    return status;
  }

  stream = apr_pcalloc(pool, sizeof(*stream));
  stream->pool = pool;
  stream->file = in;
  stream->socket = socket;
  if ((status = apr_thread_create(thread, tattr, in_stream, stream, pool)) 
      != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * Output stream to process
 *
 * @param pool IN pool
 * @param socket IN socket to read from
 * @param in IN input file desc
 * @param thread OUT thread handle
 *
 * @return apr status
 */
static apr_status_t create_out_stream(apr_socket_t *socket, apr_file_t *out, 
                                      apr_thread_t **thread) {
  apr_status_t status;
  apr_threadattr_t *tattr;
  stream_t *stream;
  apr_pool_t *pool;

  apr_pool_create(&pool, NULL);
  if ((status = apr_threadattr_create(&tattr, pool)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_stacksize_set(tattr, DEFAULT_THREAD_STACKSIZE))
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_detach_set(tattr, 1)) != APR_SUCCESS) {
    return status;
  }

  stream = apr_pcalloc(pool, sizeof(*stream));
  stream->pool = pool;
  stream->file = out;
  stream->socket = socket;
  if ((status = apr_thread_create(thread, tattr, out_stream, stream, pool)) 
      != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * Execute command and return proc handle
 *
 * @param pool IN pool
 * @param cmd IN command with args
 * @param proc OUT proc handler
 *
 * @return apr status
 */
static apr_status_t exec(apr_pool_t *pool, const char *cmd, apr_proc_t *proc) {
  apr_status_t status;
  apr_procattr_t *attr;
  apr_table_t *table;
  apr_table_entry_t *e;
  char *last;
  char *val;
  char *copy;
  const char *progname;
  const char **args;
  int i;
   
  table = apr_table_make(pool, 5);
  copy = apr_pstrdup(pool, cmd);
  progname = apr_strtok(copy, " ", &last);

  if (!progname) {
    fprintf(stderr, "No program name specified");
    return APR_ENOENT;
  }
  
  apr_table_addn(table, progname, "TRUE");

  while ((val = apr_strtok(NULL, " ", &last))) {
    apr_table_addn(table, val, "TRUE");
  }

  args = apr_pcalloc(pool,
                     (apr_table_elts(table)->nelts + 1) * sizeof(const char *));

  e = (apr_table_entry_t *) apr_table_elts(table)->elts;
  for (i = 0; i < apr_table_elts(table)->nelts; i++) {
    args[i] = e[i].key;
  }
  args[i] = NULL;

  if ((status = apr_procattr_create(&attr, pool)) != APR_SUCCESS) {
    fprintf(stderr, "%s", my_status_str(pool, status));
    return status;
  }

  if ((status = apr_procattr_cmdtype_set(attr, APR_SHELLCMD_ENV)) != APR_SUCCESS) {
    fprintf(stderr, "%s", my_status_str(pool, status));
    return status;
  }

  if ((status = apr_procattr_io_set(attr, APR_FULL_BLOCK, APR_FULL_BLOCK,
				    APR_FULL_BLOCK))
      != APR_SUCCESS) {
    fprintf(stderr, "%s", my_status_str(pool, status));
    return status;
  }

  if ((status = apr_proc_create(proc, progname, args, NULL, attr,
                                pool)) != APR_SUCCESS) {
    fprintf(stderr, "%s", my_status_str(pool, status));
    return status;
  }
  
  return APR_SUCCESS;
}

static void * APR_THREAD_FUNC handle_connection(apr_thread_t * thread, void *selfv) {
  apr_status_t status;
  apr_proc_t proc;
  apr_thread_t *thread1;
  apr_thread_t *thread2;
  apr_thread_t *thread3;
  apr_exit_why_e exitwhy;
  int exitcode = 0;
  apr_pool_t *pool;
  connection_t *conn = selfv;

  apr_pool_create(&pool, NULL);
  fprintf(stdout, "\nExec %s", conn->cmd);
  exec(pool, conn->cmd, &proc);
  
  fprintf(stdout, "\nStart threads");
  /* start 3 threads one for in one for out and one for err */
  if ((status = create_in_stream(conn->socket, proc.in, &thread1)) 
      != APR_SUCCESS) {
    fprintf(stderr, "\nERROR %s\n", my_status_str(pool, status));
    goto error;
  }
  if ((status = create_out_stream(conn->socket, proc.out, &thread2))
      != APR_SUCCESS) {
    fprintf(stderr, "%s", my_status_str(pool, status));
    goto error;
  }
  if ((status = create_out_stream(conn->socket, proc.err, &thread3))
      != APR_SUCCESS) {
    fprintf(stderr, "\nERROR %s\n", my_status_str(pool, status));
    goto error;
  }
  
  fprintf(stdout, "\nJoin command %s", conn->cmd);
  fflush(stdout);
  apr_proc_wait(&proc, &exitcode, &exitwhy, APR_WAIT);
  if (exitcode) {
    fprintf(stdout, "\nERROR %d", exitcode);
    goto error;
  }

  fprintf(stdout, "\n--normal end\n");

error:
  apr_pool_destroy(pool);
  return NULL;
}


/** 
 * call remote controler 
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
  apr_socket_t *socket;
  apr_socket_t *listener;
  apr_sockaddr_t *local_addr;
#define TYPE_NONE 0
#define TYPE_RESTART 1
#define TYPE_THREADED 2
  int type = TYPE_NONE;
  int count = 1;
  int i;

  int port = 8080;
  const char *cmd = "";

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
    case 'p':
      port = apr_atoi64(optarg);
      break;
    case 'e':
      cmd = optarg;
      break;
    case 'r':
      type = TYPE_RESTART;
      count = -1;
      break;
    case 't':
      type = TYPE_THREADED;
      count = -1;
      break;
    }
  }

  /* test for wrong options */
  if (!APR_STATUS_IS_EOF(status)) {
    fprintf(stderr, "try \"%s --help\" to get more information\n", filename(pool, argv[0]));
    exit(1);
  }

  fprintf(stdout, "Start command \"%s\" on port %d\n", cmd, port);
    
  if ((status = apr_sockaddr_info_get(&local_addr, APR_ANYADDR, APR_UNSPEC,
                                      port, APR_IPV4_ADDR_OK, pool))
      != APR_SUCCESS) {
    fprintf(stderr, "\nERROR %s\n", my_status_str(pool, status));
    return status;
  }

  if ((status = apr_socket_create(&listener, APR_INET, SOCK_STREAM,
                                  APR_PROTO_TCP, pool)) != APR_SUCCESS) {
    fprintf(stderr, "\nERROR %s\n", my_status_str(pool, status));
    return status;
  }

  status = apr_socket_opt_set(listener, APR_SO_REUSEADDR, 1);
  if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
    fprintf(stderr, "\nERROR %s\n", my_status_str(pool, status));
    return status;
  }
  
  if ((status = apr_socket_bind(listener, local_addr)) != APR_SUCCESS) {
    fprintf(stderr, "\nERROR %s\n", my_status_str(pool, status));
    return status;
  }

  if ((status = apr_socket_listen(listener, LISTENBACKLOG_DEFAULT)) != APR_SUCCESS) {
    fprintf(stderr, "\nERROR %s\n", my_status_str(pool, status));
    return status;
  }

  if (type != TYPE_THREADED) {
    for (i = 0; i != count; i++) {
      connection_t conn;

      fprintf(stdout, "\nWait for connection");
      if ((status = apr_socket_accept(&socket, listener, pool)) != APR_SUCCESS) {
        fprintf(stderr, "\nERROR %s(%d)\n", my_status_str(pool, status), status);
        return status;
      }

      conn.cmd = cmd;
      conn.socket = socket;

      handle_connection(NULL, &conn);
    }
  }
  else {
    fprintf(stderr, "\nThreaded mode is not implemented yet.\n");
  }

  fprintf(stdout, "\nTerminated");
  fflush(stdout);
  return 0;
}

