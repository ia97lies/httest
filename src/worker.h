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
 * Interface of the HTTP Test Tool file.
 */

#ifndef HTTEST_WORKER_H
#define HTTEST_WORKER_H

#include <setjmp.h>
#include <apr_hooks.h>
#include "logger.h" 
#include "transport.h" 
#include "store.h" 
#include "socket.h" 

typedef struct command_s command_t;
typedef apr_status_t(*command_f) (command_t * self, void * type, char *data, 
                                  apr_pool_t *ptmp);

struct command_s {
  char *name;
  command_f func;
  char *syntax;
  char *help;
#define COMMAND_FLAGS_NONE         0x00000000
#define COMMAND_FLAGS_DEPRECIATED  0x00000001
#define COMMAND_FLAGS_EXPERIMENTAL 0x00000002
#define COMMAND_FLAGS_LINK         0x00000004
#define COMMAND_FLAGS_BODY         0x00000008
  int flags;
};

typedef struct socket_s {
  int is_ssl;
  transport_t *transport;
  apr_socket_t *socket;
#define SOCKET_CLOSED 0
#define SOCKET_CONNECTED 1
  int socket_state;
  /* worker config */
  apr_hash_t *config;
  apr_size_t peeklen;
  char peek[32];
  apr_table_t *cookies;
  char *cookie;
  sockreader_t *sockreader;
} socket_t;

typedef struct validation_s {
  apr_table_t *ns;

  apr_table_t *dot;
  apr_table_t *headers;
  apr_table_t *body;
  apr_table_t *error;
  apr_table_t *exec;
} validation_t;

typedef struct worker_s worker_t;
typedef struct global_s global_t;
typedef apr_status_t(*interpret_f)(worker_t *worker, worker_t *parent, 
                                   apr_pool_t *ptmp);
typedef const char *(*readline_f)(worker_t *worker);
struct worker_s {
  global_t *global;
  /* readline function */
  readline_f readline;
  /* interpreter function */
  interpret_f interpret;
  /* worker config */
  apr_hash_t *config;
  /* worker block if this is a CALL */
  worker_t *block;
  /* this is the pool where the structure lives */
  apr_pool_t *heartbeat;
  /* dies on END */
  apr_pool_t *pbody;
  /* dies on every flush */
  apr_pool_t *pcache;
  /* body variables */
  store_t *vars;
  /* block parameters */
  store_t *params;
  /* block return variables */
  store_t *retvars;
  /* block local variables */
  store_t *locals;
  /* buffered stdout */
  apr_file_t *out;
  /* buffered errout */
  apr_file_t *err;
  /* filename of current script part */
  const char *filename;
#define FLAGS_NONE           0x00000000
#define FLAGS_PIPE           0x00000001
#define FLAGS_CHUNKED        0x00000002
#define FLAGS_PIPE_IN        0x00000008
#define FLAGS_FILTER         0x00000010
#define FLAGS_CLIENT         0x00000020
#define FLAGS_SERVER         0x00000040
#define FLAGS_ONLY_PRINTABLE 0x00000080
#define FLAGS_PRINT_HEX      0x00000100
#define FLAGS_SSL_LEGACY     0x00000200
#define FLAGS_AUTO_CLOSE     0x00000400
#define FLAGS_AUTO_COOKIE    0x00000800
#define FLAGS_IGNORE_BODY    0x00001000
#define FLAGS_SKIP_FLUSH     0x00002000
#define FLAGS_LOADED_BLOCK   0x00004000
  int flags;
  int cmd;
  int cmd_from;
  int cmd_to;
  int which;
  int group;
  char *name;
  char *additional;
  const char *short_desc;
  const char *desc;
  int chunksize;
  apr_size_t sent;
  int req_cnt;
  char *match_seq;
  apr_time_t socktmo;
  apr_thread_t *mythread;
  apr_thread_mutex_t *sync_mutex;
  apr_thread_mutex_t *log_mutex;
  apr_thread_mutex_t *mutex;
  apr_table_t *lines;
  apr_table_t *cache;
  validation_t match;
  validation_t grep;
  validation_t expect;
  apr_table_t *headers_allow;
  apr_table_t *headers_filter;
  apr_table_t *headers_add;
  apr_table_t *headers;
  apr_hash_t *modules;
  apr_hash_t *blocks;
  apr_hash_t *sockets;
  apr_socket_t *listener;
  socket_t *socket;
  apr_port_t listener_port;
  char *listener_addr;
  logger_t *logger;
};

struct global_s {
  apr_pool_t *pool;
  apr_pool_t *cleanup_pool;
  apr_hash_t *config;
  int flags;
  const char *path;
  const char *filename;
  store_t *vars;
  store_t *shared;
  apr_hash_t *modules;
  apr_hash_t *blocks;
  apr_table_t *files;
  apr_table_t *threads;
  apr_table_t *clients;
  apr_table_t *servers;
  apr_table_t *daemons;
  logger_t *logger;
  int CLTs;
  int SRVs;
  int cur_threads; 
  int tot_threads; 
  int groups;
  apr_thread_mutex_t *sync_mutex;
  apr_thread_mutex_t *mutex;
  int line_nr;
#define GLOBAL_STATE_NONE   0
#define GLOBAL_STATE_CLIENT 1
#define GLOBAL_STATE_SERVER 2
#define GLOBAL_STATE_BLOCK  3
#define GLOBAL_STATE_DAEMON  4
#define GLOBAL_STATE_FILE 5
  int state;
#define GLOBAL_FILE_STATE_NORMAL 0
#define GLOBAL_FILE_STATE_MODULE 1
  int file_state;
  int socktmo;
  worker_t *worker;
  worker_t *cur_worker;
  apr_threadattr_t *tattr;
  int recursiv;
  jmp_buf setjmpEnv;
};

typedef struct line_s {
  char *info;
  char *buf;
  apr_size_t len;
} line_t;

#ifndef min
#define min(a,b) ((a)<(b))?(a):(b)
#endif
#ifndef max
#define max(a,b) ((a)>(b))?(a):(b)
#endif

#ifndef DEFAULT_THREAD_STACKSIZE
#define DEFAULT_THREAD_STACKSIZE 262144 
#endif

#define RSA_SERVER_CERT "server.cert.pem"
#define RSA_SERVER_KEY "server.key.pem"

#define LISTENBACKLOG_DEFAULT 511
	
#define COMMAND_NEED_ARG(err_text) \
{ \
  if (self && self->flags & COMMAND_FLAGS_DEPRECIATED) { \
    fprintf(stderr, "Command %s is depreciated", self->name); \
    fflush(stderr); \
  } \
  while (*data == ' ') { \
    ++data; \
  } \
  if(!*data) { \
    worker_log(worker, LOG_ERR, err_text); \
    return APR_EGENERAL; \
  } \
  copy = apr_pstrdup(ptmp, data); \
  copy = worker_replace_vars(worker, copy, NULL, ptmp); \
  if (self) { \
    worker_log(worker, LOG_CMD, "%s %s", self->name, copy); \
  } \
  else { \
    worker_log(worker, LOG_CMD, "%s", copy); \
  } \
}

#define COMMAND_OPTIONAL_ARG \
{ \
  if (self && self->flags & COMMAND_FLAGS_DEPRECIATED) { \
    fprintf(stderr, "\n*** Command %s is depreciated ***", self->name); \
    fflush(stderr); \
  } \
  while (*data == ' ') { \
    ++data; \
  } \
  copy = apr_pstrdup(ptmp, data); \
  copy = worker_replace_vars(worker, copy, NULL, ptmp); \
  if (self) { \
    worker_log(worker, LOG_CMD, "%s %s", self->name, copy); \
  } \
  else { \
    worker_log(worker, LOG_CMD, "%s", copy); \
  } \
}

#define COMMAND_NO_ARG \
  if (self && self->flags & COMMAND_FLAGS_DEPRECIATED) { \
    fprintf(stderr, "\n*** Command %s is depreciated ***", self->name); \
    fflush(stderr); \
  } \
  if (self) { \
    worker_log(worker, LOG_CMD, "%s", self->name); \
  }

/** register */
# define HTT_DECLARE(type)    type

APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, line_get_length,
                          (worker_t *worker, line_t *line))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, line_flush,
                          (worker_t *worker, line_t *line))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, line_sent,
                          (worker_t *worker, line_t *line))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, client_port_args,
                          (worker_t *worker, char *portinfo, 
			   char **new_portinfo, char *rest_of_line))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, server_port_args,
                          (worker_t *worker, char *portinfo, 
			   char **new_portinfo, char *rest_of_line))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, pre_connect,
                          (worker_t *worker))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, connect,
                          (worker_t *worker))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, post_connect,
                          (worker_t *worker))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, accept,
                          (worker_t *worker, char *rest_of_line))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, pre_close,
                          (worker_t *worker))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, close,
                          (worker_t *worker, char *info, char **new_info))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, WAIT_begin,
                          (worker_t *worker))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, read_pre_headers,
                          (worker_t *worker))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, read_status_line,
                          (worker_t *worker, char *line))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, read_header,
                          (worker_t *worker, char *line))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, read_buf,
                          (worker_t *worker, char *buf, apr_size_t len))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, WAIT_end,
                          (worker_t *worker, apr_status_t status))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, worker_clone,
                          (worker_t *worker, worker_t *clone))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, read_line,
                          (global_t *global, char **line))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, block_start,
                          (global_t *global, char **line))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, block_end,
                          (global_t *global))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, client_create,
                          (worker_t *worker, apr_thread_start_t func, apr_thread_t **new_thread))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, server_create,
                          (worker_t *worker, apr_thread_start_t func, apr_thread_t **new_thread))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, worker_finally,
                          (worker_t *worker))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, thread_start,
                          (global_t *global, apr_thread_t *thread))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, thread_join,
                          (global_t *global, apr_thread_t *thread))
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, worker_joined,
                          (global_t *global))

apr_status_t transport_register(socket_t *socket, transport_t *transport);
apr_status_t transport_unregister(socket_t *socket, transport_t *transport);
transport_t *transport_get_current(socket_t *socket); 

/** commands */
apr_status_t command_CALL(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_REQ(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_RESWAIT(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_RES(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_WAIT(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_SLEEP(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_EXPECT(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_CLOSE(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_TIMEOUT(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_MATCH(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_GREP(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_ASSERT(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_SET(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_UNSET(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_DATA(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_BIN_DATA(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_FLUSH(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_CHUNK(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_EXEC(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_SENDFILE(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_PIPE(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_NOCRLF(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_SOCKSTATE(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_HEADER(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_RAND(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_DEBUG(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_PRINT(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_UP(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_DOWN(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_TIME(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_LOG_LEVEL_SET(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_LOG_LEVEL_GET(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_RECV(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_READLINE(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_CHECK(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_WHICH(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_ONLY_PRINTABLE(command_t *self, worker_t *worker, 
                                    char *data, apr_pool_t *ptmp); 
apr_status_t command_SH(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_ADD_HEADER(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_DETACH(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_PID(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_URLENC(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_URLDEC(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_B64ENC(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp);
apr_status_t command_B64DEC(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_STRFTIME(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_TUNNEL(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_BREAK(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_PRINT_HEX(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_AUTO_CLOSE(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_AUTO_COOKIE(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_MATCH_SEQ(command_t * self, worker_t * worker, char *data, apr_pool_t *ptmp);
apr_status_t command_RECORD(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_PLAY(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_USE(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_LOCAL(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_LOCK(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_UNLOCK(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_IGNORE_BODY(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_VERSION(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 
apr_status_t command_DUMMY(command_t *self, worker_t *worker, char *data, apr_pool_t *ptmp); 

/** helper */
void lock(apr_thread_mutex_t *mutex); 
void unlock(apr_thread_mutex_t *mutex); 
void worker_var_set_and_zero_terminate(worker_t * worker, const char *var, const char *val, apr_size_t len);
void worker_new(worker_t ** self, char *additional,
                global_t *global, interpret_f interpret);
void worker_clone(worker_t ** self, worker_t * orig); 
apr_status_t worker_handle_buf(worker_t *worker, apr_pool_t *pool, char *buf, 
                               apr_size_t len); 

void worker_log(worker_t * worker, int mode, char *fmt, ...); 
void worker_log_buf(worker_t * worker, int mode, char dir, const char *buf,
                    apr_size_t len); 
void worker_var_set(worker_t * worker, const char *var, const char *val); 
const char * worker_var_get(worker_t * worker, const char *var); 
void worker_test_reset(worker_t * worker); 
apr_status_t worker_test_unused(worker_t * self); 
apr_status_t worker_test_unused_errors(worker_t * self); 
apr_status_t worker_expect(worker_t * self, apr_table_t * regexs, 
                           const char *data, apr_size_t len); 
apr_status_t worker_assert(worker_t * self, apr_status_t status); 
apr_status_t worker_check_error(worker_t *self, apr_status_t status); 
const char * worker_resolve_var(worker_t *worker, const char *name, 
                                apr_pool_t *ptmp); 
char * worker_replace_vars(worker_t * worker, char *line, int *unresolved,
                           apr_pool_t *ptmp); 
apr_status_t worker_flush(worker_t * self, apr_pool_t *ptmp);
void worker_destroy(worker_t * self); 
apr_status_t worker_match(worker_t * worker, apr_table_t * regexs, 
                          const char *data, apr_size_t len); 
void worker_conn_close_all(worker_t *self); 
apr_status_t worker_listener_up(worker_t *worker, apr_int32_t backlog); 
void worker_get_socket(worker_t *self, const char *hostname, 
                       const char *portname);
apr_status_t worker_add_line(worker_t * self, const char *file_and_line,
                             char *line); 
apr_status_t worker_socket_send(worker_t *self, char *buf, 
                                apr_size_t len); 
apr_status_t worker_to_file(worker_t * self);
const char *worker_get_value_from_param(worker_t *worker, const char *param, 
                                        apr_pool_t *ptmp); 
void worker_finally_cleanup(worker_t *worker);
const char *worker_get_file_and_line(worker_t *worker);
apr_status_t worker_get_line_length(worker_t*, apr_table_entry_t, apr_size_t*);
apr_status_t worker_assert_match(worker_t*, apr_table_t*, char*, apr_status_t);
apr_status_t worker_assert_expect(worker_t*, apr_table_t*, char*, apr_status_t);

#endif
