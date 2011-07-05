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
 * Interface of the HTTP Test Tool file.
 */

#ifndef HTTEST_WORKER_H
#define HTTEST_WORKER_H

#include <apr_hooks.h>

typedef struct socket_s {
  apr_socket_t *socket;
#define SOCKET_CLOSED 0
#define SOCKET_CONNECTED 1
  int socket_state;
#ifdef USE_SSL
  int is_ssl;
  SSL *ssl;
  SSL_SESSION *sess;
#endif
  apr_size_t peeklen;
  char peek[32];
  apr_table_t *cookies;
  char *cookie;
} socket_t;

typedef struct validation_s {
  apr_table_t *dot;
  apr_table_t *headers;
  apr_table_t *body;
  apr_table_t *error;
  apr_table_t *exec;
} validation_t;

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
  apr_pool_t *pool;
  sockreader_t *sockreader;
} recorder_t;

typedef struct worker_s worker_t;
typedef apr_status_t(*interpret_f)(worker_t * self, worker_t *parent);
struct worker_s {
  interpret_f interpret;
  /* this is the pool where the structure lives */
  apr_pool_t *heartbeat;
  /* dies on END */
  apr_pool_t *pbody;
  /* dies on every flush */
  apr_pool_t *pcache;
  const char *filename;
  X509 *foreign_cert;
  apr_file_t *tmpf;
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
  int flags;
  apr_proc_t proc;
  int cmd;
  int cmd_from;
  int cmd_to;
  int which;
  char *name;
  char *prefix;
  char *additional;
  char *file_and_line;
  const char *short_desc;
  const char *desc;
  int chunksize;
  apr_size_t sent;
  int req_cnt;
  char *match_seq;
  apr_time_t socktmo;
  apr_thread_t *mythread;
  apr_thread_cond_t *sync_cond;
  apr_thread_mutex_t *sync_mutex;
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
  apr_table_t *vars;
  apr_table_t *params;
  apr_table_t *retvars;
  apr_table_t *locals;
  apr_table_t *tmp_table;
  apr_hash_t *modules;
  apr_hash_t *blocks;
  apr_time_t start_time;
  apr_hash_t *sockets;
  apr_socket_t *listener;
  socket_t *socket;
  apr_port_t listener_port;
  char *listener_addr;
  sockreader_t *sockreader;
  recorder_t *recorder;
#define LOG_NONE 0
#define LOG_ERR 1
#define LOG_WARN 2
#define LOG_INFO 3
#define LOG_CMD 4
#define LOG_ALL_CMD 5
#define LOG_DEBUG 6
  int log_mode;
#ifdef USE_SSL
  int is_ssl;
  SSL_CTX *ssl_ctx;
  SSL_METHOD *meth;
  BIO *bio_out;
  BIO *bio_err;
  char *ssl_info;
#endif
#if APR_HAS_FORK
  apr_hash_t *procs;
#endif
};

typedef struct global_s {
  apr_pool_t *pool;
  int flags;
  const char *filename;
  apr_table_t *vars;
  apr_hash_t *modules;
  apr_hash_t *blocks;
  apr_table_t *files;
  int log_mode;
  apr_table_t *threads;
  apr_table_t *clients;
  apr_table_t *servers;
  apr_table_t *daemons;
  int CLTs; 
  int SRVs; 
  apr_thread_cond_t *cond; 
  apr_thread_mutex_t *sync;
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
  char *prefix;
  worker_t *worker;
  apr_threadattr_t *tattr;
  int recursiv;
} global_t;

typedef struct command_s command_t;
typedef apr_status_t(*command_f) (command_t * self, void * type, char *data);

struct command_s {
  char *name;
  command_f func;
  char *syntax;
  char *help;
#define COMMAND_FLAGS_NONE 0x0
#define COMMAND_FLAGS_DEPRECIATED 0x1
#define COMMAND_FLAGS_EXPERIMENTAL 0x2
#define COMMAND_FLAGS_LINK 0x4
  int flags;
};

typedef struct line_s {
  char *info;
  char *buf;
  apr_size_t len;
} line_t;

# define HTT_DECLARE(type)    type
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, void, flush_resolved_line,
                          (worker_t *worker, line_t *line));

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
  copy = apr_pstrdup(worker->pbody, data); \
  copy = worker_replace_vars(worker, copy, NULL); \
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
  copy = apr_pstrdup(worker->pbody, data); \
  copy = worker_replace_vars(worker, copy, NULL); \
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

apr_status_t worker_new(worker_t ** self, char *additional,
                        char *prefix, global_t *global, interpret_f interpret);
apr_status_t worker_clone(worker_t ** self, worker_t * orig); 
apr_status_t worker_handle_buf(worker_t *worker, apr_pool_t *pool, char *buf, 
                               apr_size_t len); 

/** commands */
apr_status_t command_REQ(command_t * self, worker_t * worker, char *data);
apr_status_t command_RESWAIT(command_t * self, worker_t * worker, char *data);
apr_status_t command_RES(command_t * self, worker_t * worker, char *data);
apr_status_t command_WAIT(command_t * self, worker_t * worker, char *data);
apr_status_t command_SLEEP(command_t * self, worker_t * worker, char *data);
apr_status_t command_EXPECT(command_t * self, worker_t * worker, char *data);
apr_status_t command_CLOSE(command_t * self, worker_t * worker, char *data);
apr_status_t command_TIMEOUT(command_t * self, worker_t * worker, char *data);
apr_status_t command_MATCH(command_t * self, worker_t * worker, char *data);
apr_status_t command_GREP(command_t * self, worker_t * worker, char *data);
apr_status_t command_SET(command_t * self, worker_t * worker, char *data);
apr_status_t command_DATA(command_t * self, worker_t * worker, char *data);
apr_status_t command_BIN_DATA(command_t * self, worker_t * worker, char *data);
apr_status_t command_FLUSH(command_t * self, worker_t * worker, char *data);
apr_status_t command_CHUNK(command_t * self, worker_t * worker, char *data);
apr_status_t command_EXEC(command_t * self, worker_t * worker, char *data);
apr_status_t command_SENDFILE(command_t * self, worker_t * worker, char *data);
apr_status_t command_PIPE(command_t * self, worker_t * worker, char *data);
apr_status_t command_NOCRLF(command_t * self, worker_t * worker, char *data);
apr_status_t command_SOCKSTATE(command_t * self, worker_t * worker, char *data);
apr_status_t command_HEADER(command_t *self, worker_t *worker, char *data);
apr_status_t command_RAND(command_t *self, worker_t *worker, char *data);
apr_status_t command_DEBUG(command_t *self, worker_t *worker, char *data);
apr_status_t command_UP(command_t *self, worker_t *worker, char *data);
apr_status_t command_DOWN(command_t *self, worker_t *worker, char *data);
apr_status_t command_TIME(command_t *self, worker_t *worker, char *data);
apr_status_t command_LOG_LEVEL(command_t *self, worker_t *worker, char *data);
apr_status_t command_SYNC(command_t *self, worker_t *worker, char *data);
apr_status_t command_RECV(command_t * self, worker_t * worker, char *data);
apr_status_t command_READLINE(command_t *self, worker_t *worker, char *data);
apr_status_t command_CHECK(command_t *self, worker_t *worker, char *data);
apr_status_t command_OP(command_t * self, worker_t * worker, char *data);
apr_status_t command_WHICH(command_t * self, worker_t * worker, char *data);
apr_status_t command_CERT(command_t * self, worker_t * worker, char *data);
apr_status_t command_VERIFY_PEER(command_t *self, worker_t * worker, 
                                 char *data);
apr_status_t command_RENEG(command_t *self, worker_t * worker, char *data);
apr_status_t command_ONLY_PRINTABLE(command_t *self, worker_t *worker, 
                                    char *data); 
apr_status_t command_SH(command_t *self, worker_t *worker, char *data); 
apr_status_t command_ADD_HEADER(command_t *self, worker_t *worker, char *data);
apr_status_t command_DETACH(command_t *self, worker_t *worker, char *data);
apr_status_t command_PID(command_t *self, worker_t *worker, char *data); 
apr_status_t command_URLENC(command_t *self, worker_t *worker, char *data); 
apr_status_t command_URLDEC(command_t *self, worker_t *worker, char *data); 
apr_status_t command_B64ENC(command_t *self, worker_t *worker, char *data);
apr_status_t command_B64DEC(command_t *self, worker_t *worker, char *data); 
apr_status_t command_STRFTIME(command_t *self, worker_t *worker, char *data); 
apr_status_t command_TUNNEL(command_t *self, worker_t *worker, char *data); 
apr_status_t command_BREAK(command_t *self, worker_t *worker, char *data); 
apr_status_t command_PRINT_HEX(command_t *self, worker_t *worker, char *data); 
apr_status_t command_TIMER(command_t *self, worker_t *worker, char *data); 
apr_status_t command_SSL_CONNECT(command_t *self, worker_t *worker, char *data);
apr_status_t command_SSL_ACCEPT(command_t *self, worker_t *worker, char *data);
apr_status_t command_SSL_LEGACY(command_t *self, worker_t *worker, char *data); 
apr_status_t command_SSL_SECURE_RENEG_SUPPORTED(command_t *self, 
                                                worker_t *worker, char *data);
apr_status_t command_SSL_ENGINE(command_t *self, worker_t *worker, char *data); 
apr_status_t command_AUTO_CLOSE(command_t *self, worker_t *worker, char *data); 
apr_status_t command_AUTO_COOKIE(command_t *self, worker_t *worker, char *data); 
apr_status_t command_IGNORE_BODY(command_t *self, worker_t *worker, char *data); 
apr_status_t command_SSL_CERT_VAL(command_t *self, worker_t *worker, 
                                  char *data); 
apr_status_t command_SSL_SESSION_ID(command_t *self, worker_t *worker, char *data); 
apr_status_t command_SSL_BUF_2_CERT(command_t *self, worker_t *worker, 
                                    char *data);
#if APR_HAS_FORK
apr_status_t command_PROC_WAIT(command_t *self, worker_t *worker, char *data); 
#endif
apr_status_t command_MATCH_SEQ(command_t * self, worker_t * worker, char *data);
apr_status_t command_RECORD(command_t *self, worker_t *worker, char *data); 
apr_status_t command_PLAY(command_t *self, worker_t *worker, char *data); 
apr_status_t command_USE(command_t *self, worker_t *worker, char *data); 
apr_status_t command_SSL_GET_SESSION(command_t *self, worker_t *worker, char *data); 
apr_status_t command_SSL_SET_SESSION(command_t *self, worker_t *worker, char *data); 
apr_status_t command_LOCAL(command_t *self, worker_t *worker, char *data); 
apr_status_t command_LOCK(command_t *self, worker_t *worker, char *data); 
apr_status_t command_UNLOCK(command_t *self, worker_t *worker, char *data); 

/** helper */
void worker_log(worker_t * self, int log_mode, char *fmt, ...); 
void worker_log_error(worker_t * self, char *fmt, ...); 
void worker_log_buf(worker_t * self, int log_mode, char *buf, char *prefix, 
                    int len); 
apr_status_t worker_test_unused(worker_t * self); 
apr_status_t worker_test_unused_errors(worker_t * self); 
apr_status_t worker_expect(worker_t * self, apr_table_t * regexs, 
                           const char *data, apr_size_t len); 
apr_status_t worker_check_expect(worker_t * self, apr_status_t status); 
apr_status_t worker_check_error(worker_t *self, apr_status_t status); 
char * worker_replace_vars(worker_t * worker, char *line, int *unresolved); 
apr_status_t worker_flush(worker_t * self);
apr_status_t worker_clone(worker_t ** self, worker_t * orig); 
apr_status_t worker_body(worker_t **body, worker_t *worker, char *end); 
void worker_body_end(worker_t *body, worker_t *worker); 
void worker_destroy(worker_t * self); 
apr_status_t worker_match(worker_t * worker, apr_table_t * regexs, 
                          const char *data, apr_size_t len); 
void worker_conn_close_all(worker_t *self); 
apr_status_t worker_ssl_ctx(worker_t * self, const char *certfile, 
                            const char *keyfile, const char *cafile, 
			    int check); 
apr_status_t worker_listener_up(worker_t *worker, apr_int32_t backlog); 
void worker_get_socket(worker_t *self, const char *hostname, 
                       const char *portname);
apr_status_t worker_ssl_accept(worker_t * worker); 
apr_status_t worker_add_line(worker_t * self, const char *file_and_line,
                             char *line); 
apr_status_t worker_socket_send(worker_t *self, char *buf, 
                                apr_size_t len); 
apr_status_t worker_to_file(worker_t * self);

#endif
