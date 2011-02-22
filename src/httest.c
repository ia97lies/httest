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
 * Implementation of the HTTP Test Tool.
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

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

/* on windows the inclusion of windows.h/wincrypt.h causes
 * X509_NAME and a few more to be defined; found no other
 * way than to undef manually before inclusion of engine.h;
 * somehow the same undef in ossl_typ.h is not enough...
 */
#ifdef OPENSSL_SYS_WIN32
#undef X509_NAME
#endif

#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include <apr.h>
#include <apr_signal.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_file_io.h>
#include <apr_time.h>
#include <apr_getopt.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_thread_proc.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_support.h>
#include <apr_hash.h>
#include <apr_base64.h>
#include <apr_env.h>

#include <pcre.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#include "file.h"
#include "socket.h"
#include "regex.h"
#include "util.h"
#include "ssl.h"
#include "worker.h"

/************************************************************************
 * Defines 
 ***********************************************************************/

/************************************************************************
 * Structurs
 ***********************************************************************/

/************************************************************************
 * Globals 
 ***********************************************************************/
static apr_status_t command_EXIT(command_t * self, worker_t * worker, 
                                 char *data);
static apr_status_t command_IF(command_t * self, worker_t * worker,
                               char *data); 
static apr_status_t command_LOOP(command_t *self, worker_t *worker, 
                                 char *data); 
static apr_status_t command_FOR(command_t *self, worker_t *worker, 
                                 char *data); 
static apr_status_t command_BPS(command_t *self, worker_t *worker, 
                                char *data); 
static apr_status_t command_RPS(command_t *self, worker_t *worker, 
                                 char *data); 
static apr_status_t command_SOCKET(command_t *self, worker_t *worker, 
                                   char *data); 
static apr_status_t command_PROCESS(command_t *self, worker_t *worker, 
                                   char *data); 
static apr_status_t command_CALL(command_t *self, worker_t *worker, 
                                 char *data); 
static apr_status_t command_ERROR(command_t *self, worker_t *worker, 
                                  char *data); 

static apr_status_t global_GO(command_t *self, global_t *global, 
			     char *data); 
static apr_status_t global_END(command_t *self, global_t *global, 
			      char *data); 
static apr_status_t global_DAEMON(command_t *self, global_t *global, 
				 char *data); 
static apr_status_t global_BLOCK(command_t *self, global_t *global,
				char *data);
static apr_status_t global_FILE(command_t *self, global_t *global,
				char *data);
static apr_status_t global_CLIENT(command_t *self, global_t *global, 
				 char *data); 
static apr_status_t global_SERVER(command_t *self, global_t *global, 
				 char *data); 
static apr_status_t global_EXEC(command_t *self, global_t *global, 
			       char *data); 
static apr_status_t global_SET(command_t *self, global_t *global, 
			      char *data); 
static apr_status_t global_INCLUDE(command_t *self, global_t *global, 
				  char *data); 
static apr_status_t global_TIMEOUT(command_t *self, global_t *global, 
				  char *data); 
static apr_status_t global_AUTO_CLOSE(command_t *self, global_t *global, 
				      char *data); 
static apr_status_t global_PROCESS(command_t *self, global_t *global, 
				   char *data); 
static apr_status_t global_MODULE(command_t *self, global_t *global, 
				  char *data); 

command_t global_commands[] = {
  {"END", (command_f )global_END, "", 
  "Close CLIENT|SERVER body"},
  {"GO", (command_f )global_GO, "", 
  "Starts all so far defined clients, servers and daemons"},
  {"CLIENT", (command_f )global_CLIENT, "[<number of concurrent clients>]", 
  "Client body start, close it with END and a newline"},
  {"SERVER", (command_f )global_SERVER, "[<SSL>:]<addr_port> [<number of concurrent servers>]", 
  "Server body start, close it with END and a newline,\n"
  "Do load server.cert.pem and server.key.pem if found in local directory,\n"
  "number of concurrent servers, -1 for unlimited,\n"
  "<SSL>: SSL, SSL2, SSL3, TLS1\n"
  "<addr_port>: 8080                (just the port number)\n"
  "             www.apache.org      (just the hostname)\n"
  "             www.apache.org:8080 (hostname and port number)\n"
  "             [fe80::1]:80        (IPv6 numeric address string only)\n"},
  {"EXEC", (command_f )global_EXEC, "<shell command>", 
  "Execute a shell command, attention executes will not join CLIENT/SERVER"},
  {"SET", (command_f )global_SET, "<variable>=<value>", 
  "Store a value in a global variable"},
  {"INCLUDE", (command_f )global_INCLUDE, "<include file>", 
  "Load and execute defined include file,\n"
  "current path is taken the callers current path"},
  {"TIMEOUT", (command_f )global_TIMEOUT, "<timeout in ms>", 
  "Defines global socket timeout"},
  {"AUTO_CLOSE", (command_f )global_AUTO_CLOSE, "on|off", 
  "Handle Connection: close header and close automaticaly the given connection"},
#if APR_HAS_FORK
  {"PROCESS", (command_f )global_PROCESS, "<n>", 
  "Run the script in <n> process simultanous"},
#endif
  {"BLOCK", (command_f )global_BLOCK, "<name>", 
  "Store a block of commands to call it from a CLIENT/SERVER/BLOCK"},
  {"FILE", (command_f )global_FILE, "<name>", 
  "Create a temporary file with given name"},
  {"DAEMON", (command_f )global_DAEMON, "", 
  "Daemon body start, close it with END and a newline. \n"
  "A daemon will not join CLIENT/SERVER and could therefore be used\n"
  "for supervisor jobs" },
  {"MODULE", (command_f )global_MODULE, "<name>",
   "Define a module to collect a number of BLOCKs. If you call a BLOCK within"
   "a module, you need to prefix the BLOCK name with \"<name>:\""}, 
  {NULL, NULL, NULL,
  NULL }
};

command_t local_commands[] = {
  {"__", (command_f )command_DATA, "<string>", 
  "Send <string> to the socket with a CRLF at the end of line"},
  {"_-", (command_f )command_NOCRLF, "<string>", 
  "Same like __ but no CRLF at the end of line"},
  {"_FLUSH", (command_f )command_FLUSH, "", 
  "Flush the cached lines, \n"
  "the AUTO Content-Length calculation will take place here"},
  {"_CHUNK", (command_f )command_CHUNK, "", 
  "Mark the end of a chunk block, all data after last _FLUSH are counted,\n"
  "does automatic add chunk info"},
  {"_REQ", (command_f )command_REQ, "<host> [<SSL>:]<port>[:<tag>] [<cert-file> <key-file> [<ca-cert-file>]]", 
  "Open connection to defined host:port, with SSL support.\n"
  "If connection exist no connect will be performed\n"
  "<SSL>: SSL, SSL2, SSL3, TLS1\n"
  "<host>: host name or IPv4/IPv6 address (IPv6 address must be surrounded\n"
  "        in square brackets)\n"
  "<tag>: Additional tag info do support multiple connection to one target\n"
  "<cert-file>, <key-file> and <ca-cert-file> are optional for client/server authentication"},	
  {"_RESWAIT", (command_f )command_RESWAIT, "", 
   "Combines the _RES and _WAIT command ignoring TCP connections not sending any data." },
  {"_RES", (command_f )command_RES, "", 
  "Wait for a connection accept"},
  {"_WAIT", (command_f )command_WAIT, "[<amount of bytes>]", 
  "Wait for data and receive them.\n"
  "EXPECT and MATCH definitions will be checked here on the incoming data.\n"
  "Optional you could receive a specific amount of bytes" },
  {"_CLOSE", (command_f )command_CLOSE, "", 
  "Close the current connection and set the connection state to CLOSED"},
  {"_EXPECT", (command_f )command_EXPECT, ".|headers|body|error|exec|var() \"|'[!]<regex>\"|'", 
  "Define what data we do or do not expect on a WAIT command.\n"
  "Negation with a leading '!' in the <regex>"},
  {"_MATCH", (command_f )command_MATCH, "(.|headers|body|error|exec|var()) \"|'<regex>\"|' <variable>", 
   "Define a regex with a match which should be stored in <variable> and do fail if no match"},
  {"_GREP", (command_f )command_GREP, "(.|headers|body|error|exec|var()) \"|'<regex>\"|' <variable>", 
   "Define a regex with a match which should be stored in <variable> and do not fail if no match"},
  {"_SEQUENCE", (command_f )command_MATCH_SEQ, "<var-sequence>", 
   "Define a sequence of _MATCH variables which must apear in this order"},
  {"_IF", (command_f )command_IF, "(\"<string>\" [NOT] MATCH \"regex\")|(\"<number>\" [NOT] EQ|LT|GT|LE|GT \"<number>)\"", 
  "Test if variable do or do not match the regex, close body with _END IF,\n"
  "negation with a leading '!' in the <regex>,\n"
  "<expression> must not be empty"},
  {"_LOOP", (command_f )command_LOOP, "<n>", 
  "Do loop the body <n> times,\n"
  "close body with _END LOOP"},
  {"_FOR", (command_f )command_FOR, "<variable> \"|'<string>*\"|'", 
  "Do for each element,\n"
  "close body with _END FOR"},
  {"_BREAK", (command_f )command_BREAK, "", 
   "Break a loop"},
  {"_BPS", (command_f )command_BPS, "<n> <duration>", 
  "Send not more than defined bytes per second, while defined duration [s]\n"
  "close body with _END BPS"},
  {"_RPS", (command_f )command_RPS, "<n> <duration>", 
  "Send not more than defined requests per second, while defined duration [s]\n"
  "Request is count on every _WAIT call\n"
  "close body with _END RPS"},
  {"_SOCKET", (command_f )command_SOCKET, "", 
  "Spawns a socket reader over the next _WAIT _RECV commands\n"
  "close body with _END SOCKET"},
  {"_ERROR", (command_f )command_ERROR, "", 
  "We do expect specific error on body exit\n"
  "close body with _END ERROR"},
#if APR_HAS_FORK
  {"_PROCESS", (command_f )command_PROCESS, "<name>", 
  "Fork a process to run body in. Process termination handling see _PROC_WAIT\n"
  "close body with _END PROCESS"},
  {"_PROC_WAIT", (command_f )command_PROC_WAIT, "<name>*", 
  "Wait for processes <name>*\n"},
#endif
  {"_SLEEP", (command_f )command_SLEEP, "<milisecond>", 
   "Sleep for defined amount of time"},
  {"_TIMEOUT", (command_f )command_TIMEOUT, "<milisecond", 
   "Set socket timeout of current socket"},
  {"_SET", (command_f )command_SET, "<variable>=<value>", 
  "Store a value in a local variable"},
  {"_EXEC", (command_f )command_EXEC, "<shell command>", 
  "Execute a shell command, _EXEC| will pipe the incoming stream on the\n"
  "socket in to the called shell command"},
  {"_PIPE", (command_f )command_PIPE, "[chunked [<chunk_size>]]", 
  "Start a pipe for stream the output of EXEC to the socket stream,\n" 
  "wiht optional chunk support"},
  {"_SOCKSTATE", (command_f )command_SOCKSTATE, "<variable>", 
  "Stores connection state CLOSED or CONNECTED in the <variable>"},
  {"_EXIT", (command_f )command_EXIT, "[OK|FAILED]", 
  "Exits with OK or FAILED default is FAILED"},
  {"_HEADER", (command_f )command_HEADER, "ALLOW|FILTER <header name>", 
  "Defines allowed headers or headers to filter,\n"
  "default all headers are allowed and no headers are filtered.\n"
  "Filter only for receive mechanisme"},
  {"_RAND", (command_f )command_RAND, "<start> <end> <variable>", 
  "Generates a number between <start> and <end> and stores result in"
  " <variable>"},
  {"_SENDFILE", (command_f )command_SENDFILE, "<file>", 
  "Send file over http"},
  {"_DEBUG", (command_f )command_DEBUG, "<string>", 
  "Prints to stderr for debugging reasons"},
  {"_UP", (command_f )command_UP, "", 
  "Setup listener"},
  {"_DOWN", (command_f )command_DOWN, "", 
  "Shutdown listener"},
  {"_TIMER", (command_f )command_TIMER, "GET|RESET <variable>", 
  "Stores time duration from last reset or from start of test"},
  {"_TIME", (command_f )command_TIME, "<variable>", 
  "Store time in variable [ms]"},
  {"_CALL", (command_f )command_CALL, "<name of block>", 
  "Call a defined block"},
  {"_LOG_LEVEL", (command_f )command_LOG_LEVEL, "<level>", 
  "Level is a number 0-4"},
  {"_SYNC", (command_f )command_SYNC, "", 
  "Synchronise to the next full second"},
  {"_RECV", (command_f )command_RECV, "<bytes>|POLL|CHUNKED|CLOSE [DO_NOT_CHECK]", 
  "Receive an amount of bytes, either specified by a number \n"
  "or as much until socket timeout will in POLL mode.\n"
  "optional DO_NOT_CHECK do not check the _MATCH and _EXPECT clauses. \n"
  "With _CHECK you can do this afterward over a couple of not yet checked "
  "_RECVs"},
  {"_READLINE", (command_f )command_READLINE, "[DO_NOT_CHECK]", 
  "Receive a line terminated with \\r\\n or \\n\n"
  "optional DO_NOT_CHECK do not check the _MATCH and _EXPECT clauses. \n"
  "With _CHECK you can do this afterward over a couple of not yet checked "
  "_READLINEs"},
  {"_CHECK", (command_f )command_CHECK, "", 
  "Receive a line terminated with \\r\\n or \\n"},
  {"_OP", (command_f )command_OP, "<left> ADD|SUB|DIV|MUL <right> <variable>", 
  "Store evaluated expression"},
  {"_WHICH", (command_f )command_WHICH, "<variable>", 
  "Stores the concurrency number of current thread"},
  {"_CERT", (command_f )command_CERT, "<cert-file> <key-file> [<ca-cert-file>]", 
  "Sets cert for the current ssl connection, mainly used for server cert"},
  {"_VERIFY_PEER", (command_f )command_VERIFY_PEER, "", 
  "Gets peer cert and validate it"},
  {"_RENEG", (command_f )command_RENEG, "[verify]", 
  "Performs an SSL renegotiation."},
  {"_ONLY_PRINTABLE", (command_f )command_ONLY_PRINTABLE, "on|off", 
  "Replace all chars below 32 and above 127 with a space"},
  {"_PRINT_HEX", (command_f )command_PRINT_HEX, "on|off", 
  "Display bytes with two hex ditigs no space"},
  {"_SH", (command_f )command_SH, "shell script line or END", 
  "Embedded shell script within a tmp file, execute if END is found"},
  {"_ADD_HEADER", (command_f )command_ADD_HEADER, "<header> <value>", 
  "Add additional header to received headers to force forexample chunked encoding"},
  {"_DETACH", (command_f )command_DETACH, "", 
  "Daemonize the httest, usefull if it is a test server among others"},
  {"_PID", (command_f )command_PID, "<variable>", 
  "Store PID into a variable"},
  {"_URLENC", (command_f )command_URLENC, "\"<string>\" <variable>", 
  "Store url encoded string into a variable"},
  {"_URLDEC", (command_f )command_URLDEC, "\"<string>\" <variable>", 
  "Store url decoded string into a variable"},
  {"_B64ENC", (command_f )command_B64ENC, "\"<string>\" <variable>", 
  "Store base64 encoded string into a variable"},
  {"_B64DEC", (command_f )command_B64DEC, "\"<string>\" <variable>", 
  "Store base64 decoded string into a variable"},
  {"_STRFTIME", (command_f )command_STRFTIME, "<time> \"<format-string>\" <variable> [Local|GMT]", 
  "Stores given time [ms] formated to variable"},
  {"_SSL_CONNECT", (command_f )command_SSL_CONNECT, "SSL|SSL2|SSL3|TLS1 [<cert-file> <key-file>]", 
  "Do a ssl connect on an already connected TCP socket"},
  {"_SSL_LEGACY", (command_f )command_SSL_LEGACY, "on|off", 
  "Turn on|off SSL legacy behavour for renegotiation for openssl libraries 0.9.8l and above"},
  {"_SSL_ENGINE", (command_f )command_SSL_ENGINE, "<engine>", 
  "Set an openssl engine to run tests with crypto devices"},
  {"_SSL_SECURE_RENEG_SUPPORTED", (command_f )command_SSL_SECURE_RENEG_SUPPORTED, "", 
  "Test if remote peer do support secure renegotiation"},
  {"_AUTO_CLOSE", (command_f )command_AUTO_CLOSE, "on|off", 
  "Close connection on Connection: close header"},
  {"_AUTO_COOKIE", (command_f )command_AUTO_COOKIE, "on|off", 
  "Handles cookies in a simple way, do not check expire or path"},
  {"_IGNORE_BODY", (command_f )command_IGNORE_BODY, "on|off", 
  "Recv but do not store or inspect body, used for performance testing."},
  {"_SSL_CERT_VAL", (command_f )command_SSL_CERT_VAL, "<cert entry> <variable>", 
  "Get <cert entry> and store it into <variable>\n"
  "Get cert with _RENEG or _VERIFY_PEER\n"
  "<cert entry> are\n"
  "  M_VERSION\n"
  "  M_SERIAL\n"
  "  V_START\n"
  "  V_END\n"
  "  V_REMAIN\n"
  "  S_DN\n"
  "  S_DN_<var>\n"
  "  I_DN\n"
  "  I_DN_<var>\n"
  "  A_SIG\n"
  "  A_KEY\n"
  "  CERT"},
  {"_SSL_BUF_2_CERT", (command_f )command_SSL_BUF_2_CERT, "pem cert", 
  "Read the given buf as a pem cert, ussable with SSL_CERT_VAL"},
  {"_SSL_SESSION_ID", (command_f )command_SSL_SESSION_ID, "<variable>", 
  "Stores the session id of given sockett into <variable> base64 encoded."},
  {"_SSL_GET_SESSION", (command_f )command_SSL_GET_SESSION, "<variabl>", 
  "Store the ssl session of this connection in a variable as b64 encoded string"},
  {"_SSL_SET_SESSION", (command_f )command_SSL_SET_SESSION, "<variable>", 
  "Set ssl session for this connection from <variable> which stores a base 64 encoded ssl session"},
  {"_TUNNEL", (command_f )command_TUNNEL, "<host> [<SSL>:]<port>[:<tag>] [<cert-file> <key-file> [<ca-cert-file>]]", 
  "Open tunnel to defined host:port, with SSL support.\n"
  "If connection exist no connect will be performed\n"
  "<SSL>: SSL, SSL2, SSL3, TLS1\n"
  "<tag>:Additional tag info do support multiple connection to one target\n"
  "<cert-file>, <key-file> and <ca-cert-file> are optional for client/server authentication"},	
  {"_RECORD", (command_f )command_RECORD, "RES [ALL] {STATUS | HEADERS | BODY}*", 
  "Record response for replay it or store it"},
  {"_PLAY", (command_f )command_PLAY, "SOCKET | VAR <var>", 
  "Play back recorded stuff either on socket or into a variable."},
  {"_USE", (command_f )command_USE, "<module>", 
  "Use the name space of a module."},
  {NULL, NULL, NULL, 
  NULL},
};

global_t *process_global = NULL;
int success = 1;
int running_threads = 0;
     
/************************************************************************
 * Private 
 ***********************************************************************/

static void worker_set_global_error(worker_t *self); 
static apr_status_t worker_interpret(worker_t * self, worker_t *parent); 

/**
 * checked lock function, will exit FAILED if status not ok
 *
 * @param mutex IN mutex
 */
static void sync_lock(apr_thread_mutex_t *mutex) {
  apr_status_t status;
  if ((status = apr_thread_mutex_lock(mutex)) != APR_SUCCESS) {
    apr_pool_t *ptmp;
    apr_pool_create(&ptmp, NULL);
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
static void sync_unlock(apr_thread_mutex_t *mutex) {
  apr_status_t status;
  if ((status = apr_thread_mutex_unlock(mutex)) != APR_SUCCESS) {
    apr_pool_t *ptmp;
    apr_pool_create(&ptmp, NULL);
    success = 0;
    fprintf(stderr, "could not unlock: %s(%d)\n", 
	    my_status_str(ptmp, status), status);
    exit(1);
  }
}

static apr_hash_t *worker_lookup_block(worker_t * worker, char *data) {
  apr_size_t len = 0;
  char *block_name;
  apr_hash_t *block = NULL;

  if (strncmp(data, "__", 2) == 0 || strncmp(data, "_-", 2) == 0) {
    /* very special commands, not possible to overwrite this one */
    return NULL;
  }

  while (data[len] != ' ' && data[len] != '\0') ++len;
  block_name = apr_pstrndup(worker->pcmd, data, len);

  /* if name space do handle otherwise */
  if (strchr(block_name, ':')) {
    return NULL;
  }

  /* CR BEGIN */
  sync_lock(worker->mutex);
  block = apr_hash_get(worker->blocks, block_name, APR_HASH_KEY_STRING);
  /* CR END */
  sync_unlock(worker->mutex);

  return block;
}

/**
 * Exit program with OK|FAILED 
 *
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN OK|FAILED|<empty> 
 *
 * @return never reached
 */
static apr_status_t command_EXIT(command_t * self, worker_t * worker, 
                                 char *data) {
  char *copy;

  COMMAND_OPTIONAL_ARG;

  if (strcmp(copy, "OK") == 0) {
    worker_destroy(worker);
    exit(0);
  }
  else {
    worker_log_error(worker, "EXIT");
    worker_set_global_error(worker);
    worker_destroy(worker);
    exit(1);
  }

  /* just make the compiler happy, never reach this point */
  return APR_SUCCESS;
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

  end = "_END IF";
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
    if (ends==1 && strlen(line) >= my_else_len && strncmp(line, my_else, my_else_len) == 0) {
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
static apr_status_t command_IF(command_t * self, worker_t * worker,
                               char *data) {
  char *copy;
  char *left;
  char *right;
  apr_ssize_t left_val;
  apr_ssize_t right_val;
  char *middle;
  char *last;
  const char *err;
  int off;
  regex_t *compiled;
  apr_status_t status;
  worker_t *body;
  apr_size_t len;

  int doit = 0;
  int not = 0;
  int else_pos = 0;
 
  COMMAND_NEED_ARG("Need left operant right parameters");
  
  ++copy;
  left = apr_strtok(copy, "\"", &last);
  middle = apr_strtok(NULL, " ", &last);
  if (strcmp(middle, "NOT") == 0) {
    not = 1;
    middle = apr_strtok(NULL, " ", &last);
  }
  right = apr_strtok(NULL, "\"", &last);
 
  if (!left || !middle || !right) {
    worker_log(worker, LOG_ERR, "%s: Syntax error '%s'", self->name, data);
    return APR_EGENERAL;
  }
  
  if (right[0] == '!') {
    not = 1;
    ++right;
  }
 
  if (strcmp(middle, "MATCH") == 0) {
    if (!(compiled = pregcomp(worker->pcmd, right, &err, &off))) {
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

  if ((status = worker_body(&body, worker, "IF")) != APR_SUCCESS) {
    return status;
  }

  /* now split _IF body on _ELSE */
  if (worker_where_is_else(body, &else_pos) == APR_SUCCESS) {
    /* found _ELSE */
    if (doit) {
      body->cmd_from = 0;
      body->cmd_to = else_pos;
      status = worker_interpret(body, worker);
      worker_log(worker, LOG_CMD, "_ELSE");
    }
    else {
      worker_log(worker, LOG_CMD, "_ELSE");
      body->cmd_from = else_pos + 1;
      body->cmd_to = 0;
      status = worker_interpret(body, worker);
    }
  }
  else {
    /* did not found _ELSE */
    if (doit) {
      body->cmd_from = 0;
      body->cmd_to = 0;
      status = worker_interpret(body, worker);
    }
  }

  worker_log(worker, LOG_CMD, "_END IF");

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
static apr_status_t command_LOOP(command_t *self, worker_t *worker, 
                                 char *data) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  int loop;
  int i;

  COMMAND_NEED_ARG("<number>|FOREVER"); 
 
  if (strncmp(copy, "FOREVER", 7) == 0) {
    loop = -1;
  }
  else {
    loop = apr_atoi64(copy);
  }
  
  /* create a new worker body */
  if ((status = worker_body(&body, worker, "LOOP")) != APR_SUCCESS) {
    return status;
  }
  
  /* loop */
  for (i = 0; loop == -1 || i < loop; i++) {
    /* interpret */
    if ((status = worker_interpret(body, worker)) != APR_SUCCESS) {
      break;
    }
  }
  
  /* special case to break the loop */
  if (status == -1) {
    status = APR_SUCCESS;
  }
  
  if (status != APR_SUCCESS) {
    worker_log_error(worker, "Error in loop with count = %d", i);
  }
  
  worker_log(worker, LOG_CMD, "_END LOOP");
  
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
static apr_status_t command_FOR(command_t *self, worker_t *worker, 
                                 char *data) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  char *last;
  char *var;
  char *list;
  char *cur;

  COMMAND_NEED_ARG("<variable> \"<string>*\""); 
 
  var = apr_strtok(copy, " ", &last);
  
  list = my_unescape(last, &last);

  /* create a new worker body */
  if ((status = worker_body(&body, worker, "FOR")) != APR_SUCCESS) {
    return status;
  }
  
  /* for */
  cur = apr_strtok(list, " ", &last);
  while (cur) {
    /* interpret */
    apr_table_setn(body->vars, var, cur);
    if ((status = worker_interpret(body, worker)) != APR_SUCCESS) {
      break;
    }
    cur = apr_strtok(NULL, " ", &last);
  }
  
  /* special case to break the loop */
  if (status == -1) {
    status = APR_SUCCESS;
  }
  
  worker_log(worker, LOG_CMD, "_END FOR");
  
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
static apr_status_t command_BPS(command_t *self, worker_t *worker, char *data) {
  apr_status_t status;
  worker_t *body;
  char *last;
  char *copy;
  char *val;
  int bps;
  int duration;
  apr_time_t init;
  apr_time_t start;
  apr_time_t cur;

  COMMAND_NEED_ARG("Byte/s and duration time in second"); 

  val = apr_strtok(copy, " ", &last);
  bps = apr_atoi64(val);
  val = apr_strtok(NULL, " ", &last);
  duration = apr_atoi64(val);
  
  /* create a new worker body */
  if ((status = worker_body(&body, worker, "BPS")) != APR_SUCCESS) {
    return status;
  }
  
  /* loop */
  init = apr_time_now();
  for (;;) {
    /* interpret */
    start = apr_time_now();
    if ((status = worker_interpret(body, worker)) != APR_SUCCESS) {
      break;
    }
    cur = apr_time_now();

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

    /* reset sent bytes */
    body->sent = 0;

    /* test termination */
    if (apr_time_sec(cur - init) >= duration) {
      goto end;
    }
  }
  
end:
  worker_log(worker, LOG_CMD, "_END BPS");
  
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
static apr_status_t command_RPS(command_t *self, worker_t *worker, char *data) {
  apr_status_t status;
  worker_t *body;
  char *last;
  char *copy;
  char *val;
  int rps;
  int duration;
  apr_time_t init;
  apr_time_t start;
  apr_time_t cur;

  COMMAND_NEED_ARG("Byte/s and duration time in second"); 

  val = apr_strtok(copy, " ", &last);
  rps = apr_atoi64(val);
  val = apr_strtok(NULL, " ", &last);
  duration = apr_atoi64(val);
  
  /* create a new worker body */
  if ((status = worker_body(&body, worker, "RPS")) != APR_SUCCESS) {
    return status;
  }
  
  /* loop */
  init = apr_time_now();
  for (;;) {
    /* interpret */
    start = apr_time_now();
    if ((status = worker_interpret(body, worker)) != APR_SUCCESS) {
      break;
    }
    cur = apr_time_now();

    /* avoid division by zero, do happen on windows */
    while ((cur - start == 0)) {
      /* wait 1 ms */
      apr_sleep(1000);
      cur = apr_time_now();
    }
    
    /* wait loop until we are below the max rps */
    while (((body->req_cnt * APR_USEC_PER_SEC) / (cur - start)) > rps ) {
      /* wait 1 ms */
      apr_sleep(1000);
      cur = apr_time_now();
    }

    /* reset sent bytes */
    body->req_cnt = 0;

    /* test termination */
    if (apr_time_sec(cur - init) >= duration) {
      goto end;
    }
  }
  
end:
  worker_log(worker, LOG_CMD, "_END RPS");
  
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
static apr_status_t command_ERROR(command_t *self, worker_t *worker, 
                                  char *data) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  char **argv;
  char *status_str;
  regex_t *compiled;
  const char *err;
  int off;

  COMMAND_NEED_ARG("<error>"); 
 
 if ((status = apr_tokenize_to_argv(copy, &argv, worker->pcmd)) == APR_SUCCESS) {
    if (!argv[0]) {
      worker_log_error(worker, "No argument found, need an regex for expected errof.");
      return APR_EINVAL;
    }
  }
  else {
    worker_log_error(worker, "Could not read argument");
    return status;
  }

  /* store value by his index */
  if (!(compiled = pregcomp(worker->pcmd, argv[0], &err, &off))) {
    worker_log(worker, LOG_ERR, "ERROR condition compile failed: \"%s\"", argv[0]);
    return APR_EINVAL;
  }

  /* create a new worker body */
  if ((status = worker_body(&body, worker, "ERROR")) != APR_SUCCESS) {
    return status;
  }
  
  /* interpret */
  status = worker_interpret(body, worker);
  
  status_str = my_status_str(worker->pcmd, status);
  if (regexec(compiled, status_str, strlen(status_str), 0, NULL, 0) != 0) {
    worker_log_error(worker, "Did expect error \"%s\" but got \"%s\"", argv[0], 
	             status_str);
    return APR_EINVAL;
  }
  else {
    status = APR_SUCCESS;
  }

  worker_log(worker, LOG_CMD, "_END ERROR");
  
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
static apr_status_t command_SOCKET(command_t *self, worker_t *worker, 
                                   char *data) {
  apr_status_t status;
  worker_t *body;
  apr_size_t peeklen;
  apr_pool_t *pool;

  COMMAND_NO_ARG;

  worker_flush(worker);

  /* create a new worker body */
  if ((status = worker_body(&body, worker, "SOCKET")) != APR_SUCCESS) {
    return status;
  }

  apr_pool_create(&pool, NULL);

  peeklen = body->socket->peeklen;
  body->socket->peeklen = 0;

  if ((status = sockreader_new(&body->sockreader, body->socket->socket,
#ifdef USE_SSL
                               body->socket->is_ssl ? body->socket->ssl : NULL,
#endif
                               body->socket->peek, peeklen, pool)) != APR_SUCCESS) {
    goto error;
  }
 
  status = worker_interpret(body, worker);
  
  worker_log(worker, LOG_CMD, "_END SOCKET");
  
error:
  apr_pool_destroy(pool);
  worker_body_end(body, worker);
  return status;
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
static apr_status_t command_CALL(command_t *self, worker_t *worker, 
                                 char *data) {
  apr_status_t status;
  char *copy;
  const char *block_name;
  char *last;
  worker_t *block, *call;
  apr_table_t *lines;
  int cmd;
  apr_pool_t *call_pool;
  char *module;
  apr_hash_t *blocks;

  COMMAND_NEED_ARG("Need a block name: <block> <input-vars>* : <output-vars>*");

  apr_pool_create(&call_pool, worker->pcmd);
  my_get_args(copy, worker->params, worker->pcmd);
  block_name = apr_table_get(worker->params, "0");
  module = apr_pstrdup(worker->pcmd, block_name);

  /* determine module if any */
  if ((last = strchr(block_name, ':'))) {
    module = apr_strtok(module, ":", &last);
    /* always jump over prefixing "_" */
    module++;
    block_name = apr_pstrcat(worker->pcmd, "_", last, NULL);
    if (!(blocks = apr_hash_get(worker->modules, module, APR_HASH_KEY_STRING))) {
      worker_log_error(worker, "Could not find module \"%s\"", module);
      return APR_EINVAL;
    }
  }
  else {
    blocks = worker->blocks;
  }

  /* CR BEGIN */
  sync_lock(worker->mutex);
  if (!(block = apr_hash_get(blocks, block_name, APR_HASH_KEY_STRING))) {
    worker_log_error(worker, "Could not find block %s", block_name);
    /* CR END */
    sync_unlock(worker->mutex);
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

    /* handle parameters first */
    for (i = 1; i < apr_table_elts(block->params)->nelts; i++) {
      index = apr_itoa(call_pool, i);
      if (!(arg = apr_table_get(block->params, index))) {
	worker_log_error(worker, "Param missmatch for block \"%s\"", block->name);
      }
      if (!(val = apr_table_get(worker->params, index))) {
	worker_log_error(worker, "Param missmatch for block \"%s\"", block->name);
      }
      if (arg && val) {
	apr_table_set(worker->params, arg, val);
	apr_table_unset(worker->params, index);
      }
    }

    /* handle return variables second */
    j = i;
    for (i = 0; i < apr_table_elts(block->retvars)->nelts; i++, j++) {
      index = apr_itoa(call_pool, j);
      if (!(arg = apr_table_get(block->retvars, index))) {
	worker_log_error(worker, "Return variables missmatch for block \"%s\"", block->name);
      }
      if (!(val = apr_table_get(worker->params, index))) {
	worker_log_error(worker, "Return variables missmatch for block \"%s\"", block->name);
      }
      if (arg && val) {
	apr_table_set(worker->retvars, arg, val);
	apr_table_unset(worker->retvars, index);
      }
    }

    lines = my_table_deep_copy(call_pool, block->lines);
    sync_unlock(worker->mutex);
    /* CR END */
    call = apr_pcalloc(call_pool, sizeof(worker_t));
    memcpy(call, worker, sizeof(worker_t));
    /* lines in block */
    call->lines = lines;
    log_mode = call->log_mode;
    if (call->log_mode == LOG_CMD) {
      call->log_mode = LOG_INFO;
    }
    status = worker->interpret(call, worker);
    call->log_mode = log_mode;
    cmd = worker->cmd;
    lines = worker->lines;
    memcpy(worker, call, sizeof(worker_t));
    worker->lines = lines;
    worker->cmd = cmd;

    goto error;
  }

error:
  apr_pool_destroy(call_pool);
  apr_table_clear(worker->params);
  return status;
}

/**
 * PROCESS command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN header name (spaces are possible) 
 *
 * @return APR_SUCCESS
 */
#if APR_HAS_FORK
static apr_status_t command_PROCESS(command_t *self, worker_t *worker, char *data) {
  apr_status_t status;
  worker_t *body;
  apr_proc_t *proc;
  char *copy;

  COMMAND_NEED_ARG("<name>");

  /* create a new worker body */
  if ((status = worker_body(&body, worker, "PROCESS")) != APR_SUCCESS) {
    return status;
  }
  
  /* fork  */
  proc = apr_pcalloc(worker->pbody, sizeof(apr_proc_t));
  status = apr_proc_fork(proc, worker->pbody);

  if (APR_STATUS_IS_INCHILD(status)) {
    /* interpret */
    status = worker_interpret(body, worker);
  
    /* terminate */
    worker_log(worker, LOG_CMD, "_END PROCESS");
    worker_body_end(body, worker);
    if (status != APR_SUCCESS) {
      exit(1);
    }
    else {
      exit(0);
    }
  }

  if (!worker->procs) {
    worker->procs = apr_hash_make(worker->pbody);
  }

  apr_hash_set(worker->procs, copy, APR_HASH_KEY_STRING, proc);

  return APR_SUCCESS; 
}
#endif

/**
 * Unset global success
 *
 * @param self IN thread data object
 */
static void worker_set_global_error(worker_t *self) {
  sync_lock(self->mutex);
  success = 0;
  sync_unlock(self->mutex);
}

/**
 * Lookup function
 *
 * @param line IN line where the command resides
 *
 * @return command index
 */
static int lookup_func_index(command_t *commands, const char *line) {
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

  return k;
}

/**
 * Interpreter
 *
 * @param self IN thread data object
 *
 * @return an apr status
 */
static apr_status_t worker_interpret(worker_t * self, worker_t *parent) {
  apr_status_t status;
  char *line;
  int j;
  int k;
  int to;

  apr_table_entry_t *e =
    (apr_table_entry_t *) apr_table_elts(self->lines)->elts;

  if (self->cmd_from) {
    self->cmd = self->cmd_from;
  }
  else {
    self->cmd = 0;
  }

  if (self->cmd_to) {
    to = self->cmd_to; 
  }
  else {
    to = apr_table_elts(self->lines)->nelts;
  }

  /* iterate through all script line for this thread */
  for (; self->cmd < to; self->cmd++) {
    self->file_and_line = e[self->cmd].key;
    line = e[self->cmd].val;
    /* lookup blocks */
    if (worker_lookup_block(self, line)) {
      status = command_CALL(NULL, self, line);
    }
    else {
      /* lookup function index */
      j = 0;
      k = lookup_func_index(local_commands, line);
      /* TODO: command overwriting by calling _OVERWRITE:<command-name> */
      /* get command and test if found */
      if (local_commands[k].func) {
	j += strlen(local_commands[k].name);
	status = local_commands[k].func(&local_commands[k], self, &line[j]);
	status = worker_check_error(parent, status);
      }
      else {
	status = command_CALL(NULL, self, line);
      }
      //apr_pool_clear(self->pcmd);
      if (APR_STATUS_IS_ENOENT(status)) {
	worker_log_error(self, "%s syntax error", self->name);
	worker_set_global_error(self);
	return APR_EINVAL;
      }
    }
    if (status != APR_SUCCESS) {
      return status;
    }
  }
  if (parent == self) {
    //apr_pool_clear(self->pcmd);
    apr_pool_destroy(self->pcmd);
    apr_pool_create(&self->pcmd, self->heartbeat);
  }
  return APR_SUCCESS;
}

/**
 * Call final block if exist
 *
 * @param self IN thread data object
 */
void worker_finally(worker_t *self, apr_status_t status) {
  int k;
  int mode;

  if (self->tmpf) {
    const char *name;

    /* get file name */
    if (apr_file_name_get(&name, self->tmpf) == APR_SUCCESS) {
      /* close file */
      apr_file_close(self->tmpf);
      self->tmpf = NULL;

      apr_file_remove(name, self->pcmd);
    }
  }

  /* count down threads */
  sync_lock(self->mutex);
  --running_threads;
  sync_unlock(self->mutex);

  apr_table_set(self->vars, "__ERROR", my_status_str(self->pbody, status));
  apr_table_set(self->vars, "__STATUS", apr_ltoa(self->pbody, status));
  apr_table_set(self->vars, "__THREAD", self->name);

  if (!running_threads) { 
    k = lookup_func_index(local_commands, "_CALL");
    if (local_commands[k].func) {
      mode = self->log_mode;
      self->log_mode = 0;
      if (apr_hash_get(self->blocks, "FINALLY", APR_HASH_KEY_STRING)) {
	local_commands[k].func(&local_commands[k], self, "FINALLY");
      }
      self->log_mode = mode;
    }
  }

  if (status != APR_SUCCESS) {
    k = lookup_func_index(local_commands, "_CALL");
    if (local_commands[k].func) {
      self->blocks = apr_hash_get(self->modules, "DEFAULT", APR_HASH_KEY_STRING);
      if (apr_hash_get(self->blocks, "ON_ERROR", APR_HASH_KEY_STRING)) {
	local_commands[k].func(&local_commands[k], self, "ON_ERROR");
	goto exodus;
      }
    }

    worker_set_global_error(self);
//    worker_destroy(self);
    worker_conn_close_all(self);
    exit(1);
  }
exodus:
//  worker_destroy(self);
  worker_conn_close_all(self);
  apr_thread_exit(self->mythread, APR_SUCCESS);
}

/**
 * client thread
 *
 * @param thread IN thread object
 * @param selfv IN void pointer to thread data object
 *
 * @return an apr status
 */
static void * APR_THREAD_FUNC worker_thread_client(apr_thread_t * thread, void *selfv) {
  apr_status_t status;

  worker_t *self = selfv;
  self->mythread = thread;
  self->flags |= FLAGS_CLIENT;

  self->file_and_line = apr_psprintf(self->pool, "%s:-1", self->filename);

  sync_lock(self->mutex);
  ++running_threads;
  sync_unlock(self->mutex);
  
  worker_log(self, LOG_INFO, "%s start ...", self->name);

  if ((status = worker_interpret(self, self)) != APR_SUCCESS) {
    goto error;
  }

  worker_flush(self);

  if ((status = worker_test_unused(self)) != APR_SUCCESS) {
    goto error;
  }

  if ((status = worker_test_unused_errors(self)) != APR_SUCCESS) {
    goto error;
  }

error:
  worker_finally(self, status);
  return NULL;
}

/**
 * daemon thread
 *
 * @param thread IN thread object
 * @param selfv IN void pointer to thread data object
 *
 * @return an apr status
 */
static void * APR_THREAD_FUNC worker_thread_daemon(apr_thread_t * thread, void *selfv) {
  apr_status_t status;

  worker_t *self = selfv;
  self->mythread = thread;
  self->flags |= FLAGS_CLIENT;

  self->file_and_line = apr_psprintf(self->pool, "%s:-1", self->filename);

  worker_log(self, LOG_INFO, "Daemon start ...");

  worker_log(self, LOG_DEBUG, "unlock %s", self->name);

  if ((status = worker_interpret(self, self)) != APR_SUCCESS) {
    goto error;
  }

  worker_flush(self);

  if ((status = worker_test_unused(self)) != APR_SUCCESS) {
    goto error;
  }

  if ((status = worker_test_unused_errors(self)) != APR_SUCCESS) {
    goto error;
  }

error:
  /* no mather if there are other threads running set running threads to one */
  sync_lock(self->mutex);
  running_threads = 1;
  sync_unlock(self->mutex);
  worker_finally(self, status);
  return NULL;
}

/**
 * server thread
 *
 * @param thread IN thread object
 * @param selfv IN void pointer to thread data object
 *
 * @return 
 */
static void * APR_THREAD_FUNC worker_thread_server(apr_thread_t * thread, void *selfv) {
  apr_status_t status;

  worker_t *self = selfv;
  self->mythread = thread;
  self->flags |= FLAGS_SERVER;

  sync_lock(self->mutex);
  ++running_threads;
  sync_unlock(self->mutex);

  if ((status = worker_interpret(self, self)) != APR_SUCCESS) {
    goto error;
  }

  worker_flush(self);

  if ((status = worker_test_unused(self)) != APR_SUCCESS) {
    goto error;
  }

  if ((status = worker_test_unused_errors(self)) != APR_SUCCESS) {
    goto error;
  }

error:
  /* do not close listener, there may be more servers which use this 
   * listener, signal this by setting listener to NULL
   */
  self->listener = NULL;
  worker_finally(self, status);
  return NULL;
}

/**
 * listener server thread
 *
 * @param thread IN thread object
 * @param selfv IN void pointer to thread data object
 *
 * @return an apr status
 */
static void * APR_THREAD_FUNC worker_thread_listener(apr_thread_t * thread, void *selfv) {
  apr_status_t status;
  int i;
  int nolistener;
  char *last;
  char *portname;
  char *scope_id;
  char *value;
  int threads = 0;
  worker_t *clone;
  apr_threadattr_t *tattr;
  apr_thread_t *threadl;
  apr_table_t *servers;
  apr_table_entry_t *e;

  worker_t *self = selfv;
  self->mythread = thread;
  self->flags |= FLAGS_SERVER;

  sync_lock(self->mutex);
  ++running_threads;
  sync_unlock(self->mutex);

  /* TODO  ["SSL:"]["*"|<IP>|<IPv6>:]<port> ["DOWN"|<concurrent>] */
  
  portname = apr_strtok(self->additional, " ", &last);

  if (!portname) {
    worker_log_error(self, "No port defined");
    status = APR_EGENERAL;
    goto error;
  }
  
  nolistener = 0;
  value = apr_strtok(NULL, " ", &last);
  if (value && strcmp("DOWN", value) != 0) {
    threads = apr_atoi64(value);
  }
  else if (value) {
    /* do not setup listener */
    nolistener = 1;
  }
  else {
    threads = 0;
  }

#ifdef USE_SSL
  self->is_ssl = 0;
  if (strncmp(portname, "SSL:", 4) == 0) {
    self->is_ssl = 1;
    self->meth = SSLv23_server_method();
    portname += 4;
  }
  else if (strncmp(portname, "SSL2:", 4) == 0) {
    self->is_ssl = 1;
    self->meth = SSLv2_server_method();
    portname += 5;
  }
  else if (strncmp(portname, "SSL3:", 4) == 0) {
    self->is_ssl = 1;
    self->meth = SSLv3_server_method();
    portname += 5;
  }
  else if (strncmp(portname, "TLS1:", 4) == 0) {
    self->is_ssl = 1;
    self->meth = TLSv1_server_method();
    portname += 5;
  }

  if (self->is_ssl && 
      (status = worker_ssl_ctx(self, RSA_SERVER_CERT, RSA_SERVER_KEY, NULL, 0)) 
      != APR_SUCCESS) {
    goto error;
  }
#endif

  if ((status = apr_parse_addr_port(&self->listener_addr, &scope_id, 
	                            &self->listener_port, portname, 
				    self->pool)) != APR_SUCCESS) {
    goto error;
  }

  if (!self->listener_addr) {
    self->listener_addr = apr_pstrdup(self->pool, APR_ANYADDR);
  }

  if (!self->listener_port) {
    if (self->is_ssl) {
      self->listener_port = 443;
    }
    else {
      self->listener_port = 80;
    }
  }
  
  worker_log(self, LOG_INFO, "%s start on %s%s:%d", self->name, 
             self->is_ssl ? "SSL:" : "", self->listener_addr, 
	     self->listener_port);

  if (!nolistener) {
    if ((status = worker_listener_up(self, LISTENBACKLOG_DEFAULT)) != APR_SUCCESS) {
      goto error;
    }
  }
  sync_unlock(self->sync_mutex);
  worker_log(self, LOG_DEBUG, "unlock %s", self->name);

  if (threads != 0) {
    i = 0;

    if ((status = apr_threadattr_create(&tattr, self->pool)) != APR_SUCCESS) {
      goto error;
    }

    if ((status = apr_threadattr_stacksize_set(tattr, DEFAULT_THREAD_STACKSIZE))
	!= APR_SUCCESS) {
      goto error;
    }

    if ((status = apr_threadattr_detach_set(tattr, 0)) != APR_SUCCESS) {
      goto error;
    }

    servers = apr_table_make(self->pool, 10);

    while(threads == -1 || i < threads) {
      if ((status = worker_clone(&clone, self)) != APR_SUCCESS) {
	worker_log(self, LOG_ERR, "Could not clone server thread data");
	goto error;
      }
      clone->listener = self->listener;
      worker_log(self, LOG_DEBUG, "--- accept");
      if (!self->listener) {
	worker_log_error(self, "Server down");
	status = APR_EGENERAL;
	goto error;
      }

      worker_get_socket(clone, "Default", "0");
      clone->socket->is_ssl = clone->is_ssl;
      
      if ((status =
	   apr_socket_accept(&clone->socket->socket, self->listener,
			     clone->pool)) != APR_SUCCESS) {
	clone->socket->socket = NULL;
	goto error;
      }
      if ((status =
             apr_socket_timeout_set(clone->socket->socket, self->socktmo)) 
	  != APR_SUCCESS) {
        goto error;
      }
#ifdef USE_SSL
      if ((status = worker_ssl_accept(clone)) != APR_SUCCESS) {
	goto error;
      }
#endif
      worker_log(self, LOG_DEBUG, "--- create thread");
      clone->socket->socket_state = SOCKET_CONNECTED;
      clone->which = i;
      if ((status =
	   apr_thread_create(&threadl, tattr, worker_thread_server,
			     clone, self->pool)) != APR_SUCCESS) {
	goto error;
      }

      apr_table_addn(servers, self->name, (char *)threadl);

      ++i;
    }
    /* wait threads */
    e = (apr_table_entry_t *) apr_table_elts(servers)->elts;
    for (i = 0; i < apr_table_elts(servers)->nelts; ++i) {
      threadl = (apr_thread_t *) e[i].val;
      apr_thread_join(&status, threadl);
    }
  }
  else {
    if ((status = worker_interpret(self, self)) != APR_SUCCESS) {
      goto error;
    }

    worker_flush(self);

    if ((status = worker_test_unused(self)) != APR_SUCCESS) {
      goto error;
    }

    if ((status = worker_test_unused_errors(self)) != APR_SUCCESS) {
      goto error;
    }
  }

error:
  worker_finally(self, status);
  return NULL;
}

/****
 * Global object 
 ****/

/**
 * Create new global object
 *
 * @param self OUT new global object
 * @param vars IN global variable table
 * @param log_mode IN log mode
 * @param p IN pool
 *
 * @return apr status
 */
static apr_status_t global_new(global_t **self, apr_table_t *vars, 
                               int log_mode, apr_pool_t *p) {
  apr_status_t status;
  *self = apr_pcalloc(p, sizeof(global_t));

  (*self)->pool = p;
  (*self)->vars = vars;
  (*self)->log_mode = log_mode;

  (*self)->threads = apr_table_make(p, 10);
  (*self)->clients = apr_table_make(p, 5);
  (*self)->servers = apr_table_make(p, 5);
  (*self)->daemons = apr_table_make(p, 5);
  (*self)->modules = apr_hash_make(p);
  (*self)->blocks = apr_hash_make(p);
  (*self)->files = apr_table_make(p, 5);

  /* set default blocks for blocks with no module name */
  apr_hash_set((*self)->modules, "DEFAULT", APR_HASH_KEY_STRING, (*self)->blocks);

  if ((status = apr_threadattr_create(&(*self)->tattr, (*self)->pool)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_stacksize_set((*self)->tattr, DEFAULT_THREAD_STACKSIZE))
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_detach_set((*self)->tattr, 0)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_thread_cond_create(&(*self)->cond, p)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_thread_mutex_create(&(*self)->sync, 
	                                APR_THREAD_MUTEX_DEFAULT,
                                        p)) != APR_SUCCESS) {
    return status;
  }
 
  if ((status = apr_thread_mutex_create(&(*self)->mutex, 
	                                APR_THREAD_MUTEX_DEFAULT,
                                        p)) != APR_SUCCESS) {
    return status;
  }

  (*self)->state = GLOBAL_STATE_NONE;
  (*self)->socktmo = 300000000;
  (*self)->prefix = apr_pstrdup(p, "");

  return APR_SUCCESS;
}

/**
 * Global CLIENT command
 *
 * @param self IN global object
 * @param data IN additional 
 *
 * @return apr status 
 */
static apr_status_t global_END(command_t *self, global_t *global, char *data) {
  int concurrent;
  char *last;
  char *val;
  char *name;
  char *called_name;
  worker_t *clone;
  apr_status_t status;

  /* start client server deamon */
  switch (global->state) {
  case GLOBAL_STATE_CLIENT:
    if (global->file_state == GLOBAL_FILE_STATE_MODULE) {
      fprintf(stderr, "\nCLIENT not allowed in a MODULE file");
      return APR_EINVAL;
    }
    /* get number of concurrent default is 1 */
    val = apr_strtok(global->worker->additional, " ", &last);
    if (val) {
      concurrent = apr_atoi64(val);
      if (concurrent <= 0) {
	fprintf(stderr, "\nNumber of concurrent clients must be > 0");
	return EINVAL;
      }
      global->worker->additional = NULL;
    }
    else {
      concurrent = 1;
    }
    name = apr_psprintf(global->pool, "CLT%d", global->CLTs);
    ++global->CLTs;
    break; 
  case GLOBAL_STATE_SERVER:
    if (global->file_state == GLOBAL_FILE_STATE_MODULE) {
      fprintf(stderr, "\nSERVER not allowed in a MODULE file");
      return APR_EINVAL;
    }
    name = apr_psprintf(global->pool, "SRV%d", global->SRVs);
    concurrent = 1;
    ++global->SRVs;
    break; 
  case GLOBAL_STATE_BLOCK:
    /* store block */
    apr_hash_set(global->blocks, global->worker->name, APR_HASH_KEY_STRING, 
	         global->worker);
    global->state = GLOBAL_STATE_NONE;
    return APR_SUCCESS;
    break; 
  case GLOBAL_STATE_DAEMON:
    if (global->file_state == GLOBAL_FILE_STATE_MODULE) {
      fprintf(stderr, "\nDAEMON not allowed in a MODULE file");
      return APR_EINVAL;
    }
    /* get number of concurrent default is 1 */
    concurrent = 1;
    name = apr_pstrdup(global->pool, "DMN");
    break; 
  case GLOBAL_STATE_FILE:
    /* write file */
    if ((status = worker_to_file(global->worker)) != APR_SUCCESS) {
      worker_set_global_error(global->worker);
      fprintf(stderr, "\nCould not create %s: %s(%d)", global->worker->name, 
	      my_status_str(global->pool, status), status);
      return status;
    }
    apr_table_addn(global->files, global->worker->name, 
	           (const char *)global->worker);
    global->state = GLOBAL_STATE_NONE;
    return APR_SUCCESS;
    break; 
  default: 
    fprintf(stderr, "\nUnknown close of a body definition");
    return APR_ENOTIMPL;
    break; 
  }

  /* store the workers to start them later */
  global->worker->filename = global->filename;
  while (concurrent) {
    clone = NULL;
    --concurrent;
    called_name = apr_psprintf(global->pool, "%s-%d", name, concurrent);
    global->worker->name = called_name;
    global->worker->which = concurrent;
    if (concurrent) {
      if ((status = worker_clone(&clone, global->worker)) != APR_SUCCESS) {
	worker_log(global->worker, LOG_ERR, "Could not clone thread");
	return APR_EINVAL;
      }
    }

    switch (global->state) {
    case GLOBAL_STATE_CLIENT:
      apr_table_addn(global->clients, called_name, (char *) global->worker);
      break;
    case GLOBAL_STATE_SERVER:
      apr_table_addn(global->servers, called_name, (char *) global->worker);
      break;
    case GLOBAL_STATE_DAEMON:
      apr_table_addn(global->daemons, called_name, (char *) global->worker);
      break;
    }
    global->worker = clone;
  }
  /* reset */
  global->state = GLOBAL_STATE_NONE;

  return APR_SUCCESS;
}

/**
 * Global worker defintion 
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN additional 
 * @param state IN CLIENT | SERVER
 *
 * @return apr status 
 */
static apr_status_t global_worker(command_t *self, global_t *global, char *data, int state) {
  apr_status_t status;

  /* Client start */
  global->state = state;
  if ((status = worker_new(&global->worker, data, global->prefix, global, 
                           worker_interpret)) != APR_SUCCESS) {
    return status;
  }
  global->prefix = apr_pstrcat(global->pool, global->prefix, 
			     "                        ", NULL);
  return APR_SUCCESS;
}

/**
 * Global CLIENT command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN additional 
 *
 * @return apr status 
 */
static apr_status_t global_CLIENT(command_t *self, global_t *global, char *data) {
  return global_worker(self, global, data, GLOBAL_STATE_CLIENT);
}

/**
 * Global SERVER command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN additional 
 *
 * @return apr status 
 */
static apr_status_t global_SERVER(command_t *self, global_t *global, char *data) {
  return global_worker(self, global, data, GLOBAL_STATE_SERVER);
}

/**
 * global BLOCK command 
 *
 * @param self IN command object
 * @param worker IN global object
 * @param data IN name
 *
 * @return an apr status
 */
static apr_status_t global_BLOCK(command_t * self, global_t * global,
                                 char *data) {
  apr_status_t status;
  char *token;
  char *last;
  int input=1;
  int i = 0;

  while (*data == ' ') ++data;

  /* Block start */
  global->state = GLOBAL_STATE_BLOCK;

  /* Start a new worker */
  if ((status = worker_new(&global->worker, data, global->prefix, global, 
                           worker_interpret)) != APR_SUCCESS) {
    return status;
  }
  
  /* A block has its callies prefix I suppose */
  global->prefix = apr_pstrcat(global->pool, global->prefix, "", NULL);
  
  /* Get params and returns */
  /* create two tables for in/out vars */
  /* input and output vars */
  token = apr_strtok(data, " ", &last);
  if (token) {
    if (strchr(token, ':')) {
      fprintf(stderr, "\nChar ':' is not allowed in block name \"%s\"", token);
      return APR_EINVAL;
    }
    global->worker->name = data;
  }
  while (token) {
    if (strcmp(token, ":") == 0) {
      /* : is separator between input and output vars */
      input = 0;
    }
    else {
      if (input) {
	apr_table_set(global->worker->params, 
	              apr_itoa(global->worker->pbody, i), token);
      }
      else {
	apr_table_set(global->worker->retvars, 
	              apr_itoa(global->worker->pbody, i), token);
      }
      i++;
    }
    token = apr_strtok(NULL, " ", &last);
  }

  return APR_SUCCESS;
}

/**
 * global FILE command 
 *
 * @param self IN command object
 * @param worker IN global object
 * @param data IN name
 *
 * @return an apr status
 */
static apr_status_t global_FILE(command_t * self, global_t * global,
                                char *data) {
  apr_status_t status;

  while (*data == ' ') ++data;
  
  /* Block start */
  global->state = GLOBAL_STATE_FILE;

  /* Start a new worker */
  if ((status = worker_new(&global->worker, data, global->prefix, global, 
                           worker_interpret)) != APR_SUCCESS) {
    return status;
  }

  global->worker->name = data;
  
  /* A block has its callies prefix I suppose */
  global->prefix = apr_pstrcat(global->pool, global->prefix, "", NULL);

  /* open file */
  return APR_SUCCESS;
}

/**
 * Global DAEMON command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN additional 
 *
 * @return apr status 
 */
static apr_status_t global_DAEMON(command_t *self, global_t *global, char *data) {
  return global_worker(self, global, data, GLOBAL_STATE_DAEMON);
}

/**
 * Global EXEC command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN shell command 
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_EXEC(command_t *self, global_t *global, char *data) {
  apr_status_t status;
  worker_t *worker;

  int i = 0;
  
  while (data[i] == ' ') {
    ++i;
  }

  if ((status = worker_new(&worker, &data[i], "", global, worker_interpret))
      != APR_SUCCESS) {
    return status;
  }
  worker_add_line(worker, apr_psprintf(global->pool, "%s:%d", global->filename,
	                               global->line_nr), 
		  apr_pstrcat(worker->pool, "_EXEC ", &data[i], NULL));
  status = worker_interpret(worker, worker);
  if (status != APR_SUCCESS) {
    worker_set_global_error(worker);
  }

  worker_destroy(worker);

  return status;
}

/**
 * Global SET command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN key=value
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_SET(command_t *self, global_t *global, char *data) {
  char *last;
  char *key;
  char *val;
  
  int i = 0;
  
  while (data[i] == ' ') {
    ++i;
  }
  key = apr_strtok(&data[i], "=", &last);
  for (i = 0; key[i] != 0 && strchr(VAR_ALLOWED_CHARS, key[i]); i++); 
  if (key[i] != 0) {
    fprintf(stderr, "\nChar '%c' is not allowed in \"%s\"", key[i], key);
    success = 0;
    return APR_EINVAL;
  }

  val = apr_strtok(NULL, "", &last);
  if (val) {
    apr_table_set(global->vars, key, val);
  }
  else {
    apr_table_set(global->vars, key, "");
  }

  return APR_SUCCESS;
}

/**
 * Use to define a MODULE. Used to make a name space for BLOCKs.
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN MODULE name 
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_MODULE(command_t * self, global_t * global,
                                  char *data) {
  apr_hash_t *blocks;

  while (*data == ' ') ++data;
  global->file_state = GLOBAL_FILE_STATE_MODULE;
 
  if (strcmp(data, "DEFAULT") == 0) {
    fprintf(stderr, "\nModule name \"%s\" is not allowed", data);
    return APR_EINVAL;
  }

  if (!(blocks = apr_hash_get(global->modules, data, APR_HASH_KEY_STRING))) {
    blocks = apr_hash_make(global->pool);
    apr_hash_set(global->modules, data, APR_HASH_KEY_STRING, blocks);
  }

  global->blocks = blocks;

  return APR_SUCCESS;
}

/**
 * Global INCLUDE command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN relative to caller or absolut path
 *
 * @return APR_SUCCESS
 */
static apr_status_t interpret_recursiv(apr_file_t *fp, global_t *global); 
static apr_status_t global_INCLUDE(command_t *self, global_t *global, char *data) {
  apr_status_t status;
  apr_file_t *fp;
  const char *prev_filename;
  char **argv;
  int i;

  status = APR_ENOENT;
  if (apr_tokenize_to_argv(data, &argv, global->pool) == APR_SUCCESS) {
    for (i = 0; argv[i] != NULL; i++) {
      /* open include file */
      if ((status =
	   apr_file_open(&fp, argv[i], APR_READ, APR_OS_DEFAULT,
			 global->pool)) == APR_SUCCESS) {
	break;
      }
    }
  }

  if (status != APR_SUCCESS) {
    fprintf(stderr, "\nInclude file %s not found", data);
    return APR_ENOENT;
  }

  ++global->recursiv;
  prev_filename = global->filename;
  global->filename = argv[i];
  status = interpret_recursiv(fp, global);
  /* TODO reset module name */
  if (!(global->blocks = apr_hash_get(global->modules, "DEFAULT", APR_HASH_KEY_STRING))) {
    fprintf(stderr, "\nDEFAULT module not found?!\n");
    return APR_EGENERAL;
  }
  global->file_state = GLOBAL_FILE_STATE_NORMAL;
  global->filename = prev_filename;

  apr_file_close(fp);

  return status;
}

/**
 * Global TIMEOUT command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN timeout (starting spaces are possible) 
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_TIMEOUT(command_t *self, global_t *global, char *data) {
  int i = 0;
  
  while (data[i] == ' ') {
    ++i;
  }

  global->socktmo = 1000 * apr_atoi64(&data[i]);

  return APR_SUCCESS;
}

/**
 * Global AUTO_CLOSE command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN timeout (starting spaces are possible) 
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_AUTO_CLOSE(command_t *self, global_t *global, char *data) {
  int i = 0;
  
  while (data[i] == ' ') {
    ++i;
  }

  if (strcasecmp(&data[i], "on") == 0) {
    global->flags |= FLAGS_AUTO_CLOSE;
  }
  else {
    global->flags &= ~FLAGS_AUTO_CLOSE;
  }
  
  return APR_SUCCESS;
}

/**
 * Global PROCESS command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN n 
 *
 * @return APR_SUCCESS
 */
#if APR_HAS_FORK
static apr_status_t global_PROCESS(command_t *self, global_t *global, char *data) {
  apr_proc_t proc;
  apr_status_t status;
  int n;
  char *copy;
  char *last;
  char *no;
  char *var;
  int i = 0; 

  while (data[i] == ' ') { 
    ++i; 
  } 
  if(!data[i]) { 
    return APR_EGENERAL; 
  } 
  copy = apr_pstrdup(global->pool, &data[i]); 
  copy = my_replace_vars(global->pool, copy, global->vars, 0);

  no = apr_strtok(copy, " ", &last);
  var = apr_strtok(NULL, " ", &last);

  if (!no) {
    return APR_EGENERAL;
  }

  n = apr_atoi64(no);

  for (i = 0; i < n; i++) {
    status = apr_proc_fork(&proc, global->pool);
    if (APR_STATUS_IS_INCHILD(status)) {
      if (var && strlen(var)) {
        apr_table_set(global->vars, var, apr_itoa(global->pool, i));
      }
      return APR_SUCCESS;
    }
  }

  for (i = 0; i < n; i++) {
    /* wait for termination */
    int exitcode;
    apr_exit_why_e why;
    apr_proc_wait_all_procs(&proc, &exitcode, &why, APR_WAIT, global->pool); 
    if (exitcode != 0) {
      success = 1;
    }
  }

  /* and exit */
  if (success != 0) {
    exit(1);
  }
  exit(0);
}
#endif

/**
 * Global GO command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_GO(command_t *self, global_t *global, char *data) {
  apr_status_t status;
  apr_table_entry_t *e;
  int i;
  worker_t *worker;
  apr_thread_t *thread;

  /* start all daemons first */
  e = (apr_table_entry_t *) apr_table_elts(global->daemons)->elts;
  for (i = 0; i < apr_table_elts(global->daemons)->nelts; ++i) {
    worker = (void *)e[i].val;
    if ((status =
	 apr_thread_create(&thread, global->tattr, worker_thread_daemon,
			   worker, global->pool)) != APR_SUCCESS) {
      return status;
    }
  }
  apr_table_clear(global->daemons);
  /* start all servers */
  e = (apr_table_entry_t *) apr_table_elts(global->servers)->elts;
  for (i = 0; i < apr_table_elts(global->servers)->nelts; ++i) {
    sync_lock(global->sync);
    worker = (void *)e[i].val;
    if ((status =
	 apr_thread_create(&thread, global->tattr, worker_thread_listener,
			   worker, global->pool)) != APR_SUCCESS) {
      return status;
    }
    apr_table_addn(global->threads, worker->name, (char *) thread);
  }
  apr_table_clear(global->servers);

  /* start all clients */
  sync_lock(global->sync);
  sync_unlock(global->sync);
  e = (apr_table_entry_t *) apr_table_elts(global->clients)->elts;
  for (i = 0; i < apr_table_elts(global->clients)->nelts; ++i) {
    worker = (void *)e[i].val;
    if ((status =
	 apr_thread_create(&thread, global->tattr, worker_thread_client,
			   worker, global->pool)) != APR_SUCCESS) {
      return status;
    }
    apr_table_addn(global->threads, worker->name, (char *) thread);
  }
  apr_table_clear(global->clients);

  return APR_SUCCESS;
}

/**
 * Recursiv interpreter. Can handle recursiv calls to with sub files i.e. INCLUDE.
 *
 * @param fp IN current open file
 * @param vars IN global variable table
 * @param log_mode IN log mode
 * @param p IN pool
 * @param threads IN table of running threads
 * @param CLTs IN number of current client
 * @param SRVs IN number of current server
 * @param recursiv IN recursiv level to avoid infinit recursion
 *
 * @return apr status
 */
static apr_status_t interpret_recursiv(apr_file_t *fp, global_t *global) {
  apr_status_t status;
  bufreader_t *bufreader;
  char *line;
  int k;
  int i;
  int line_nr;

  if (global->recursiv > 8) {
    fprintf(stderr, "\nRecursiv inlcudes too deep");
    exit(1);
  }

  if ((status = bufreader_new(&bufreader, fp, global->pool)) != APR_SUCCESS) {
    return status;
  }

  line_nr = 0;
  while (bufreader_read_line(bufreader, &line) == APR_SUCCESS) {
    ++line_nr;
    global->line_nr = line_nr;
    i = 0;
    if (line[i] != '#' && line[i] != 0) {
      /* lets see if we can start thread */
      if (global->state != GLOBAL_STATE_NONE) {
	/* replace all variables */
	line = my_replace_vars(global->pool, &line[i], global->vars, 0);

        if ((strlen(line) >= 3 && strncmp(line, "END", 3) == 0)) { 
	  i += 3;
	  if ((status = global_END(&global_commands[0], global, &line[i])) != APR_SUCCESS) {
	    return status;
	  }
        }
        else if (line[0] == '_' && 
	         (status = worker_add_line(global->worker, 
		                           apr_psprintf(global->pool, "%s:%d", 
					                global->filename, 
							line_nr), line)) !=
                 APR_SUCCESS) {
          return status;
        }
	else if (line[0] != '_') {
          fprintf(stderr, "\nWrong scope:%d: %s is not a local command, close body with \"END\"", global->line_nr, line);
	  return APR_EGENERAL;
	}
      }
      else {
	/* replace all variables */
	line = my_replace_vars(global->pool, &line[i], global->vars, 1);

        /* lookup function index */
	i = 0;
        k = lookup_func_index(global_commands, line);
	/* found command? */
	if (global_commands[k].func) {
	  i += strlen(global_commands[k].name);
	  if ((status =
	       global_commands[k].func(&global_commands[k], global,
				       &line[i])) != APR_SUCCESS) {
	    return status;
	  }
	}
	else {
	  /* I ignore unknown commands to be able to set tags like 
	   * DECLARE_SLOW_TEST
	   */
	}
      }
    }
  }

  if (global->state != GLOBAL_STATE_NONE) {
    fprintf(stderr, "\n<none>:%d: Missing END", global->line_nr);
    return APR_EGENERAL;
  }

  return APR_SUCCESS;
}

/**
 * root interpreter
 *
 * @param fp IN open file to interpret
 * @param vars IN host and port file
 * @param log_mode IN log mode
 * @param p IN pool
 *
 * @return an apr status
 */
static apr_status_t interpret(apr_file_t * fp, apr_table_t * vars,
                              int log_mode, apr_pool_t * p) {
  apr_status_t status;
  apr_status_t retstat = APR_SUCCESS;
  apr_table_entry_t *e;
  int i;
  const char *name;
  global_t *global;
  apr_thread_t *thread;

  if ((status = global_new(&global, vars, log_mode, p)) 
      != APR_SUCCESS) {
    return status;
  }
  
  process_global = global;
  
  apr_file_name_get(&global->filename, fp);
  if ((status = interpret_recursiv(fp, global)) != APR_SUCCESS) {
    return status;
  }

  global_GO(&global_commands[1], global, NULL);
  
  /* wait on thermination of all started threads */
  e = (apr_table_entry_t *) apr_table_elts(global->threads)->elts;
  for (i = 0; i < apr_table_elts(global->threads)->nelts; ++i) {
    thread = (apr_thread_t *) e[i].val;
    name = e[i].key;
    if ((retstat = apr_thread_join(&status, thread))) {
      return retstat;
    }
    if (status != APR_SUCCESS) {
      return status;
    }
  }

  return retstat;
}

apr_getopt_option_t options[] = {
  { "version", 'V', 0, "Print version number and exit" },
  { "help", 'h', 0, "Display usage information (this message)" },
  { "suppress", 'n', 0, "do no print start and OK|FAILED" },
  { "silent", 's', 0, "silent mode" },
  { "error", 'e', 0, "log level error" },
  { "warn", 'w', 0, "log level warn" },
  { "info", 'i', 0, "log level info" },
  { "debug", 'd', 0, "log level debug" },
  { "list-commands", 'L', 0, "List all available script commands" },
  { "help-command", 'C', 1, "Print help for specific command" },
  { "timestamp", 'T', 0, "Time stamp on every run" },
  { "shell", 'S', 0, "Shell mode" },
  { NULL, 0, 0, NULL }
};

/** 
 * display usage information
 *
 * @progname IN name of the programm
 */
static void usage(const char *progname) {
  int i = 0;

  fprintf(stdout, 
"%s is a script based tool for testing and benchmarking web applications, \n"
"web servers, proxy servers and web browsers. httest can emulate clients and \n"
"servers in the same test script, very useful for testing proxys.\n", progname);
  fprintf(stdout, "\nUsage: %s [OPTIONS] scripts\n", progname);
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
  fprintf(stdout, "\nExamples:");
  fprintf(stdout, "\n%s script.htt", progname);
  fprintf(stdout, "\n\n%s -Ts script.htt", progname);
  fprintf(stdout, "\n");
  fprintf(stdout, "\nReport bugs to http://sourceforge.net/projects/htt");
  fprintf(stdout, "\n");
}

/**
 * Print formated command help
 *
 * @param p IN pool
 * @param command IN command to print
 */
static void print_command_formated(apr_pool_t *p, command_t command) {
  char *help;
  char *last;
  char *val;

  fprintf(stdout, "%s %s", command.name, 
	  command.syntax);
  help = apr_pstrdup(p, command.help);
  val = apr_strtok(help, "\n", &last);
  while (val) {
    fprintf(stdout, "\n\t%s", val);
    val = apr_strtok(NULL, "\n", &last);
  }
}

/**
 * Show all commands
 *
 * @param p IN pool
 */
static void show_commands(apr_pool_t *p) {
  int i;

  fprintf(stdout, "Global commands");
  i = 0;
  while (global_commands[i].name) { 
    fprintf(stdout, "\n");
    fprintf(stdout, "\t%s %s", global_commands[i].name, 
	    global_commands[i].syntax);
    ++i;
  }
  
  fprintf(stdout, "\n\nLocal commands");
  i = 0;
  while (local_commands[i].name) { 
    fprintf(stdout, "\n");
    fprintf(stdout, "\t%s %s", local_commands[i].name, 
	    local_commands[i].syntax);
    ++i;
  }
  fprintf(stdout, "\n\n(Get detailed help with --help-command <command>)\n");
  fflush(stdout);
  exit(0);
}

/**
 * Print help for specified command
 *
 * @param pool IN pool
 * @param command IN command name
 */
static void show_command_help(apr_pool_t *p, const char *command) {
  int i;

  for (i = 0; global_commands[i].name; i++) {
    if (strcmp(command, global_commands[i].name) == 0) {
      print_command_formated(p, global_commands[i]);
      goto exit;
    }
  }
  for (i = 0; local_commands[i].name; i++) {
    if (strcmp(command, local_commands[i].name) == 0) {
      print_command_formated(p, local_commands[i]);
      goto exit;
    }
  }

  fprintf(stdout, "\ncommand: %s do not exist\n\n", command);

exit:
  fprintf(stdout, "\n");
  fflush(stdout);
}

/**
 * own exit func
 */
static void my_exit() {
  int i;
  worker_t *worker;

  if (process_global) {
    apr_table_entry_t *e = 
      (apr_table_entry_t *) apr_table_elts(process_global->files)->elts;
    for (i = 0; i < apr_table_elts(process_global->files)->nelts; i++) {
      worker = (worker_t *)e[i].val;
      apr_file_remove(worker->name, process_global->pool);
    }
  }

  if (!success) {
    fprintf(stderr, " FAILED\n");
    fflush(stderr);
  }
  else {
    fprintf(stdout, " OK\n");
    fflush(stdout);
  }
}

static void no_output_exit() {
}

/** 
 * sort out command-line args and call test 
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
  char *cur_file;
  apr_file_t *fp;
  apr_table_t *vars_table;
  int log_mode;
#define MAIN_FLAGS_NONE 0
#define MAIN_FLAGS_PRINT_TSTAMP 1
#define MAIN_FLAGS_USE_STDIN 2
#define MAIN_FLAGS_NO_OUTPUT 4
  int flags;
  apr_time_t time;
  char time_str[256];

  srand(apr_time_now()); 
  
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  /* block broken pipe signal */
#if !defined(WIN32)
  apr_signal_block(SIGPIPE);
#endif
  
  /* set default */
  log_mode = LOG_CMD;
  flags = MAIN_FLAGS_NONE;

#ifdef USE_SSL
#ifndef OPENSSL_NO_ENGINE
  ENGINE_load_builtin_engines();
#endif
#endif
  
  /* get options */
  apr_getopt_init(&opt, pool, argc, argv);
  while ((status = apr_getopt_long(opt, options, &c, &optarg)) == APR_SUCCESS) {
    switch (c) {
    case 'h':
      usage(filename(pool, argv[0]));
      exit(0);
      break;
    case 'V':
      copyright(filename(pool, argv[0]));
      exit(0);
      break;
    case 'n':
      flags |= MAIN_FLAGS_NO_OUTPUT; 
      break;
    case 's':
      log_mode = LOG_NONE;
      break;
    case 'e':
      log_mode = LOG_ERR;
      break;
    case 'd':
      log_mode = LOG_DEBUG;
      break;
    case 'w':
      log_mode = LOG_WARN;
      break;
    case 'i':
      log_mode = LOG_INFO;
      break;
    case 'L':
      show_commands(pool);
      break;
    case 'C':
      show_command_help(pool, apr_pstrdup(pool, optarg)); 
      exit(0);
      break;
    case 'T':
      flags |= MAIN_FLAGS_PRINT_TSTAMP; 
      break;
    case 'S':
      flags |= MAIN_FLAGS_USE_STDIN; 
      break;
    }
  }

  /* test for wrong options */
  if (!APR_STATUS_IS_EOF(status)) {
    fprintf(stderr, "try \"%s --help\" to get more information\n", filename(pool, argv[0]));
    exit(1);
  }

  /* test at least one file */
  if (!(flags & MAIN_FLAGS_USE_STDIN) && !(argc - opt->ind)) {
    fprintf(stderr, "%s: wrong number of arguments\n\n", filename(pool, 
	    argv[0]));
    fprintf(stderr, "try \"%s --help\" to get more information\n", filename(pool, argv[0]));
    exit(1);
  }

  if (flags & MAIN_FLAGS_NO_OUTPUT) {
    atexit(no_output_exit);
  }
  else {
    atexit(my_exit);
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

  /* do for all files (no wild card support) */
  while (flags & MAIN_FLAGS_USE_STDIN || argc - opt->ind) {
    if (flags & MAIN_FLAGS_USE_STDIN) {
      cur_file = apr_pstrdup(pool, "<stdin>");
    }
    else {
      cur_file = apr_pstrdup(pool, opt->argv[opt->ind++]);
    }

    if (flags & MAIN_FLAGS_USE_STDIN) {
      fprintf(stdout, "simple htt shell\n");
    }
    else if (flags & MAIN_FLAGS_PRINT_TSTAMP) {
      time = apr_time_now();
      if ((status = apr_ctime(time_str, time)) != APR_SUCCESS) {
	fprintf(stderr, "Could not format time: %s (%d)\n", 
	        my_status_str(pool, status), status);
	success = 0;
	exit(1);
      }
      if (!(flags & MAIN_FLAGS_NO_OUTPUT)) {
	fprintf(stdout, "%s  run %-54s\t", time_str, cur_file);
      }
    }
    else {
      if (!(flags & MAIN_FLAGS_NO_OUTPUT)) {
	fprintf(stdout, "run %-80s\t", cur_file);
      }
    }
    fflush(stdout);

    /* open current file */
    if (flags & MAIN_FLAGS_USE_STDIN) {
      if ((status = apr_file_open_stdin(&fp, pool)) != APR_SUCCESS) {
	fprintf(stderr, "Could not open stdin: %s (%d)\n", 
	        my_status_str(pool, status), status);
	success = 0;
	exit(1);
      }
    }
    else if ((status =
              apr_file_open(&fp, cur_file, APR_READ, APR_OS_DEFAULT,
                            pool)) != APR_SUCCESS) {
      fprintf(stderr, "\nCould not open %s: %s (%d)", cur_file,
	      my_status_str(pool, status), status);
      success = 0;
      exit(1);
    }

    /* create a global vars table */
    vars_table = apr_table_make(pool, 20);

    /* interpret current file */
    if ((status = interpret(fp, vars_table, log_mode, pool)) != APR_SUCCESS) {
      success = 0;
      exit(1);
    }

    /* close current file */
    apr_file_close(fp);

    if (flags & MAIN_FLAGS_USE_STDIN) {
      break;
    }
  }
  apr_pool_destroy(pool);

  return 0;
}

