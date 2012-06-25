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

/* Use STACK from openssl to sort commands */
#include <openssl/ssl.h>

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
#include <apr_hooks.h>

#include <pcre.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#include "file.h"
#include "transport.h"
#include "socket.h"
#include "regex.h"
#include "util.h"
#include "replacer.h"
#include "worker.h"
#include "module.h"
#include "eval.h"
#include "tcp_module.h"

/************************************************************************
 * Defines 
 ***********************************************************************/

/************************************************************************
 * Structurs
 ***********************************************************************/
typedef struct global_replacer_s {
  apr_pool_t *ptmp;
  store_t *store;
} global_replacer_t;

/************************************************************************
 * Globals 
 ***********************************************************************/
extern module_t modules[];

static void show_commands(apr_pool_t *p, global_t *global); 
static void show_command_help(apr_pool_t *p, global_t *global, 
                              const char *command); 

static apr_status_t command_EXIT(command_t * self, worker_t * worker, 
                                 char *data, apr_pool_t *ptmp);
static apr_status_t command_IF(command_t * self, worker_t * worker,
                               char *data, apr_pool_t *ptmp); 
static apr_status_t command_LOOP(command_t *self, worker_t *worker, 
                                 char *data, apr_pool_t *ptmp); 
static apr_status_t command_FOR(command_t *self, worker_t *worker, 
                                 char *data, apr_pool_t *ptmp); 
static apr_status_t command_BPS(command_t *self, worker_t *worker, 
                                char *data, apr_pool_t *ptmp); 
static apr_status_t command_RPS(command_t *self, worker_t *worker, 
                                 char *data, apr_pool_t *ptmp); 
static apr_status_t command_SOCKET(command_t *self, worker_t *worker, 
                                   char *data, apr_pool_t *ptmp); 
static apr_status_t command_PROCESS(command_t *self, worker_t *worker, 
                                   char *data, apr_pool_t *ptmp); 
static apr_status_t command_ERROR(command_t *self, worker_t *worker, 
                                  char *data, apr_pool_t *ptmp); 

static apr_status_t global_GO(command_t *self, global_t *global, 
			     char *data, apr_pool_t *ptmp); 
static apr_status_t global_EXIT(command_t *self, global_t *global, 
			     char *data, apr_pool_t *ptmp); 
static apr_status_t global_START(command_t *self, global_t *global, 
			         char *data, apr_pool_t *ptmp); 
static apr_status_t global_JOIN(command_t *self, global_t *global, 
			        char *data, apr_pool_t *ptmp); 
static apr_status_t global_END(command_t *self, global_t *global, 
			      char *data, apr_pool_t *ptmp); 
static apr_status_t global_DAEMON(command_t *self, global_t *global, 
				 char *data, apr_pool_t *ptmp); 
static apr_status_t global_BLOCK(command_t *self, global_t *global,
				char *data, apr_pool_t *ptmp);
static apr_status_t global_FILE(command_t *self, global_t *global,
				char *data, apr_pool_t *ptmp);
static apr_status_t global_CLIENT(command_t *self, global_t *global, 
				 char *data, apr_pool_t *ptmp); 
static apr_status_t global_SERVER(command_t *self, global_t *global, 
				 char *data, apr_pool_t *ptmp); 
static apr_status_t global_EXEC(command_t *self, global_t *global, 
			       char *data, apr_pool_t *ptmp); 
static apr_status_t global_SET(command_t *self, global_t *global, 
			      char *data, apr_pool_t *ptmp); 
static apr_status_t global_GLOBAL(command_t *self, global_t *global, 
			          char *data, apr_pool_t *ptmp); 
static apr_status_t global_PATH(command_t *self, global_t *global, 
				char *data, apr_pool_t *ptmp); 
static apr_status_t global_INCLUDE(command_t *self, global_t *global, 
				   char *data, apr_pool_t *ptmp); 
static apr_status_t global_TIMEOUT(command_t *self, global_t *global, 
				  char *data, apr_pool_t *ptmp); 
static apr_status_t global_AUTO_CLOSE(command_t *self, global_t *global, 
				      char *data, apr_pool_t *ptmp); 
static apr_status_t global_PROCESS(command_t *self, global_t *global, 
				   char *data, apr_pool_t *ptmp); 
static apr_status_t global_MODULE(command_t *self, global_t *global, 
				  char *data, apr_pool_t *ptmp); 

command_t global_commands[] = {
  {"END", (command_f )global_END, "", 
  "Close CLIENT|SERVER body",
  COMMAND_FLAGS_NONE},
  {"GO", (command_f )global_GO, "", 
  "Starts all defined clients, servers and daemons. "
  "All started client and servers will be joined. "
  "It is actually a START followed by JOIN.",
  COMMAND_FLAGS_NONE},
  {"START", (command_f )global_START, "", 
  "Starts all defined clients, servers and daemons.",
  COMMAND_FLAGS_NONE},
  {"JOIN", (command_f )global_JOIN, "", 
  "All started client and servers will be joined, only makes sense after START.",
  COMMAND_FLAGS_NONE},
  {"EXIT", (command_f )global_EXIT, "", 
  "Graceful script termination, useful for shell mode.",
  COMMAND_FLAGS_NONE},
  {"CLIENT", (command_f )global_CLIENT, "[<number of concurrent clients>]", 
  "Client body start, close it with END and a newline",
  COMMAND_FLAGS_NONE},
  {"SERVER", (command_f )global_SERVER, "[<SSL>:]<addr_port> [<number of concurrent servers>]", 
  "Server body start, close it with END and a newline,\n"
  "Do load server.cert.pem and server.key.pem if found in local directory,\n"
  "number of concurrent servers, -1 for unlimited,\n"
  "<SSL>: SSL, SSL2, SSL3, DTLS1, TLS1"
#if (OPENSSL_VERSION_NUMBER >= 0x1000102fL)
  ", TLS1.1, TLS1.2"
#endif
  "\n"
  "<addr_port>: 8080                (just the port number)\n"
  "             www.apache.org      (just the hostname)\n"
  "             www.apache.org:8080 (hostname and port number)\n"
  "             [fe80::1]:80        (IPv6 numeric address string only)\n",
  COMMAND_FLAGS_NONE},
  {"EXEC", (command_f )global_EXEC, "<shell command>", 
  "Execute a shell command, attention executes will not join CLIENT/SERVER",
  COMMAND_FLAGS_NONE},
  {"SET", (command_f )global_SET, "<variable>=<value>", 
  "Store a value in a global variable",
  COMMAND_FLAGS_NONE},
  {"GLOBAL", (command_f )global_GLOBAL, "<variable-name>+", 
  "Define the given variable as global, this is shared over all threads",
  COMMAND_FLAGS_NONE},
  {"PATH", (command_f )global_PATH, "<include paths colon separated>", 
  "Defines a set of path where INCLUDE looks first for there include files",
  COMMAND_FLAGS_NONE},
  {"INCLUDE", (command_f )global_INCLUDE, "<include file>", 
  "Load and execute defined include file,\n"
  "current path is taken the callers current path",
  COMMAND_FLAGS_NONE},
  {"TIMEOUT", (command_f )global_TIMEOUT, "<timeout in ms>", 
  "Defines global socket timeout",
  COMMAND_FLAGS_NONE},
  {"AUTO_CLOSE", (command_f )global_AUTO_CLOSE, "on|off", 
  "Handle Connection: close header and close automaticaly the given connection",
  COMMAND_FLAGS_NONE},
#if APR_HAS_FORK
  {"PROCESS", (command_f )global_PROCESS, "<n>", 
  "Run the script in <n> process simultanous",
  COMMAND_FLAGS_NONE},
#endif
  {"BLOCK", (command_f )global_BLOCK, "<name>", 
  "Store a block of commands to call it from a CLIENT/SERVER/BLOCK",
  COMMAND_FLAGS_NONE},
  {"FILE", (command_f )global_FILE, "<name>", 
  "Create a temporary file with given name",
  COMMAND_FLAGS_NONE},
  {"DAEMON", (command_f )global_DAEMON, "", 
  "Daemon body start, close it with END and a newline. \n"
  "A daemon will not join CLIENT/SERVER and could therefore be used\n"
  "for supervisor jobs" ,
  COMMAND_FLAGS_NONE},
  {"MODULE", (command_f )global_MODULE, "<name>",
   "Define a module to collect a number of BLOCKs. If you call a BLOCK within"
   "a module, you need to prefix the BLOCK name with \"<name>:\"",
  COMMAND_FLAGS_NONE}, 
  {NULL, NULL, NULL,
  NULL ,
  COMMAND_FLAGS_NONE}
};

command_t local_commands[] = {
  {"__", (command_f )command_DATA, "<string>", 
  "Send <string> to the socket with a CRLF at the end of line",
  COMMAND_FLAGS_NONE},
  {"_-", (command_f )command_NOCRLF, "<string>", 
  "Same like __ but no CRLF at the end of line",
  COMMAND_FLAGS_NONE},
  {"_FLUSH", (command_f )command_FLUSH, "", 
  "Flush the cached lines, \n"
  "the AUTO Content-Length calculation will take place here",
  COMMAND_FLAGS_NONE},
  {"_CHUNK", (command_f )command_CHUNK, "", 
  "Mark the end of a chunk block, all data after last _FLUSH are counted,\n"
  "does automatic add chunk info",
  COMMAND_FLAGS_NONE},
  {"_REQ", (command_f )command_REQ, "<host> [<SSL>:]<port>[:<tag>] [<cert-file> <key-file> [<ca-cert-file>]]", 
  "Open connection to defined host:port, with SSL support.\n"
  "If connection exist no connect will be performed\n"
  "<SSL>: SSL, SSL2, SSL3, DTLS1, TLS1"
#if (OPENSSL_VERSION_NUMBER >= 0x1000102fL)
  ", TLS1.1, TLS1.2"
#endif
  "\n"
  "<host>: host name or IPv4/IPv6 address (IPv6 address must be surrounded\n"
  "        in square brackets)\n"
  "<tag>: Additional tag info do support multiple connection to one target\n"
  "<cert-file>, <key-file> and <ca-cert-file> are optional for client/server authentication",
  COMMAND_FLAGS_NONE},	
  {"_RESWAIT", (command_f )command_RESWAIT, "", 
   "Do use _RES IGNORE_MONITORS instead" ,
  COMMAND_FLAGS_DEPRECIATED},
  {"_RES", (command_f )command_RES, "[IGNORE_MONITORS]", 
  "Wait for a connection accept \n"
  "IGNORE_MONITORS do ignore all connection pings without data",
  COMMAND_FLAGS_NONE},
  {"_WAIT", (command_f )command_WAIT, "[<amount of bytes>]", 
  "Wait for data and receive them.\n"
  "EXPECT and MATCH definitions will be checked here on the incoming data.\n"
  "Optional you could receive a specific amount of bytes" ,
  COMMAND_FLAGS_NONE},
  {"_CLOSE", (command_f )command_CLOSE, "", 
  "Close the current connection and set the connection state to CLOSED",
  COMMAND_FLAGS_NONE},
  {"_EXPECT", (command_f )command_EXPECT, ".|headers|body|error|exec|var() \"|'[!]<regex>\"|'", 
  "Define what data we do or do not expect on a WAIT command.\n"
  "Negation with a leading '!' in the <regex>",
  COMMAND_FLAGS_NONE},
  {"_MATCH", (command_f )command_MATCH, "(.|headers|body|error|exec|var()) \"|'<regex>\"|' <variable>", 
   "Define a regex with a match which should be stored in <variable> and do fail if no match",
  COMMAND_FLAGS_NONE},
  {"_GREP", (command_f )command_GREP, "(.|headers|body|error|exec|var()) \"|'<regex>\"|' <variable>", 
   "Define a regex with a match which should be stored in <variable> and do not fail if no match",
  COMMAND_FLAGS_NONE},
  {"_ASSERT", (command_f )command_ASSERT, "<expression>", 
   "Check if expression is true fail otherwise",
  COMMAND_FLAGS_NONE},
  {"_SEQUENCE", (command_f )command_MATCH_SEQ, "<var-sequence>", 
   "Define a sequence of _MATCH variables which must apear in this order",
  COMMAND_FLAGS_NONE},
  {"_BREAK", (command_f )command_BREAK, "", 
   "Break a loop",
  COMMAND_FLAGS_NONE},
#if APR_HAS_FORK
  {"_PROC_WAIT", (command_f )command_PROC_WAIT, "<name>*", 
  "Wait for processes <name>*\n",
  COMMAND_FLAGS_NONE},
#endif
  {"_TIMEOUT", (command_f )command_TIMEOUT, "<miliseconds>", 
   "Set socket timeout of current socket",
  COMMAND_FLAGS_NONE},
  {"_SET", (command_f )command_SET, "<variable>=<value>", 
  "Store a value in a local variable",
  COMMAND_FLAGS_NONE},
  {"_UNSET", (command_f )command_UNSET, "<variable>", 
  "Delete variable",
  COMMAND_FLAGS_NONE},
  {"_EXEC", (command_f )command_EXEC, "<shell command>", 
  "Execute a shell command, _EXEC| will pipe the incoming stream on the\n"
  "socket in to the called shell command",
  COMMAND_FLAGS_NONE},
  {"_PIPE", (command_f )command_PIPE, "[chunked [<chunk_size>]]", 
  "Start a pipe for stream the output of EXEC to the socket stream,\n" 
  "wiht optional chunk support",
  COMMAND_FLAGS_NONE},
  {"_SOCKSTATE", (command_f )command_SOCKSTATE, "<variable>", 
  "Stores connection state CLOSED or CONNECTED in the <variable>",
  COMMAND_FLAGS_NONE},
  {"_EXIT", (command_f )command_EXIT, "[OK|FAILED]", 
  "Exits with OK or FAILED default is FAILED",
  COMMAND_FLAGS_NONE},
  {"_HEADER", (command_f )command_HEADER, "ALLOW|FILTER <header name>", 
  "Defines allowed headers or headers to filter,\n"
  "default all headers are allowed and no headers are filtered.\n"
  "Filter only for receive mechanisme",
  COMMAND_FLAGS_NONE},
  {"_SENDFILE", (command_f )command_SENDFILE, "<file>", 
  "Send file over http",
  COMMAND_FLAGS_NONE},
  {"_DEBUG", (command_f )command_DEBUG, "<string>", 
  "Prints to stderr for debugging reasons",
  COMMAND_FLAGS_NONE},
  {"_UP", (command_f )command_UP, "", 
  "Setup listener",
  COMMAND_FLAGS_NONE},
  {"_DOWN", (command_f )command_DOWN, "", 
  "Shutdown listener",
  COMMAND_FLAGS_NONE},
  {"_CALL", (command_f )command_CALL, "<name of block>", 
  "Call a defined block",
  COMMAND_FLAGS_NONE},
  {"_LOG_LEVEL_SET", (command_f )command_LOG_LEVEL_SET, "<level>", 
  "Level is a number 0-4",
  COMMAND_FLAGS_NONE},
  {"_LOG_LEVEL_GET", (command_f )command_LOG_LEVEL_GET, "<variable>", 
  "Store log level into <variable>",
  COMMAND_FLAGS_NONE},
  {"_LOG_LEVEL", (command_f )command_LOG_LEVEL_SET, "<level>", 
  "Level is a number 0-4",
  COMMAND_FLAGS_NONE},
  {"_RECV", (command_f )command_RECV, "<bytes>|POLL|CHUNKED|CLOSE [DO_NOT_CHECK]", 
  "Receive an amount of bytes, either specified by a number \n"
  "or as much until socket timeout will in POLL mode.\n"
  "optional DO_NOT_CHECK do not check the _MATCH and _EXPECT clauses. \n"
  "With _CHECK you can do this afterward over a couple of not yet checked "
  "_RECVs",
  COMMAND_FLAGS_NONE},
  {"_READLINE", (command_f )command_READLINE, "[DO_NOT_CHECK]", 
  "Receive a line terminated with \\r\\n or \\n\n"
  "optional DO_NOT_CHECK do not check the _MATCH and _EXPECT clauses. \n"
  "With _CHECK you can do this afterward over a couple of not yet checked "
  "_READLINEs",
  COMMAND_FLAGS_NONE},
  {"_CHECK", (command_f )command_CHECK, "", 
  "Check _EXPECT and _MATCH",
  COMMAND_FLAGS_NONE},
  {"_ONLY_PRINTABLE", (command_f )command_ONLY_PRINTABLE, "on|off", 
  "Replace all chars below 32 and above 127 with a space",
  COMMAND_FLAGS_NONE},
  {"_PRINT_HEX", (command_f )command_PRINT_HEX, "on|off", 
  "Display bytes with two hex ditigs no space",
  COMMAND_FLAGS_NONE},
  {"_SH", (command_f )command_SH, "shell script line or END", 
  "Embedded shell script within a tmp file, execute if END is found",
  COMMAND_FLAGS_NONE},
  {"_ADD_HEADER", (command_f )command_ADD_HEADER, "<header> <value>", 
  "Add additional header to received headers to force forexample chunked encoding",
  COMMAND_FLAGS_NONE},
  {"_AUTO_CLOSE", (command_f )command_AUTO_CLOSE, "on|off", 
  "Close connection on Connection: close header",
  COMMAND_FLAGS_NONE},
  {"_AUTO_COOKIE", (command_f )command_AUTO_COOKIE, "on|off", 
  "Handles cookies in a simple way, do not check expire or path",
  COMMAND_FLAGS_NONE},
  {"_IGNORE_BODY", (command_f )command_IGNORE_BODY, "on|off", 
  "Read but ignore body of request/response.",
  COMMAND_FLAGS_NONE},
  {"_TUNNEL", (command_f )command_TUNNEL, "<host> [<SSL>:]<port>[:<tag>] [<cert-file> <key-file> [<ca-cert-file>]]", 
  "Open tunnel to defined host:port, with SSL support.\n"
  "If connection exist no connect will be performed\n"
  "<SSL>: SSL, SSL2, SSL3, DTLS1, TLS1"
#if (OPENSSL_VERSION_NUMBER >= 0x1000102fL)
  ", TLS1.1, TLS1.2"
#endif
  "\n"
  "<tag>:Additional tag info do support multiple connection to one target\n"
  "<cert-file>, <key-file> and <ca-cert-file> are optional for client/server authentication",
  COMMAND_FLAGS_NONE},	
  {"_RECORD", (command_f )command_RECORD, "RES [ALL] {STATUS | HEADERS | BODY}*", 
  "Record response for replay it or store it",
  COMMAND_FLAGS_NONE},
  {"_PLAY", (command_f )command_PLAY, "SOCKET | VAR <var>", 
  "Play back recorded stuff either on socket or into a variable.",
  COMMAND_FLAGS_NONE},
  {"_USE", (command_f )command_USE, "<module>", 
  "Use the name space of a module.",
  COMMAND_FLAGS_NONE},
  {"_LOCAL", (command_f )command_LOCAL, "<var>+", 
  "Define BLOCK local variables.",
  COMMAND_FLAGS_NONE},
  {"_VERSION", (command_f )command_VERSION, "<var>", 
  "Get version of running httest.",
  COMMAND_FLAGS_NONE},

  /* body section */
  {"_IF", (command_f )command_IF, "(\"<string>\" [NOT] MATCH \"regex\")|(\"<number>\" [NOT] EQ|LT|GT|LE|GT \"<number>)\"|\"(\"expression\")\"", 
   "Test string match, number equality or simply an expression to run body, \n"
   "close body with _END,\n"
   "negation with a leading '!' in the <regex>",
   COMMAND_FLAGS_BODY},
  {"_LOOP", (command_f )command_LOOP, "<n>[s|ms]|FOREVER [<variable>]", 
  "LOOP for specified times or optional for a duration given as \"s\" or "
  "\"ms\" with no space after number, additional you can specify a variable "
  "which holds the loop count,\n"
  "close body with _END",
  COMMAND_FLAGS_BODY},
  {"_FOR", (command_f )command_FOR, "<variable> \"|'<string>*\"|'", 
  "Do for each element,\n"
  "close body with _END",
  COMMAND_FLAGS_BODY},
  {"_BPS", (command_f )command_BPS, "<n> <duration>", 
  "Send not more than defined bytes per second, while defined duration [s]\n"
  "close body with _END",
  COMMAND_FLAGS_BODY},
  {"_RPS", (command_f )command_RPS, "<n> <duration>", 
  "Send not more than defined requests per second, while defined duration [s]\n"
  "Request is count on every _WAIT call\n"
  "close body with _END",
  COMMAND_FLAGS_BODY},
  {"_SOCKET", (command_f )command_SOCKET, "", 
  "Spawns a socket reader over the next _WAIT _RECV commands\n"
  "close body with _END",
  COMMAND_FLAGS_BODY},
  {"_ERROR", (command_f )command_ERROR, "", 
  "We do expect specific error on body exit\n"
  "close body with _END",
  COMMAND_FLAGS_BODY},
#if APR_HAS_FORK
  {"_PROCESS", (command_f )command_PROCESS, "<name>", 
  "Fork a process to run body in. Process termination handling see _PROC_WAIT\n"
  "close body with _END",
  COMMAND_FLAGS_BODY},
#endif

  /* Link section */
  {"_OP", NULL, "_MATH:OP", NULL, COMMAND_FLAGS_LINK},
  {"_RAND", NULL, "_MATH:RAND", NULL, COMMAND_FLAGS_LINK},
  {"_DETACH", NULL, "_PROC:DETACH", NULL, COMMAND_FLAGS_LINK},
  {"_PID", NULL, "_PROC:GET_PID", NULL, COMMAND_FLAGS_LINK},
  {"_LOCK", NULL, "_PROC:LOCK", NULL, COMMAND_FLAGS_LINK},
  {"_UNLOCK", NULL, "_PROC:UNLOCK", NULL, COMMAND_FLAGS_LINK},
  {"_WHICH", NULL, "_THREAD:GET_NUMBER", NULL, COMMAND_FLAGS_LINK},
  {"_SLEEP", NULL, "_SYS:SLEEP", NULL, COMMAND_FLAGS_LINK},
  {"_B64ENC", NULL, "_CODER:B64ENC", NULL, COMMAND_FLAGS_LINK},
  {"_B64DEC", NULL, "_CODER:B64DEC", NULL, COMMAND_FLAGS_LINK},
  {"_URLENC", NULL, "_CODER:URLENC", NULL, COMMAND_FLAGS_LINK},
  {"_URLDEC", NULL, "_CODER:URLDEC", NULL, COMMAND_FLAGS_LINK},
  {"_TIMER", NULL, "_DATE:TIMER", NULL, COMMAND_FLAGS_LINK},
  {"_TIME", NULL, "_DATE:GET_TIME", NULL, COMMAND_FLAGS_LINK},
  {"_STRFTIME", NULL, "_DATE:FORMAT", NULL, COMMAND_FLAGS_LINK},
  {"_SYNC", NULL, "_DATE:SYNC", NULL, COMMAND_FLAGS_LINK},
  {"_SSL_CONNECT", NULL, "_SSL:CONNECT", NULL, COMMAND_FLAGS_LINK},
  {"_SSL_ACCEPT", NULL, "_SSL:ACCEPT", NULL, COMMAND_FLAGS_LINK},
  {"_RENEG", NULL, "_SSL:RENEG_CERT", NULL, COMMAND_FLAGS_LINK},
  {"_SSL_BUF_2_CERT", NULL, "_SSL:LOAD_CERT", NULL, COMMAND_FLAGS_LINK},
  {"_CERT", NULL, "_SSL:SET_CERT", NULL, COMMAND_FLAGS_LINK},
  {"_SSL_CERT_VAL", NULL, "_SSL:GET_CERT_VALUE", NULL, COMMAND_FLAGS_LINK},
  {"_SSL_GET_SESSION", NULL, "_SSL:GET_SESSION", NULL, COMMAND_FLAGS_LINK},
  {"_SSL_SET_SESSION", NULL, "_SSL:SET_SESSION", NULL, COMMAND_FLAGS_LINK},
  {"_SSL_SESSION_ID", NULL, "_SSL:GET_SESSION_ID", NULL, COMMAND_FLAGS_LINK},
  {"_SSL_LEGACY", NULL, "_SSL:SET_LEGACY", NULL, COMMAND_FLAGS_LINK},
  {"_SSL_ENGINE", NULL, "_SSL:SET_ENGINE", NULL, COMMAND_FLAGS_LINK},
  {"_VERIFY_PEER", NULL, "_SSL:RENEG_CERT verify", NULL, COMMAND_FLAGS_LINK},
  {"_SSL_SECURE_RENEG_SUPPORTED", NULL, "_SSL:SECURE_RENEG_SUPPORTED", NULL, COMMAND_FLAGS_LINK},
  /* mark end of list */
  {NULL, NULL, NULL, 
  NULL,
  COMMAND_FLAGS_NONE},
};

global_t *process_global = NULL;
int success = 1;
int running_threads = 0;
     
/************************************************************************
 * Private 
 ***********************************************************************/

static void worker_set_global_error(worker_t *worker); 
static apr_status_t worker_interpret(worker_t * worker, worker_t *parent, 
                                     apr_pool_t *ptmp); 

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

/**
 * Lookup a block name in current module
 * @param worker IN worker object
 * @param line IN line with a possible block name
 * @param ptmp IN temp pool
 * @return block hash
 */
static int worker_is_block(worker_t * worker, char *line, apr_pool_t *ptmp) {
  apr_size_t len = 0;
  char *block_name;

  if (strncmp(line, "__", 2) == 0 || strncmp(line, "_-", 2) == 0) {
    /* very special commands, not possible to overwrite this one */
    return 0;
  }

  while (line[len] != ' ' && line[len] != '\0') ++len;
  block_name = apr_pstrndup(ptmp, line, len);

  /* if name space do handle otherwise */
  if (strchr(block_name, ':')) {
    return 0;
  }

  return apr_hash_get(worker->blocks, block_name, APR_HASH_KEY_STRING) != NULL;
}

/**
 * Replacer upcall for global context
 * @param udata IN void pointer to store
 * @param name IN name of variable to lookup
 * @param value
 */
static const char *global_replacer(void *udata, const char *name) {
  const char *val;
  global_replacer_t *hook = udata;
  val = store_get(hook->store, name);
  if (!val) {
    char *env;
    if (apr_env_get(&env, name, hook->ptmp) == APR_SUCCESS) {
      val = env;
    }
  }
  return val;
}

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
                                 char *data, apr_pool_t *ptmp) {
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
static apr_status_t command_IF(command_t * self, worker_t * worker,
                               char *data, apr_pool_t *ptmp) {
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
      worker_log_error(worker, "Empty condition");
      return APR_EINVAL;
    }
    copy[len-1] = 0;

    if ((status = math_evaluate(math, copy, &val)) != APR_SUCCESS) {
      worker_log_error(worker, "Invalid condition");
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
                                 char *data, apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  int loop;
  char **argv;
  int i;
  char *var;
  apr_time_t duration = 0;
  apr_time_t start;

  COMMAND_NEED_ARG("<number>[s|ms]|FOREVER"); 
 
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
  
  /* create a new worker body */
  if ((status = worker_body(&body, worker)) != APR_SUCCESS) {
    return status;
  }
  
  /* loop */
  start = apr_time_now();
  for (i = 0; loop == -1 || i < loop; i++) {
    /* interpret */
    if (var) {
      worker_var_set(body, var, apr_itoa(ptmp, i));
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
                                char *data, apr_pool_t *ptmp) {
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
  cur = apr_strtok(list, " ", &last);
  while (cur) {
    /* interpret */
    worker_var_set(body, var, cur);
    if ((status = body->interpret(body, worker, NULL)) != APR_SUCCESS) {
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
static apr_status_t command_BPS(command_t *self, worker_t *worker, char *data, 
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
static apr_status_t command_RPS(command_t *self, worker_t *worker, char *data, 
                                apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *body;
  char *copy;
  char **argv;
  int rps;
  int duration;
  apr_time_t init;
  apr_time_t start;
  apr_time_t cur;

  COMMAND_NEED_ARG("Byte/s and duration time in second"); 

  my_tokenize_to_argv(copy, &argv, ptmp, 0);
  rps = apr_atoi64(argv[0]);
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

    if (rps > 0) {
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

      /* reset sent requests */
      body->req_cnt = 0;
    }

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
                                  char *data, apr_pool_t *ptmp) {
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
      worker_log_error(worker, "No argument found, need an regex for expected errof.");
      return APR_EINVAL;
    }
  }
  else {
    worker_log_error(worker, "Could not read argument");
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
    worker_log_error(worker, "Did expect error \"%s\" but got \"%s\"", argv[0], 
	             status_str);
    return APR_EINVAL;
  }
  else {
    status = APR_SUCCESS;
  }

  worker_log(worker, LOG_CMD, "_END ERROR");
  
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
static apr_status_t command_SOCKET(command_t *self, worker_t *worker, 
                                   char *data, apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *body;
  apr_size_t peeklen;
  apr_pool_t *pool;

  COMMAND_NO_ARG;

  if (!worker->socket) {
    worker_log_error(worker, "Call _RES or REQ before you spawn a long life _SOCKET");
    return APR_ENOSOCKET;
  }

  worker_flush(worker, ptmp);

  /* create a new worker body */
  if ((status = worker_body(&body, worker)) != APR_SUCCESS) {
    return status;
  }

  apr_pool_create(&pool, NULL);

  peeklen = body->socket->peeklen;
  body->socket->peeklen = 0;

  if ((status = sockreader_new(&body->sockreader, body->socket->transport,
                               body->socket->peek, peeklen, pool)) != APR_SUCCESS) {
    goto error;
  }
 
  status = body->interpret(body, worker, NULL);
  
  worker_log(worker, LOG_CMD, "_END SOCKET");
  
error:
  apr_pool_destroy(pool);
  worker_body_end(body, worker);
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
static apr_status_t command_PROCESS(command_t *self, worker_t *worker, char *data, 
                                    apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *body;
  apr_proc_t *proc;
  char *copy;

  COMMAND_NEED_ARG("<name>");

  /* create a new worker body */
  if ((status = worker_body(&body, worker)) != APR_SUCCESS) {
    return status;
  }
  
  /* fork  */
  proc = apr_pcalloc(worker->pbody, sizeof(apr_proc_t));
  status = apr_proc_fork(proc, worker->pbody);

  if (APR_STATUS_IS_INCHILD(status)) {
    /* interpret */
    status = body->interpret(body, worker, NULL);
  
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
  else {
    apr_pool_note_subprocess(worker->global->pool, proc, APR_KILL_ALWAYS);
  }

  if (!worker->procs) {
    worker->procs = apr_hash_make(worker->pbody);
  }

  apr_hash_set(worker->procs, apr_pstrdup(worker->pbody, copy), APR_HASH_KEY_STRING, proc);

  return APR_SUCCESS; 
}
#endif

/**
 * Unset global success
 *
 * @param self IN thread data object
 */
static void worker_set_global_error(worker_t *worker) {
  sync_lock(worker->mutex);
  success = 0;
  sync_unlock(worker->mutex);
}

/**
 * Interpreter
 *
 * @param worker IN thread data object
 * @param parent IN caller
 * @param dummy IN not used, but interface definition wants that
 *
 * @return an apr status
 */
static apr_status_t worker_interpret(worker_t * worker, worker_t *parent, 
                                     apr_pool_t *dummy) {
  apr_status_t status;
  int to;

  apr_table_entry_t *e =
    (apr_table_entry_t *) apr_table_elts(worker->lines)->elts;

  to = worker->cmd_to ? worker->cmd_to : apr_table_elts(worker->lines)->nelts;

  for (worker->cmd = worker->cmd_from; worker->cmd < to; worker->cmd++) {
    char *line;
    apr_pool_t *ptmp;

    apr_pool_create(&ptmp, NULL);
    worker->file_and_line = e[worker->cmd].key;
    line = e[worker->cmd].val;
    if (worker_is_block(worker, line, ptmp)) {
      status = command_CALL(NULL, worker, line, ptmp);
      /* dirty hack */
      worker->file_and_line = e[worker->cmd].key;
      status = worker_check_error(parent, status);
    }
    else {
      int j = 0;
      command_t *command = lookup_command(local_commands, line);
      if (command->flags & COMMAND_FLAGS_LINK) {
        j += strlen(command->name);
        status = command_CALL(NULL, worker, apr_pstrcat(worker->pbody, 
                              command->syntax,
                              " ", &line[j], NULL), 
                              ptmp);
        status = worker_check_error(parent, status);
      }
      else if (command->func) {
        j += strlen(command->name);
        status = command->func(command, worker, &line[j], ptmp);
        status = worker_check_error(parent, status);
      }
      else {
        status = command_CALL(NULL, worker, line, ptmp);
        if (!APR_STATUS_IS_ENOENT(status)) {
          status = worker_check_error(parent, status);
        }
        else {
          worker_log_error(worker, "%s syntax error", worker->name);
          worker_set_global_error(worker);
          status = APR_EINVAL;
        }
      }
    }
    apr_pool_destroy(ptmp);

    if (status != APR_SUCCESS) {
      return status;
    }
  }
  return APR_SUCCESS;
}

/**
 * Call final block if exist
 *
 * @param worker IN thread data object
 */
void worker_finally(worker_t *worker, apr_status_t status) {
  int mode;

  if (worker->tmpf) {
    const char *name;

    /* get file name */
    if (apr_file_name_get(&name, worker->tmpf) == APR_SUCCESS) {
      /* close file */
      apr_file_close(worker->tmpf);
      worker->tmpf = NULL;

      apr_file_remove(name, worker->pbody);
    }
  }

  sync_lock(worker->mutex);
  if (status != APR_SUCCESS) {
    running_threads = 0;
  }
  else {
    --running_threads;
  }
  sync_unlock(worker->mutex);

  worker_var_set(worker, "__ERROR", my_status_str(worker->pbody, status));
  worker_var_set(worker, "__STATUS", apr_ltoa(worker->pbody, status));
  worker_var_set(worker, "__THREAD", worker->name);

  if (running_threads == 0) { 
    command_t *command = lookup_command(local_commands, "_CALL");
    if (command->func) {
      mode = worker->log_mode;
      worker->log_mode = 0;
      worker->blocks = apr_hash_get(worker->modules, "DEFAULT", APR_HASH_KEY_STRING);
      if (apr_hash_get(worker->blocks, "FINALLY", APR_HASH_KEY_STRING)) {
        command->func(command, worker, "FINALLY", NULL);
      }
      worker->log_mode = mode;
    }
  }

  if (status != APR_SUCCESS) {
    command_t *command = lookup_command(local_commands, "_CALL");
    if (command->func) {
      worker->blocks = apr_hash_get(worker->modules, "DEFAULT", APR_HASH_KEY_STRING);
      if (apr_hash_get(worker->blocks, "ON_ERROR", APR_HASH_KEY_STRING)) {
        command->func(command, worker, "ON_ERROR", NULL);
        goto exodus;
      }
    }

    worker_set_global_error(worker);
    worker_conn_close_all(worker);
    exit(1);
  }
exodus:
  htt_run_worker_finally(worker); 
  worker_conn_close_all(worker);
  apr_thread_exit(worker->mythread, APR_SUCCESS);
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

  worker_t *worker = selfv;
  worker->mythread = thread;
  worker->flags |= FLAGS_CLIENT;

  worker->file_and_line = apr_psprintf(worker->pbody, "%s:-1", worker->filename);

  sync_lock(worker->mutex);
  ++running_threads;
  sync_unlock(worker->mutex);
  
  worker_log(worker, LOG_INFO, "%s start ...", worker->name);

  if ((status = worker->interpret(worker, worker, NULL)) != APR_SUCCESS) {
    goto error;
  }

  worker_flush(worker, worker->pbody);

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    goto error;
  }

  if ((status = worker_test_unused_errors(worker)) != APR_SUCCESS) {
    goto error;
  }

error:
  worker_finally(worker, status);
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

  worker_t *worker = selfv;
  worker->mythread = thread;
  worker->flags |= FLAGS_CLIENT;

  worker->file_and_line = apr_psprintf(worker->pbody, "%s:-1", worker->filename);

  worker_log(worker, LOG_INFO, "Daemon start ...");

  worker_log(worker, LOG_DEBUG, "unlock %s", worker->name);

  if ((status = worker->interpret(worker, worker, NULL)) != APR_SUCCESS) {
    goto error;
  }

  worker_flush(worker, worker->pbody);

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    goto error;
  }

  if ((status = worker_test_unused_errors(worker)) != APR_SUCCESS) {
    goto error;
  }

error:
  /* no mather if there are other threads running set running threads to one */
  sync_lock(worker->mutex);
  running_threads = 1;
  sync_unlock(worker->mutex);
  worker_finally(worker, status);
  return NULL;
}

/**
 * start single server 
 *
 * @param thread IN thread object
 * @param worker IN void thread data object
 * @param threads IN number of threads
 *
 * @return an apr status
 */
static apr_status_t worker_run_single_server(worker_t *worker) {
  apr_status_t status;

  if ((status = worker->interpret(worker, worker, NULL)) != APR_SUCCESS) {
    return status;
  }

  worker_flush(worker, worker->pbody);

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    return status;
  }

  if ((status = worker_test_unused_errors(worker)) != APR_SUCCESS) {
    return status;
  }
  return APR_SUCCESS;
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

  worker_t *worker = selfv;
  worker->mythread = thread;
  worker->flags |= FLAGS_SERVER;

  sync_lock(worker->mutex);
  ++running_threads;
  sync_unlock(worker->mutex);

  status = worker_run_single_server(worker);

  /* do not close listener, there may be more servers which use this 
   * listener, signal this by setting listener to NULL
   */
  worker->listener = NULL;
  worker_finally(worker, status);
  return NULL;
}

/**
 * start threaded servers 
 *
 * @param thread IN thread object
 * @param worker IN void thread data object
 * @param threads IN number of threads
 *
 * @return an apr status
 */
static apr_status_t worker_run_server_threads(worker_t *worker, int threads) {
  apr_status_t status;
  apr_threadattr_t *tattr;
  apr_thread_t *threadl;
  apr_table_t *servers;
  apr_table_entry_t *e;
  worker_t *clone;
  int i = 0;

  if ((status = apr_threadattr_create(&tattr, worker->pbody)) != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_stacksize_set(tattr, DEFAULT_THREAD_STACKSIZE))
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_threadattr_detach_set(tattr, 0)) != APR_SUCCESS) {
    return status;
  }

  servers = apr_table_make(worker->pbody, 10);

  while(threads == -1 || i < threads) {
    if ((status = worker_clone(&clone, worker)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not clone server thread data");
      return status;
    }
    if ((status = htt_run_worker_clone(worker, clone)) != APR_SUCCESS) {
      return status;
    }
    clone->listener = worker->listener;
    worker_log(worker, LOG_DEBUG, "--- accept");
    if (!worker->listener) {
      worker_log_error(worker, "Server down");
      status = APR_EGENERAL;
      return status;
    }
    if ((status = tcp_accept(clone)) != APR_SUCCESS) {
      return status;
    }
    if ((status = htt_run_accept(clone, "")) != APR_SUCCESS) {
      return status;
    }
    worker_log(worker, LOG_DEBUG, "--- create thread");
    clone->socket->socket_state = SOCKET_CONNECTED;
    clone->which = i;
    if ((status =
         apr_thread_create(&threadl, tattr, worker_thread_server,
               clone, worker->pbody)) != APR_SUCCESS) {
      return status;
    }

    apr_table_addn(servers, worker->name, (char *)threadl);

    ++i;
  }

  e = (apr_table_entry_t *) apr_table_elts(servers)->elts;
  for (i = 0; i < apr_table_elts(servers)->nelts; ++i) {
    threadl = (apr_thread_t *) e[i].val;
    apr_thread_join(&status, threadl);
  }

  return APR_SUCCESS;
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
  int nolistener;
  char *last;
  char *portname;
  char *scope_id;
  char *value;
  int threads = 0;

  worker_t *worker = selfv;
  worker->mythread = thread;
  worker->flags |= FLAGS_SERVER;

  sync_lock(worker->mutex);
  ++running_threads;
  sync_unlock(worker->mutex);

  portname = apr_strtok(worker->additional, " ", &last);

  worker_get_socket(worker, "Default", "0");

  if ((status = htt_run_server_port_args(worker, portname, &portname, last)) != APR_SUCCESS) {
    goto error;
  }

  if (!portname) {
    worker_log_error(worker, "No port defined");
    status = APR_EGENERAL;
    goto error;
  }
  
  nolistener = 0;
  value = apr_strtok(NULL, " ", &last);
  if (value && strcmp(value, "DOWN") != 0) {
    threads = apr_atoi64(value);
  }
  else if (value) {
    /* do not setup listener */
    nolistener = 1;
  }
  else {
    threads = 0;
  }

  if ((status = apr_parse_addr_port(&worker->listener_addr, &scope_id, 
	                            &worker->listener_port, portname, 
				    worker->pbody)) != APR_SUCCESS) {
    goto error;
  }

  if (!worker->listener_addr) {
    worker->listener_addr = apr_pstrdup(worker->pbody, APR_ANYADDR);
  }

  if (!worker->listener_port) {
    if (worker->socket->is_ssl) {
      worker->listener_port = 443;
    }
    else {
      worker->listener_port = 80;
    }
  }
  
  worker_log(worker, LOG_INFO, "%s start on %s%s:%d", worker->name, 
             worker->socket->is_ssl ? "SSL:" : "", worker->listener_addr, 
	     worker->listener_port);

  if (!nolistener) {
    if ((status = worker_listener_up(worker, LISTENBACKLOG_DEFAULT)) != APR_SUCCESS) {
      worker_log_error(worker, "%s(%d)", my_status_str(worker->pbody, status), status);
      goto error;
    }
  }
  sync_unlock(worker->sync_mutex);
  worker_log(worker, LOG_DEBUG, "unlock %s", worker->name);

  if (threads != 0) {
    status = worker_run_server_threads(worker, threads);
  }
  else {
    status = worker_run_single_server(worker);
  }

error:
  worker_finally(worker, status);
  return NULL;
}

/****
 * Global object 
 ****/

/**
 * Create new global object
 *
 * @param global OUT new global object
 * @param vars IN global variable table
 * @param log_mode IN log mode
 * @param p IN pool
 *
 * @return apr status
 */
static apr_status_t global_new(global_t **global, store_t *vars, 
                               int log_mode, apr_pool_t *p) {
  apr_status_t status;
  *global = apr_pcalloc(p, sizeof(global_t));

  (*global)->pool = p;
  (*global)->config = apr_hash_make(p);
  (*global)->vars = vars;
  (*global)->log_mode = log_mode;

  (*global)->threads = apr_table_make(p, 10);
  (*global)->clients = apr_table_make(p, 5);
  (*global)->servers = apr_table_make(p, 5);
  (*global)->daemons = apr_table_make(p, 5);
  (*global)->modules = apr_hash_make(p);
  (*global)->blocks = apr_hash_make(p);
  (*global)->files = apr_table_make(p, 5);

  /* set default blocks for blocks with no module name */
  apr_hash_set((*global)->modules, "DEFAULT", APR_HASH_KEY_STRING, (*global)->blocks);

  if ((status = apr_threadattr_create(&(*global)->tattr, (*global)->pool)) != APR_SUCCESS) {
    fprintf(stderr, "\nGlobal creation: could not create thread attr");
    return status;
  }

  if ((status = apr_threadattr_stacksize_set((*global)->tattr, DEFAULT_THREAD_STACKSIZE))
      != APR_SUCCESS) {
    fprintf(stderr, "\nGlobal creation: could not set stacksize");
    return status;
  }

  if ((status = apr_threadattr_detach_set((*global)->tattr, 0)) != APR_SUCCESS) {
    fprintf(stderr, "\nGlobal creation: could not set detach");
    return status;
  }

  if ((status = apr_thread_cond_create(&(*global)->cond, p)) != APR_SUCCESS) {
    fprintf(stderr, "\nGlobal creation: could not create condition");
    return status;
  }

  if ((status = apr_thread_mutex_create(&(*global)->sync, 
	                                APR_THREAD_MUTEX_DEFAULT,
                                        p)) != APR_SUCCESS) {
    fprintf(stderr, "\nGlobal creation: could not create sync mutex");
    return status;
  }
 
  if ((status = apr_thread_mutex_create(&(*global)->mutex, 
	                                APR_THREAD_MUTEX_DEFAULT,
                                        p)) != APR_SUCCESS) {
    fprintf(stderr, "\nGlobal creation: could not create mutex");
    return status;
  }

  (*global)->state = GLOBAL_STATE_NONE;
  (*global)->socktmo = 300000000;
  (*global)->prefix = apr_pstrdup(p, "");

  if ((status = worker_new(&(*global)->worker, NULL, (*global)->prefix, 
                           (*global), NULL)) != APR_SUCCESS) {
    fprintf(stderr, "\nGlobal worker: could not create my worker");
  }

  (*global)->worker->modules = (*global)->modules;
  (*global)->worker->name = apr_pstrdup(p, "__htt_global__");

  return APR_SUCCESS;
}

/**
 * cleanup files on exit
 *
 * @param data IN file name to remove
 * @return APR_SUCCESS
 */
static apr_status_t worker_file_cleanup(void *data) {
  const char *name = data;
  apr_pool_t *pool;

  apr_pool_create(&pool, NULL);
  apr_file_remove(name, pool);
  apr_pool_destroy(pool);
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
static apr_status_t global_END(command_t *self, global_t *global, char *data, 
                               apr_pool_t *ptmp) {
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
    val = apr_strtok(global->cur_worker->additional, " ", &last);
    if (val) {
      concurrent = apr_atoi64(val);
      if (concurrent <= 0) {
	fprintf(stderr, "\nNumber of concurrent clients must be > 0");
	return EINVAL;
      }
      global->cur_worker->additional = NULL;
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
    apr_hash_set(global->blocks, global->cur_worker->name, APR_HASH_KEY_STRING, 
	         global->cur_worker);
    global->state = GLOBAL_STATE_NONE;
    return htt_run_block_end(global);
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
    if ((status = worker_to_file(global->cur_worker)) != APR_SUCCESS) {
      worker_set_global_error(global->cur_worker);
      fprintf(stderr, "\nCould not create %s: %s(%d)", global->cur_worker->name, 
	      my_status_str(global->pool, status), status);
      return status;
    }

    apr_pool_cleanup_register(global->pool, global->cur_worker->name, 
                              worker_file_cleanup, apr_pool_cleanup_null);
    global->state = GLOBAL_STATE_NONE;
    return APR_SUCCESS;
    break; 
  default: 
    fprintf(stderr, "\nUnknown close of a body definition");
    return APR_ENOTIMPL;
    break; 
  }

  /* store the workers to start them later */
  global->cur_worker->filename = global->filename;
  while (concurrent) {
    clone = NULL;
    --concurrent;
    called_name = apr_psprintf(global->pool, "%s-%d", name, concurrent);
    global->cur_worker->name = called_name;
    global->cur_worker->which = concurrent;
    if (concurrent) {
      if ((status = worker_clone(&clone, global->cur_worker)) != APR_SUCCESS) {
	worker_log(global->cur_worker, LOG_ERR, "Could not clone thread");
	return APR_EINVAL;
      }
    }

    switch (global->state) {
    case GLOBAL_STATE_CLIENT:
      apr_table_addn(global->clients, called_name, (char *) global->cur_worker);
      break;
    case GLOBAL_STATE_SERVER:
      apr_table_addn(global->servers, called_name, (char *) global->cur_worker);
      break;
    case GLOBAL_STATE_DAEMON:
      apr_table_addn(global->daemons, called_name, (char *) global->cur_worker);
      break;
    }
    global->cur_worker = clone;
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
  if ((status = worker_new(&global->cur_worker, data, global->prefix, global, 
                           worker_interpret)) != APR_SUCCESS) {
    fprintf(stderr, "\nGlobal worker: could not create worker");
    return status;
  }
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
static apr_status_t global_CLIENT(command_t *self, global_t *global, char *data, 
                                  apr_pool_t *ptmp) {
  apr_status_t status;
  status = global_worker(self, global, data, GLOBAL_STATE_CLIENT);
  global->prefix = apr_pstrcat(global->pool, global->prefix, 
			       "                        ", NULL);
  return status;
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
static apr_status_t global_SERVER(command_t *self, global_t *global, char *data, 
                                  apr_pool_t *ptmp) {
  apr_status_t status;
  status = global_worker(self, global, data, GLOBAL_STATE_SERVER);
  global->prefix = apr_pstrcat(global->pool, global->prefix, 
			       "                        ", NULL);

  return status;
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
                                 char *data, apr_pool_t *ptmp) {
  apr_status_t status;
  char *token;
  char *last;
  int input=1;
  int i = 0;

  while (*data == ' ') ++data;

  /* Block start */
  global->state = GLOBAL_STATE_BLOCK;

  if ((status = htt_run_block_start(global, &data)) 
      == APR_ENOTIMPL) {
    /* Start a new worker */
    if ((status = worker_new(&global->cur_worker, data, global->prefix, global, 
                             worker_interpret)) != APR_SUCCESS) {
      return status;
    }
  }
  else if (status != APR_SUCCESS) {
    fprintf(stderr, "\nFailed on block start %s(%d)", my_status_str(global->pool, status), status);  
    return status;
  }
  
  /* Get params and returns */
  /* create two tables for in/out vars */
  /* input and output vars */
  token = apr_strtok(data, " ", &last);
  if (token) {
    if (strchr(token, ':')) {
      fprintf(stderr, "\nChar ':' is not allowed in block name \"%s\"", token);
      return APR_EINVAL;
    }
    global->cur_worker->name = data;
  }
  while (token) {
    if (strcmp(token, ":") == 0) {
      /* : is separator between input and output vars */
      input = 0;
    }
    else {
      if (input) {
       store_set(global->cur_worker->params, apr_itoa(global->cur_worker->pbody, i), 
                  token);
      }
      else {
        store_set(global->cur_worker->retvars, apr_itoa(global->cur_worker->pbody, i),
                  token);
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
                                char *data, apr_pool_t *ptmp) {
  apr_status_t status;

  while (*data == ' ') ++data;
  
  /* Block start */
  global->state = GLOBAL_STATE_FILE;

  /* Start a new worker */
  if ((status = worker_new(&global->cur_worker, data, global->prefix, global, 
                           worker_interpret)) != APR_SUCCESS) {
    fprintf(stderr, "\nCould not initiate worker instance");
    return status;
  }

  global->cur_worker->name = data;

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
static apr_status_t global_DAEMON(command_t *self, global_t *global, char *data, 
                                  apr_pool_t *ptmp) {
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
static apr_status_t global_EXEC(command_t *self, global_t *global, char *data, 
                                apr_pool_t *ptmp) {
  apr_status_t status;
  worker_t *worker;

  int i = 0;
  
  while (data[i] == ' ') {
    ++i;
  }

  if ((status = worker_new(&worker, &data[i], "", global, worker_interpret))
      != APR_SUCCESS) {
    fprintf(stderr, "\nCould not initiate worker instance");
    return status;
  }
  worker_add_line(worker, apr_psprintf(global->pool, "%s:%d", global->filename,
	                               global->line_nr), 
		  apr_pstrcat(worker->pbody, "_EXEC ", &data[i], NULL));
  status = worker->interpret(worker, worker, NULL);
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
static apr_status_t global_SET(command_t *self, global_t *global, char *data, 
                               apr_pool_t *ptmp) {
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
    store_set(global->vars, key, val);
  }
  else {
    store_set(global->vars, key, "");
  }

  return APR_SUCCESS;
}

/**
 * Global GLOBAL command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN key=value
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_GLOBAL(command_t *self, global_t *global, char *data, 
                                  apr_pool_t *ptmp) {
  char *last;
  char *var;
  
  int i = 0;
  
  while (data[i] == ' ') ++i;

  if (!global->shared) {
    global->shared = store_make(global->pool);
  }

  var = apr_strtok(&data[i], " ", &last);
  while (var) {
    for (i = 0; var[i] != 0 && strchr(VAR_ALLOWED_CHARS, var[i]); i++); 
    if (var[i] != 0) {
      fprintf(stderr, "\nChar '%c' is not allowed in \"%s\"", var[i], var);
      success = 0;
      return APR_EINVAL;
    }

    store_set(global->shared, var, "");
    var = apr_strtok(NULL, " ", &last);
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
                                  char *data, apr_pool_t *ptmp) {
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
 * Global PATH command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN path string
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_PATH(command_t *self, global_t *global, char *data, 
                                apr_pool_t *ptmp) {
  char **argv;

  my_tokenize_to_argv(data, &argv, global->pool, 0);
  global->path = argv[0];
  return APR_SUCCESS;
}

/**
 * Global INCLUDE command
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN relative to caller or absolut path
 *
 * @return APR_SUCCESS or APR_ENOENT if no include file found
 */
static apr_status_t interpret_recursiv(apr_file_t *fp, global_t *global); 
static apr_status_t global_INCLUDE(command_t *self, global_t *global, char *data, 
                                   apr_pool_t *ptmp) {
  apr_status_t status;
  apr_file_t *fp;
  const char *prev_filename;
  char **argv;
  int i;

  status = APR_ENOENT;
  my_tokenize_to_argv(data, &argv, global->pool, 0);
  for (i = 0; argv[i] != NULL; i++) {
    if (argv[i][0] == '/' || global->path == NULL) {
      if ((status =
           apr_file_open(&fp, argv[i], APR_READ, APR_OS_DEFAULT,
                         global->pool)) == APR_SUCCESS) {
        break;
      }
    }
    else if (global->path) {
      char *last;
      char *cur;
      char *path = apr_pstrdup(global->pool, global->path);

      cur = apr_strtok(path, ":", &last);
      while (cur) {
        char *file = apr_pstrcat(global->pool, cur, "/", argv[i], NULL);
        if ((status = apr_file_open(&fp, file, APR_READ, APR_OS_DEFAULT, 
                                    global->pool)) == APR_SUCCESS) {
          break;
        }
        cur = apr_strtok(NULL, ":", &last);
      }
    }
  }

  if (status != APR_SUCCESS) {
    fprintf(stderr, "\nInclude file %s not found", data);
    return APR_ENOENT;
  }

  prev_filename = global->filename;
  global->filename = argv[i];
  ++global->recursiv;
  status = interpret_recursiv(fp, global);
  --global->recursiv;
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
static apr_status_t global_TIMEOUT(command_t *self, global_t *global, char *data, 
                                   apr_pool_t *ptmp) {
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
static apr_status_t global_AUTO_CLOSE(command_t *self, global_t *global, char *data, 
                                      apr_pool_t *ptmp) {
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
static apr_status_t global_PROCESS(command_t *self, global_t *global, char *data, 
                                   apr_pool_t *ptmp) {
  apr_proc_t proc;
  apr_status_t status;
  int n;
  char *copy;
  char *last;
  char *no;
  char *var;
  int i = 0; 
  global_replacer_t *replacer_hook = apr_pcalloc(ptmp, sizeof(*replacer_hook));
  replacer_hook->ptmp = ptmp;
  replacer_hook->store = global->vars;

  while (data[i] == ' ') { 
    ++i; 
  } 
  if(!data[i]) { 
    fprintf(stderr, "\nNumber missing");
    return APR_EGENERAL; 
  } 
  copy = apr_pstrdup(global->pool, &data[i]); 
  copy = replacer(global->pool, copy, replacer_hook, global_replacer);

  no = apr_strtok(copy, " ", &last);
  var = apr_strtok(NULL, " ", &last);

  if (!no) {
    fprintf(stderr, "\nNumber missing");
    return APR_EGENERAL;
  }

  n = apr_atoi64(no);

  for (i = 0; i < n; i++) {
    status = apr_proc_fork(&proc, global->pool);
    if (APR_STATUS_IS_INCHILD(status)) {
      if (var && strlen(var)) {
        store_set(global->vars, var, apr_itoa(global->pool, i));
      }
      return APR_SUCCESS;
    }
    else {
      apr_pool_note_subprocess(global->pool, &proc, APR_KILL_ALWAYS);
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
 * Global START command starts all so far defined threads 
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_START(command_t *self, global_t *global, char *data, 
                                 apr_pool_t *ptmp) {
  apr_status_t status;
  apr_table_entry_t *e;
  int i;
  worker_t *worker;
  apr_thread_t *thread;


  /* create all daemons first */
  e = (apr_table_entry_t *) apr_table_elts(global->daemons)->elts;
  for (i = 0; i < apr_table_elts(global->daemons)->nelts; ++i) {
    worker = (void *)e[i].val;
    if ((status =
	 apr_thread_create(&thread, global->tattr, worker_thread_daemon,
			   worker, global->pool)) != APR_SUCCESS) {
      fprintf(stderr, "\nCould not create deamon thread");
      return status;
    }
  }
  apr_table_clear(global->daemons);
  /* create all servers */
  e = (apr_table_entry_t *) apr_table_elts(global->servers)->elts;
  for (i = 0; i < apr_table_elts(global->servers)->nelts; ++i) {
    sync_lock(global->sync);
    worker = (void *)e[i].val;
    if ((status =
	 apr_thread_create(&thread, global->tattr, worker_thread_listener,
			   worker, global->pool)) != APR_SUCCESS) {
      fprintf(stderr, "\nCould not create server thread");
      return status;
    }
    apr_table_addn(global->threads, worker->name, (char *) thread);
  }
  apr_table_clear(global->servers);

  /* create clients */
  sync_lock(global->sync);
  sync_unlock(global->sync);
  e = (apr_table_entry_t *) apr_table_elts(global->clients)->elts;
  for (i = 0; i < apr_table_elts(global->clients)->nelts; ++i) {
    worker = (void *)e[i].val;
    status = htt_run_client_create(worker, worker_thread_client, &thread);
    if (status == APR_ENOTHREAD || status == APR_ENOTIMPL) {
      if ((status =
           apr_thread_create(&thread, global->tattr, worker_thread_client,
                             worker, global->pool)) != APR_SUCCESS) {
        fprintf(stderr, "\nCould not create client thread");
        return status;
      }
    }
    else if (status != APR_SUCCESS) {
      return status;
    }
    if (thread) {
      apr_table_addn(global->threads, worker->name, (char *) thread);
    }
  }
  apr_table_clear(global->clients);
   
  /* notify start threads */
  e = (apr_table_entry_t *) apr_table_elts(global->threads)->elts;
  for (i = 0; i < apr_table_elts(global->threads)->nelts; ++i) {
    thread = (apr_thread_t *) e[i].val;
    status = htt_run_thread_start(global, thread);
    if (status != APR_SUCCESS) {
      fprintf(stderr, "\nCould not start thread: %d", status);
      return status;
    }
  }
  return APR_SUCCESS;
}

/**
 * Global JOIN command waits for all started threads except DAEMONs
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_JOIN(command_t *self, global_t *global, char *data, 
                                apr_pool_t *ptmp) {
  apr_status_t status;
  apr_table_entry_t *e;
  int i;
  apr_thread_t *thread;

  /* join all started threads */
  e = (apr_table_entry_t *) apr_table_elts(global->threads)->elts;
  for (i = 0; i < apr_table_elts(global->threads)->nelts; ++i) {
    apr_status_t retstat;
    thread = (apr_thread_t *) e[i].val;
    status = htt_run_thread_join(global, thread);
    if (status == APR_ENOTHREAD || status == APR_ENOTIMPL) {
      if ((retstat = apr_thread_join(&status, thread))) {
        fprintf(stderr, "\nCould not join thread: %d", retstat);
        return retstat;
      }
    }
    else if (status != APR_SUCCESS) {
      fprintf(stderr, "\nCould not join thread: %d", status);
      return status;
    }
  }
  apr_table_clear(global->threads);

  htt_run_worker_joined(global);
  global->prefix = apr_pstrdup(global->pool, "");
  return APR_SUCCESS;
}
 

/**
 * Global GO command start all threads which are declared so far and wait
 * until all threads except DAEMON threads do have terminated.
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_GO(command_t *self, global_t *global, char *data, 
                              apr_pool_t *ptmp) {
  apr_status_t status = global_START(self, global, data, ptmp);
  if (status == APR_SUCCESS) {
    status = global_JOIN(self, global, data, ptmp);
  }
  return status;
}

/**
 * Global EXIT command for graceful script termination 
 * until all threads except DAEMON threads do have terminated.
 *
 * @param self IN command
 * @param global IN global object
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t global_EXIT(command_t *self, global_t *global, char *data, 
                                apr_pool_t *ptmp) {
  if (success) {
    exit(0);
  }
  else {
    exit(1);
  }
  /* never reach this point */
  return APR_ENOTIMPL;
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
  int i;
  int line_nr;
  global_replacer_t *replacer_hook;

  replacer_hook = apr_pcalloc(global->pool, sizeof(*replacer_hook));
  replacer_hook->ptmp = global->pool;
  replacer_hook->store = global->vars;

  if (global->recursiv > 8) {
    fprintf(stderr, "\nRecursiv inlcudes too deep");
    success = 0;
    exit(1);
  }

  if ((status = bufreader_new(&bufreader, fp, global->pool)) != APR_SUCCESS) {
    fprintf(stderr, "\nCould not create buf reader for interpreter");
    return status;
  }

  line_nr = 0;
  while (bufreader_read_line(bufreader, &line) == APR_SUCCESS) {
    ++line_nr;
    global->line_nr = line_nr;
    i = 0;
    if ((status = htt_run_read_line(global, &line)) != APR_SUCCESS) { 
      fprintf(stderr, "\nFailed on read line %s(%d)", my_status_str(global->pool, status), status);  
      return status;
    }
    if (line[i] != '#' && line[i] != 0) {
      /* lets see if we can start thread */
      if (global->state != GLOBAL_STATE_NONE) {
        if ((strlen(line) >= 3 && strncmp(line, "END", 3) == 0)) { 
	  i += 3;
	  if ((status = global_END(&global_commands[0], global, &line[i], NULL)) 
	      != APR_SUCCESS) {
	    fprintf(stderr, "\nError on global END");
	    return status;
	  }
        }
        else if ((status = worker_add_line(global->cur_worker, 
					   apr_psprintf(global->pool, "%s:%d", 
					   global->filename, line_nr), line)) 
	    != APR_SUCCESS) {
	  fprintf(stderr, "\nCould not add line lines table");
          return status;
        }
      }
      else {
	command_t *command;
	/* replace all variables for global commands */
	line = replacer(global->pool, &line[i], replacer_hook, global_replacer);

	/* lookup function index */
	i = 0;
	command = lookup_command(global_commands, line);
	if (command->func) {
	  i += strlen(command->name);
	  if ((status = command->func(command, global, &line[i], NULL)) 
	      != APR_SUCCESS) {
	    return status;
	  }
	}
        else { /* let's see if we find block for this job */
          int cur_log_mode = global->worker->log_mode;
          apr_pool_t *ptmp;

          apr_pool_create(&ptmp, NULL);
          global->worker->log_mode = 0;
          status = command_CALL(NULL, global->worker, line, ptmp);
          global->worker->log_mode = cur_log_mode;
          apr_pool_destroy(ptmp);
          if (status != APR_SUCCESS && !APR_STATUS_IS_ENOENT(status)) {
            return status;
          }
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
static apr_status_t interpret(apr_file_t * fp, store_t * vars,
                              int log_mode, apr_pool_t * p, char *additional) {
  apr_status_t status;
  int i;
  global_t *global;

  if ((status = global_new(&global, vars, log_mode, p)) 
      != APR_SUCCESS) {
    fprintf(stderr, "\nCould not create global");
    return status;
  }

  apr_hook_global_pool = global->pool;
  /**
   * Initialize registered modules
   */
  for(i = 0; modules[i].module_init; i++) {
    modules[i].module_init(global);
  }

  /* must be that late for builtin modules */
  /* for modules in includes it must be even later */
  if (log_mode == -1) {
    show_commands(p, global);
    return APR_SUCCESS;
  }

  /* must be that late for builtin modules */
  /* for modules in includes it must be even later */
  if (log_mode == -2) {
    show_command_help(p, global, additional); 
    return APR_SUCCESS;
  }

  process_global = global;
  
  apr_file_name_get(&global->filename, fp);
  if ((status = interpret_recursiv(fp, global)) != APR_SUCCESS) {
    return status;
  }

  status = global_GO(&global_commands[1], global, NULL, NULL);

  return status;
}

apr_getopt_option_t options[] = {
  { "version", 'V', 0, "Print version number and exit" },
  { "help", 'h', 0, "Display usage information (this message)" },
  { "suppress", 'n', 0, "do no print start and OK|FAILED" },
  { "silent", 's', 0, "silent mode" },
  { "error", 'e', 0, "log level error" },
  { "warn", 'w', 0, "log level warn" },
  { "info", 'i', 0, "log level info" },
  { "debug", 'd', 0, "log level debug for script debugging" },
  { "debug-system", 'p', 0, "log level debug-system to log more details" },
  { "list-commands", 'L', 0, "List all available script commands" },
  { "help-command", 'C', 1, "Print help for specific command" },
  { "duration", 't', 0, "Print test duration" },
  { "timestamp", 'T', 0, "Time stamp on every run" },
  { "shell", 'S', 0, "Shell mode" },
  { "shell", 'S', 0, "Shell mode" },
  { "define", 'D', 1, "Define variables" },
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

  if (command.flags & COMMAND_FLAGS_DEPRECIATED) {
    fprintf(stdout, "%s %s\n\t*** This command is depreciated ***", 
	    command.name, command.syntax);
  }
  else {
    fprintf(stdout, "%s %s", command.name, 
	    command.syntax);
  }
  help = apr_pstrdup(p, command.help);
  val = apr_strtok(help, "\n", &last);
  while (val) {
    fprintf(stdout, "\n\t%s", val);
    val = apr_strtok(NULL, "\n", &last);
  }
}

static int commands_compare(const char * const * right, 
                            const char * const *left) {
  return strcmp(*left, *right);
}

/**
 * Show all commands
 *
 * @param p IN pool
 */
static void show_commands(apr_pool_t *p, global_t *global) {
  int i;
  STACK_OF(char) *sorted;
  char *line;

  fprintf(stdout, "Global commands");
  sorted = SKM_sk_new(char, commands_compare);
  for (i = 0; global_commands[i].name; i++) {
    if (global_commands[i].flags & COMMAND_FLAGS_DEPRECIATED) {
      line = apr_psprintf(p, "%s *** This command is depreciated ***", 
	                  global_commands[i].name);
    }
    else if (global_commands[i].flags & COMMAND_FLAGS_LINK) {
      line = apr_psprintf(p, "%s -> %s", global_commands[i].name,
	                  global_commands[i].syntax);
    }
    else {
      line = apr_psprintf(p, "%s %s", global_commands[i].name, 
			  global_commands[i].syntax);
    }
    SKM_sk_push(char, sorted, line);
  }
  SKM_sk_sort(char, sorted);

  line = SKM_sk_pop(char, sorted);  
  while (line) {
    fprintf(stdout, "\n");
    fprintf(stdout, "\t%s", line);
    line = SKM_sk_pop(char, sorted);  
  }

  fprintf(stdout, "\n\nLocal commands");
  sorted = SKM_sk_new(char, commands_compare);
  for (i = 0; local_commands[i].name; i++) {
    if (local_commands[i].flags & COMMAND_FLAGS_DEPRECIATED) {
      line = apr_psprintf(p, "%s *** This command is depreciated ***", 
	                  local_commands[i].name);
    }
    else if (local_commands[i].flags & COMMAND_FLAGS_LINK) {
      line = apr_psprintf(p, "%s -> %s", local_commands[i].name,
	                  local_commands[i].syntax);
    }
    else {
      line = apr_psprintf(p, "%s %s", local_commands[i].name, 
			  local_commands[i].syntax);
    }
    SKM_sk_push(char, sorted, line);
  }
  SKM_sk_sort(char, sorted);

  line = SKM_sk_pop(char, sorted);  
  while (line) {
    fprintf(stdout, "\n");
    fprintf(stdout, "\t%s", line);
    line = SKM_sk_pop(char, sorted);  
  }

  fprintf(stdout, "\n\nModule commands");
  sorted = SKM_sk_new(char, commands_compare);
  {
    apr_hash_index_t *hi;
    const char *module;
    apr_hash_t *block;
    for (hi = apr_hash_first(p, global->modules); hi; hi = apr_hash_next(hi)) {
      apr_hash_this(hi, (const void **)&module, NULL, (void **)&block);
      if (strcmp(module, "DEFAULT") != 0 && block) {
	const char *command;
	apr_hash_index_t *hi;
	worker_t *worker;
	for (hi = apr_hash_first(p, block); hi; hi = apr_hash_next(hi)) {
	  apr_hash_this(hi, (const void **)&command, NULL, (void **)&worker);
	  if (command) {
            if (*command == '_') {
              ++command; /* skip "_" */
              line = apr_psprintf(p, "_%s:%s %s", module, command, 
                      worker->short_desc?worker->short_desc:"");
            }
            else {
              line = apr_psprintf(p, "%s:%s %s", module, command, 
                      worker->short_desc?worker->short_desc:"");
            }
	    SKM_sk_push(char, sorted, line);
	  }
	}
      }
    }
  }
  SKM_sk_sort(char, sorted);

  line = SKM_sk_pop(char, sorted);  
  while (line) {
    fprintf(stdout, "\n");
    fprintf(stdout, "\t%s", line);
    line = SKM_sk_pop(char, sorted);  
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
static void show_command_help(apr_pool_t *p, global_t *global, 
                              const char *command) {
  char *last;
  int i;

  for (i = 0; global_commands[i].name; i++) {
    if (strcmp(command, global_commands[i].name) == 0) {
      if (global_commands[i].flags & COMMAND_FLAGS_LINK) {
	/* this is a link, follow link */
	command = global_commands[i].syntax;
	break;
      }
      print_command_formated(p, global_commands[i]);
      goto exit;
    }
  }
  for (i = 0; local_commands[i].name; i++) {
    if (strcmp(command, local_commands[i].name) == 0) {
      if (local_commands[i].flags & COMMAND_FLAGS_LINK) {
	/* this is a link, follow link */
	command = local_commands[i].syntax;
	break;
      }
      print_command_formated(p, local_commands[i]);
      goto exit;
    }
  }

  if ((last = strchr(command, ':'))) {
    char *last;
    char *module;
    char *block_name;
    char *copy;
    apr_hash_t *blocks;
    worker_t *worker;

    copy = apr_pstrdup(p, command);
    /* determine module if any */
    module = apr_strtok(copy, ":", &last);
    if (*module == '_') {
      module++;
      block_name = apr_pstrcat(p, "_", last, NULL);
    }
    else {
      block_name = apr_pstrdup(p, last);
    }
    if (!(blocks = apr_hash_get(global->modules, module, APR_HASH_KEY_STRING))) {
      fprintf(stdout, "\ncommand: %s do not exist\n\n", command);
      exit(1);
    }
    if (!(worker = apr_hash_get(blocks, block_name, APR_HASH_KEY_STRING))) {
      fprintf(stdout, "\ncommand: %s do not exist\n", command);
      exit(1);
    }
    else {
      char *help;
      char *val;
      char *last;
      fprintf(stdout, "%s %s", command, worker->short_desc?worker->short_desc:"");
      help = apr_pstrdup(p, worker->desc);
      val = apr_strtok(help, "\n", &last);
      while (val) {
	fprintf(stdout, "\n\t%s", val);
	val = apr_strtok(NULL, "\n", &last);
      }
      goto exit;
    }

  }

  fprintf(stdout, "\ncommand: %s do not exist\n\n", command);
  exit(1);

exit:
  fprintf(stdout, "\n");
  fflush(stdout);
}

/**
 * own exit func
 */
static void my_exit() {
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
  store_t *vars;
  int log_mode;
#define MAIN_FLAGS_NONE 0
#define MAIN_FLAGS_PRINT_TSTAMP 1
#define MAIN_FLAGS_USE_STDIN 2
#define MAIN_FLAGS_NO_OUTPUT 4
#define MAIN_FLAGS_PRINT_DURATION 8
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

  /* create a global vars table */
  vars = store_make(pool);

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
    case 'p':
      log_mode = LOG_DEBUG;
      break;
    case 'w':
      log_mode = LOG_WARN;
      break;
    case 'i':
      log_mode = LOG_INFO;
      break;
    case 'd':
      log_mode = LOG_ALL_CMD;
      break;
    case 't':
      flags |= MAIN_FLAGS_PRINT_DURATION; 
      break;
    case 'L':
      interpret(NULL, NULL, -1, pool, NULL);
      break;
    case 'C':
      interpret(NULL, NULL, -2, pool, apr_pstrdup(pool, optarg));
      exit(0);
      break;
    case 'T':
      flags |= MAIN_FLAGS_PRINT_TSTAMP; 
      break;
    case 'S':
      flags |= MAIN_FLAGS_USE_STDIN; 
      break;
    case 'D':
      {
        char *val;
        char *var;
        char *entry = apr_pstrdup(pool, optarg);

        var = apr_strtok(entry, "=", &val);
        if (val && val[0]) {
          store_set(vars, var, val);
        }
        else {
          fprintf(stderr, "Error miss value in variable definition \"-D%s\", need the format -D<var>=<val>\n", optarg);
          fflush(stderr);
          exit(1);
        }
      }
      break;
    }
  }

  /* test for wrong options */
  if (!APR_STATUS_IS_EOF(status)) {
    fprintf(stderr, "try \"%s --help\" to get more information\n", filename(pool, argv[0]));
    exit(1);
  }

  /* test at least one file */
  if (!log_mode == -1 && !(flags & MAIN_FLAGS_USE_STDIN) && !(argc - opt->ind)) {
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

  /* do for all files (no wild card support) */
  while (flags & MAIN_FLAGS_USE_STDIN || argc - opt->ind) {
    if (flags & MAIN_FLAGS_USE_STDIN) {
      cur_file = apr_pstrdup(pool, "<stdin>");
    }
    else {
      cur_file = apr_pstrdup(pool, opt->argv[opt->ind++]);
    }

    if ((flags & MAIN_FLAGS_USE_STDIN)) {
      if (log_mode != LOG_NONE) {
        fprintf(stdout, "simple htt shell\n");
      }
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

    if (flags & MAIN_FLAGS_PRINT_DURATION) {
      time = apr_time_now();
    }
    /* interpret current file */
    if ((status = interpret(fp, vars, log_mode, pool, NULL)) != APR_SUCCESS) {
      success = 0;
      exit(1);
    }

    if (log_mode > LOG_WARN) {
      fprintf(stdout, "\n");
      fflush(stdout);
    }

    if (flags & MAIN_FLAGS_PRINT_DURATION) {
      time = apr_time_now() - time;
      fprintf(stdout, "%"APR_TIME_T_FMT , time);
      fflush(stdout);
    }

    /* close current file */
    apr_file_close(fp);

    if (flags & MAIN_FLAGS_USE_STDIN) {
      break;
    }
  }
  return 0;
}

APR_HOOK_STRUCT(
  APR_HOOK_LINK(module_init)
  APR_HOOK_LINK(read_line)
  APR_HOOK_LINK(block_start)
  APR_HOOK_LINK(block_end)
  APR_HOOK_LINK(server_port_args)
  APR_HOOK_LINK(worker_clone)
  APR_HOOK_LINK(client_create)
  APR_HOOK_LINK(thread_start)
  APR_HOOK_LINK(worker_finally)
  APR_HOOK_LINK(thread_join)
  APR_HOOK_LINK(worker_joined)
)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, server_port_args, 
                                      (worker_t *worker, char *portinfo, char **new_portinfo, char *rest_of_line), 
                                      (worker, portinfo, new_portinfo, rest_of_line), APR_SUCCESS);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, worker_clone, 
                                      (worker_t *worker, worker_t *clone), 
                                      (worker, clone), APR_SUCCESS);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, read_line, 
                                      (global_t *global, char **line), 
                                      (global, line), APR_SUCCESS);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, block_start, 
                                      (global_t *global, char **line), 
                                      (global, line), APR_ENOTIMPL);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, block_end, 
                                      (global_t *global), 
                                      (global), APR_SUCCESS);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, client_create, 
                                      (worker_t *worker, apr_thread_start_t func, apr_thread_t **new_thread), 
                                      (worker, func, new_thread), APR_ENOTIMPL);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, thread_start, 
                                      (global_t *global, apr_thread_t *thread), 
                                      (global, thread), APR_SUCCESS);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, worker_finally, 
                                      (worker_t *worker), 
                                      (worker), APR_SUCCESS);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, thread_join, 
                                      (global_t *global, apr_thread_t *thread), 
                                      (global, thread), APR_ENOTIMPL);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(htt, HTT, apr_status_t, worker_joined, 
                                      (global_t *global), 
                                      (global), APR_SUCCESS);
