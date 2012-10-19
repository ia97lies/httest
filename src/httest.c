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
#include "htt_defines.h"

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

#include "htt_bufreader.h"
#include "htt_util.h"
#include "htt_core.h"
#include "htt_log.h"
#include "htt_map.h"

/************************************************************************
 * Defines 
 ***********************************************************************/

/************************************************************************
 * Structurs
 ***********************************************************************/

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Private 
 ***********************************************************************/

apr_getopt_option_t options[] = {
  { "version", 'V', 0, "Print version number and exit" },
  { "help", 'h', 0, "Display usage information (this message)" },
  { "suppress", 'n', 0, "do no print start and OK|FAILED" },
  { "silent", 's', 0, "silent mode" },
  { "error", 'e', 0, "log level error" },
  { "warn", 'w', 0, "log level warn" },
  { "info", 'i', 0, "log level info" },
  { "debug", 'd', 0, "log level debug for script debugging" },
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
 * display copyright information
 *
 * @param program name
 */
static void copyright(const char *progname) {
  printf("%s " PACKAGE_VERSION "\n", progname);
  printf("\nCopyright (C) 2006 Free Software Foundation, Inc.\n"
         "This is free software; see the source for copying conditions.  There is NO\n"
	 "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
  printf("\nWritten by Christian Liesch\n");
}

/************************************************************************
 * Main 
 ***********************************************************************/

/** 
 * htt main 
 *
 * @param argc IN number of arguments
 * @param argv IN argument array
 *
 * @return 0 if htt_error
 */
int main(int argc, const char *const argv[]) {
  apr_status_t status;
  apr_getopt_t *opt;
  const char *optarg;
  int c;
  apr_pool_t *pool;
  char *cur_file;
  apr_file_t *fp;
  int log_mode;
#define MAIN_FLAGS_NONE 0
#define MAIN_FLAGS_PRINT_TSTAMP 1
#define MAIN_FLAGS_USE_STDIN 2
#define MAIN_FLAGS_NO_OUTPUT 4
#define MAIN_FLAGS_PRINT_DURATION 8
  int flags;
  apr_time_t time;
  char time_str[256];
  htt_t *htt;
  apr_file_t *out;
  apr_file_t *err;

  srand(apr_time_now()); 
  
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  /* block broken pipe signal */
#if !defined(WIN32)
  apr_signal_block(SIGPIPE);
#endif
  
  /* set default */
  htt = htt_new(pool);

  log_mode = HTT_LOG_CMD;
  flags = MAIN_FLAGS_NONE;

  /* get options */
  apr_getopt_init(&opt, pool, argc, argv);
  while ((status = apr_getopt_long(opt, options, &c, &optarg)) == APR_SUCCESS) {
    switch (c) {
    case 'h':
      usage("httest");
      exit(0);
      break;
    case 'V':
      copyright("httest");
      exit(0);
      break;
    case 'n':
      flags |= MAIN_FLAGS_NO_OUTPUT; 
      break;
    case 's':
      log_mode = HTT_LOG_NONE;
      break;
    case 'e':
      log_mode = HTT_LOG_ERROR;
      break;
    case 'w':
      log_mode = HTT_LOG_WARN;
      break;
    case 'i':
      log_mode = HTT_LOG_INFO;
      break;
    case 'd':
      log_mode = HTT_LOG_DEBUG;
      break;
    case 't':
      flags |= MAIN_FLAGS_PRINT_DURATION; 
      break;
    case 'L':
      break;
    case 'C':
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
          htt_add_value(htt, var, val);
        }
        else {
          fprintf(stderr, "Error miss value in variable definition \"-D%s\", "
                          "need the format -D<var>=<val>\n", optarg);
          fflush(stderr);
          htt_throw_error();
        }
      }
      break;
    }
  }

  /* test for wrong options */
  if (!APR_STATUS_IS_EOF(status)) {
    fprintf(stderr, "try \"httest --help\" to get more information\n");
    htt_throw_error();
  }

  /* test at least one file */
  if (!log_mode == -1 && !(flags & MAIN_FLAGS_USE_STDIN) && !(argc - opt->ind)) {
    fprintf(stderr, "httest: wrong number of arguments\n\n");
    fprintf(stderr, "try \"httest --help\" to get more information\n");
    htt_throw_error();
  }

  if (flags & MAIN_FLAGS_NO_OUTPUT) {
    atexit(htt_no_output_exit);
  }
  else {
    atexit(htt_exit);
  }

  apr_file_open_stdout(&out, pool);
  apr_file_open_stderr(&err, pool);
  htt_set_log(htt, out, err, log_mode);

  /* do for all files (no wild card support) */
  while (flags & MAIN_FLAGS_USE_STDIN || argc - opt->ind) {
    if (flags & MAIN_FLAGS_USE_STDIN) {
      cur_file = apr_pstrdup(pool, "<stdin>");
    }
    else {
      cur_file = apr_pstrdup(pool, opt->argv[opt->ind++]);
    }

    if ((flags & MAIN_FLAGS_USE_STDIN)) {
      if (log_mode != HTT_LOG_NONE) {
        fprintf(stdout, "simple htt shell\n");
      }
    }
    else if (flags & MAIN_FLAGS_PRINT_TSTAMP) {
      time = apr_time_now();
      if ((status = apr_ctime(time_str, time)) != APR_SUCCESS) {
	fprintf(stderr, "Could not format time: %s (%d)\n", 
	        htt_util_status_str(pool, status), status);
        htt_throw_error();
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
	        htt_util_status_str(pool, status), status);
        htt_throw_error();
      }
    }
    else if ((status = apr_file_open(&fp, cur_file, APR_READ, APR_OS_DEFAULT, 
                                     pool)) != APR_SUCCESS) {
      fprintf(stderr, "\nCould not open %s: %s (%d)", cur_file,
	      htt_util_status_str(pool, status), status);
      htt_throw_error();
    }

    if (flags & MAIN_FLAGS_PRINT_DURATION) {
      time = apr_time_now();
    }

    htt_set_cur_file_name(htt, cur_file);
    if ((status = htt_compile_fp(htt, fp)) != APR_SUCCESS) {
      htt_throw_error();
    }

    if ((status = htt_run(htt)) != APR_SUCCESS) {
      htt_throw_error();
    }

    if (log_mode > HTT_LOG_WARN) {
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

  apr_pool_destroy(pool);

  return 0;
}

