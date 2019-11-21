# $Id: Makefile.am,v 1.19 2009/07/19 18:31:10 ia97lies Exp $

bin_PROGRAMS = httest
#	       htproxy htremote htntlm
dist_man_MANS = httest.1
#		htproxy.1 htntlm.1 htremote.1

httest_SOURCES = \
	httest.c htt_core.c htt_context.c htt_executable.c htt_map.c \
	htt_log.c htt_log_appender.c htt_util.c htt_stack.c htt_bufreader.c \
	htt_replacer.c htt_command.c htt_string.c htt_function.c htt_socket.c \
	htt_transport.c \
	core_module.c thread_module.c exception_module.c \
	shell_module.c htt_modules.c htt_log_simple_appender.c \
	htt_log_std_appender.c log_module.c dbg_module.c \
	coder_module.c

#EXTRA_httest_SOURCES = \
#	lua_module.c

httest_LDADD = $(HTTEST_MODULES)
httest_DEPENDENCIES = $(HTTEST_MODULES)

#htproxy_SOURCES = \
#	htproxy.c file.c socket.c regex.c util.c ssl.c replacer.c worker.c \
#	module.c conf.c transport.c store.c tcp_module.c eval.c

#htremote_SOURCES = \
#	htremote.c util.c store.c

#htntlm_SOURCES = \
#	htntlm.c util.c store.c

noinst_HEADERS = \
	htt_defines.h htt_object.h htt_core.h htt_context.h htt_executable.h \
	htt_log.h htt_log_appender.h htt_map.h htt_util.h htt_stack.h \
	htt_bufreader.h htt_replacer.h htt_command.h htt_string.h \
	htt_function.h htt_socket.h htt_expr.h htt_modules.h \
	htt_log_simple_appender.h htt_log_std_appender.h htt_transport.h

#	file.h socket.h regex.h util.h ssl.h worker.h conf.h \
#	module.h transport.h store.h eval.h replacer.h tcp_module.h \
#	lua_crypto.h httest.ext

     
httest.1: htt_core.c $(top_srcdir)/configure.in
	$(MAKE) $(AM_MAKEFLAGS) httest$(EXEEXT)
	help2man -N -n "test HTTP driven application" -i $(top_srcdir)/src/httest.ext --output=httest.1 ./httest$(EXEEXT)
htproxy.1: htproxy.c $(top_srcdir)/configure.in
	$(MAKE) $(AM_MAKEFLAGS) htproxy$(EXEEXT)
	help2man -N -n "record a HTTP session" --output=htproxy.1 ./htproxy$(EXEEXT)
htntlm.1: htntlm.c $(top_srcdir)/configure.in
	$(MAKE) $(AM_MAKEFLAGS) htntlm$(EXEEXT)
	help2man -N -n "read/write NTLM message" --output=htntlm.1 ./htntlm$(EXEEXT)
htremote.1: htremote.c $(top_srcdir)/configure.in
	$(MAKE) $(AM_MAKEFLAGS) htremote$(EXEEXT)
	help2man -N -n "record a HTTP session" --output=htremote.1 ./htremote$(EXEEXT)

