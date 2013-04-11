# $Id: Makefile.am,v 1.19 2009/07/19 18:31:10 ia97lies Exp $

bin_PROGRAMS = httest htproxy htremote htntlm
dist_man_MANS = httest.1 htproxy.1 htntlm.1 htremote.1

httest_SOURCES = \
	httest.c file.c socket.c regex.c util.c replacer.c ssl.c worker.c \
	module.c transport.c store.c eval.c logger.c \
	modules.c ssl_module.c tcp_module.c skeleton_module.c date_module.c \
	coder_module.c math_module.c sys_module.c binary_module.c \
	udp_module.c socks_module.c websocket_module.c dbg_module.c \
	perf_module.c annotation_module.c charset_module.c

EXTRA_httest_SOURCES = \
	lua_crypto.c lua_module.c js_module.c html_module.c xml_module.c

httest_LDADD = $(HTTEST_MODULES)
httest_DEPENDENCIES = $(HTTEST_MODULES)

htproxy_SOURCES = \
	htproxy.c file.c socket.c regex.c util.c ssl.c replacer.c worker.c \
	module.c conf.c transport.c store.c tcp_module.c eval.c logger.c

htremote_SOURCES = \
	htremote.c util.c store.c

htntlm_SOURCES = \
	htntlm.c util.c store.c

noinst_HEADERS = \
	defines.h file.h socket.h regex.h util.h ssl.h worker.h conf.h \
	module.h transport.h store.h eval.h replacer.h tcp_module.h \
	lua_crypto.h logger.h httest.ext

     
httest.1: httest.c $(top_srcdir)/configure.in
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

