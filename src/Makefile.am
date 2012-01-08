# $Id: Makefile.am,v 1.19 2009/07/19 18:31:10 ia97lies Exp $

bin_PROGRAMS=httest htproxy htremote htntlm

httest_SOURCES= \
	httest.c file.c socket.c regex.c util.c replacer.c ssl.c worker.c \
	module.c transport.c store.c eval.c \
	modules.c ssl_module.c tcp_module.c skeleton_module.c date_module.c \
	coder_module.c math_module.c sys_module.c binary_module.c \
	udp_module.c socks_module.c websocket_module.c

EXTRA_httest_SOURCES= \
	lua_module.c 

httest_LDADD = $(HTTEST_MODULES)
httest_DEPENDENCIES = $(HTTEST_MODULES)

htproxy_SOURCES= \
	htproxy.c file.c socket.c regex.c util.c ssl.c replacer.c worker.c \
	module.c conf.c transport.c store.c tcp_module.c 

htremote_SOURCES= \
	htremote.c util.c store.c

htntlm_SOURCES= \
	htntlm.c util.c store.c

noinst_HEADERS= \
	defines.h file.h socket.h regex.h util.h ssl.h worker.h conf.h \
	module.h transport.h store.h eval.h replacer.h tcp_module.h

