# $Id: Makefile.am,v 1.19 2009/07/19 18:31:10 ia97lies Exp $

bin_PROGRAMS=httest htproxy htremote htntlm

httest_SOURCES= \
	httest.c file.c socket.c regex.c util.c ssl.c worker.c module.c binary_module.c ssl_module.c modules.c

htproxy_SOURCES= \
	htproxy.c file.c socket.c regex.c util.c ssl.c worker.c conf.c

htremote_SOURCES= \
	htremote.c file.c socket.c util.c

htntlm_SOURCES= \
	htntlm.c util.c

noinst_HEADERS= \
	defines.h file.h socket.h regex.h util.h ssl.h worker.h conf.h module.h
