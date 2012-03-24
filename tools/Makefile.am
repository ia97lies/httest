# $Id: Makefile.am,v 1.4 2009/07/21 20:29:30 ia97lies Exp $


bin_PROGRAMS=htx2b hturlext
dist_man_MANS = htx2b.1 hturlext.1

htx2b_SOURCES= \
	htx2b.c

hturlext_SOURCES= \
	hturlext.c

hturlext_INCLUDES=-I ../3thrdparty/libxml/include

htx2b.1: htx2b.c $(top_srcdir)/configure.in
	$(MAKE) $(AM_MAKEFLAGS) htx2b$(EXEEXT)
	help2man -N -n "record a HTTP session" --output=htx2b.1 ./htx2b$(EXEEXT)
hturlext.1: hturlext.c $(top_srcdir)/configure.in
	$(MAKE) $(AM_MAKEFLAGS) hturlext$(EXEEXT)
	help2man -N -n "record a HTTP session" --output=hturlext.1 ./hturlext$(EXEEXT)

