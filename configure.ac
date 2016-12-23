#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

cC_PREREQ(2.53)
AC_INIT(httest, 2.4.18, ia97lies@sourceforge.net)
AC_CONFIG_AUX_DIR([config])
AM_CONFIG_HEADER([config/config.h])
AM_INIT_AUTOMAKE([subdir-objects])

dnl This is a Hack to deal with a Macro name descrpency between Autoconf
dnl Versions. 
m4_ifdef([AC_INIT_AUTOMAKE], [AC_INIT_AUTOMAKE]) dnl 2.53
m4_ifdef([AM_INIT_AUTOMAKE], [AM_INIT_AUTOMAKE]) dnl 2.57

# Setting up C compiler stuff 
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
AC_AIX
AC_ISC_POSIX
AC_HEADER_STDC
AC_CHECK_HEADERS([unistd.h])
AC_PROG_LIBTOOL
AC_CONFIG_MACRO_DIR([m4])

# Checks for typedefs, structures, and compiler characteristics.
dnl 2.53 also doesn't have this
m4_ifdef([AC_HEADER_STDBOOL], [AC_HEADER_STDBOOL])
AC_C_CONST
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([bzero select socket])

# customize settings
AC_ARG_ENABLE([use-static], AS_HELP_STRING(--enable-use-static,Try to use archives instead of shared libraries))
AC_ARG_ENABLE([full-static], AS_HELP_STRING(--enable-full-static,Try to compile a statical linked executable))
AC_ARG_ENABLE([iconv-support], AS_HELP_STRING(--enable-iconv-support,enable iconv support))
AC_ARG_ENABLE([ssl-legacy-reneg], AS_HELP_STRING(--enable-ssl-legacy-reneg, enable unsafe legacy renegotation only needed for openssl 0.9.8l))
AC_ARG_ENABLE([lua-module], AS_HELP_STRING(--enable-lua-module,Add Lua support))
AC_ARG_ENABLE([js-module], AS_HELP_STRING(--enable-js-module,Add JavaScript support))
AC_ARG_ENABLE([html-module], AS_HELP_STRING(--enable-html-module,Add html support))
AC_ARG_ENABLE([xml-module], AS_HELP_STRING(--enable-xml-module,Add xml support))
AC_ARG_ENABLE([h2-module], AS_HELP_STRING(--enable-h2-module,Add http/2 support))
AC_ARG_ENABLE([perf-module], AS_HELP_STRING(--enable-perf-module,Add performance measuring support including distributed perfromance measuring))
AC_ARG_WITH(apr,AS_HELP_STRING(--with-apr=PATH,path to apr-1-config script),
	[if test ! -x $withval/apr-1-config; then AC_MSG_ERROR($withval/apr-1-config do not exist or is not executable); else APR_CONFIG="$withval/apr-1-config"; fi],
	[APR_CONFIG="apr-1-config"])
AC_ARG_WITH(apr-util,AS_HELP_STRING(--with-apr-util=PATH,path to apu-1-config script),
	[if test ! -x $withval/apu-1-config; then AC_MSG_ERROR($withval/apu-1-config do not exist or is not executable); else APU_CONFIG="$withval/apu-1-config"; fi],
	[APU_CONFIG="apu-1-config"])
AC_ARG_WITH(apr-iconv,AS_HELP_STRING(--with-apr-iconv=PATH,path to apr-iconv directory),
	[if test ! -f $withval/include/apr_iconv.h; then 
	   AC_MSG_ERROR($withval/include/apr_iconv.h do not exist); 
	 else 
	   APR_ICONV_INCLUDES="-I$withval/include"; 
	   APR_ICONV_LIBS="-L$withval/lib/.libs"; 
	 fi],
	[APR_ICONV_INCLUDES="";
	 APR_ICONV_LIBS=""])
AC_ARG_WITH(pcre,AS_HELP_STRING(--with-pcre=PATH,path to pcre-config script),
	[if test ! -x $withval/pcre-config; then AC_MSG_ERROR($withval/pcre-config do not exist or is not executable); else PCRE_CONFIG="$withval/pcre-config"; fi],
	[PCRE_CONFIG="pcre-config"])
AC_ARG_WITH(lua,AS_HELP_STRING(--with-lua=PATH,path to lua source dir),
	[if test ! -d $withval; then AC_MSG_ERROR($withval is not a directory); else LUA_LIB_PATH="-L${withval}"; LUA_INCLUDES="-I${withval}"; LUA_LIB="-llua"; fi],
        [LUA_LIB_PATH=""; if test -d /usr/include/lua5.1; then LUA_INCLUDES="-I/usr/include/lua5.1"; else LUA_INCLUDES=""; fi; if test -f /usr/lib/liblua5.1.a -o -f /usr/lib/liblua5.1.so -o -f /usr/lib/i386-linux-gnu/liblua5.1.so -o -f /usr/lib/i386-linux-gnu/liblua5.1.a; then LUA_LIB="-llua5.1"; else LUA_LIB="-llua"; fi])
AC_ARG_WITH(spidermonkey,AS_HELP_STRING(--with-spidermonkey=PATH,path to js-config script),
	[if test ! -x $withval/js-config; then AC_MSG_ERROR($withval/js-config do not exist or is not executable); else JS_CONFIG="$withval/js-config"; fi],
	[JS_CONFIG="js-config"])
AC_ARG_WITH(libxml2,AS_HELP_STRING(--with-libxml2=PATH,path to xml2-config script),
	[if test ! -x $withval/xml2-config; then AC_MSG_ERROR($withval/xml2-config do not exist or is not executable); else XML2_CONFIG="$withval/xml2-config"; fi],
	[XML2_CONFIG="xml2-config"])
AC_ARG_WITH(nghttp2,AS_HELP_STRING(--with-nghttp2=PATH,path to nghttp2 source),
	[if test ! -d $withval; then AC_MSG_ERROR($withval is not a directory); else NGHTTP2_LIB_PATH="-L${withval}/lib"; NGHTTP2_INCLUDES="-I${withval}/include"; fi],
	[NGHTTP2_LIB_PATH=""; NGHTTP2_INCLUDES=""])
AC_ARG_WITH(ssl,AS_HELP_STRING(--with-ssl=PATH,path to openssl source),
	[if test ! -d $withval; then AC_MSG_ERROR($withval is not a directory); else OPENSSL_LIB_PATH="-L${withval}"; OPENSSL_INCLUDES="-I${withval}/include"; fi],
	[OPENSSL_LIB_PATH=""; OPENSSL_INCLUDES=""])

APR_VERSION=`$APR_CONFIG --version`
if test ! "$?" = "0"; then
  echo "libapr is missing"
  exit -1
fi
APU_VERSION=`$APU_CONFIG --version`
if test ! "$?" = "0"; then
  echo "libaprutil is missing"
  exit -1
fi
PCRE_VERSION=`$PCRE_CONFIG --version`
if test ! "$?" = "0"; then
  echo "libpcre is missing"
  exit -1
fi

# Store settings for includes, libs and flags
INCLUDES="`$APR_CONFIG --includes` `$APU_CONFIG --includes` $OPENSSL_INCLUDES $APR_ICONV_CONFIG"
CFLAGS="`$APR_CONFIG --cflags` `$PCRE_CONFIG --cflags` $CFLAGS $INCLUDES"
CPPFLAGS="`$APR_CONFIG --cppflags` $CPPFLAGS"
LIBS="$OPENSSL_LIB_PATH -lssl -lcrypto `$APR_CONFIG --link-ld`  `$APU_CONFIG --link-ld` `$APR_CONFIG --libs` `$APU_CONFIG --libs` `$PCRE_CONFIG --libs` -lz -lm"

if test "$enable_ssl_legacy_reneg" = "yes"; then
  CFLAGS="$CFLAGS -DSSL_ALLOW_UNSAFE_LEGACY_RENEGOTIATION"
fi

# if link static
if test "$enable_full_static" = "yes"; then
  LDFLAGS="-all-static $LDFLAGS"
fi

# if link static
if test "$enable_use_static" = "yes"; then
  LDFLAGS="-static $LDFLAGS"
fi

if test "$enable_iconv_support" = "yes"; then
  CFLAGS="$CFLAGS $APR_ICONV_INCLUDES -DICONV_SUPPORT"
  LIBS="$LIBS $APR_ICONV_LIBS -lapriconv-1"
fi

MODULES="dso annotation charset dbg sys math coder date binary websocket socks udp tcp ssl" 

HTTEST_MODULES='' 
if test "$enable_lua_module" = "yes"; then
  CFLAGS="$CFLAGS $LUA_INCLUDES"
  LIBS="$LIBS $LUA_LIB_PATH $LUA_LIB"
  HTTEST_MODULES="$HTTEST_MODULES lua_crypto.${OBJEXT} lua_module.${OBJEXT}"
  MODULES=" lua $MODULES"
fi
if test "$enable_js_module" = "yes"; then
  JS_VERSION=`$JS_CONFIG --version`
  if test ! "$?" = "0"; then
    echo "spidermonkey lib is missing"
    exit -1
  fi
  CFLAGS="$CFLAGS `$JS_CONFIG --cflags`"
  LIBS="$LIBS `$JS_CONFIG --libs` -lstdc++"
  HTTEST_MODULES="$HTTEST_MODULES js_module.${OBJEXT}"
  MODULES=" js $MODULES "
fi
if test "$enable_html_module" = "yes"; then
  XML2_VERSION=`$XML2_CONFIG --version`
  if test ! "$?" = "0"; then
    echo "libxml2 is missing"
    exit -1
  fi
  CFLAGS="$CFLAGS `$XML2_CONFIG --cflags`"
  LIBS="$LIBS `$XML2_CONFIG --libs`"
  HTTEST_MODULES="$HTTEST_MODULES html_module.${OBJEXT}"
  MODULES=" html $MODULES"
fi
if test "$enable_xml_module" = "yes"; then
  XML2_VERSION=`$XML2_CONFIG --version`
  if test ! "$?" = "0"; then
    echo "libxml2 is missing"
    exit -1
  fi
  CFLAGS="$CFLAGS `$XML2_CONFIG --cflags`"
  LIBS="$LIBS `$XML2_CONFIG --libs`"
  HTTEST_MODULES="$HTTEST_MODULES xml_module.${OBJEXT}"
  MODULES=" xml $MODULES"
fi

if test "$enable_h2_module" = "yes"; then
  HTTEST_MODULES="$HTTEST_MODULES h2_module.${OBJEXT}"
  MODULES=" $MODULES h2"
  CFLAGS="$CFLAGS $NGHTTP2_INCLUDES"
  LIBS="$LIBS $NGHTTP2_LIB_PATH -lnghttp2"
fi

if test "$enable_perf_module" = "yes"; then
  HTTEST_MODULES="$HTTEST_MODULES perf_module.${OBJEXT}"
  MODULES=" $MODULES perf"
fi

if test -f ./generate_modules_c.sh; then
  ./generate_modules_c.sh "${MODULES}"
fi
AC_SUBST([HTTEST_MODULES])

# generate makefiles
AC_CONFIG_FILES([Makefile
                 tools/Makefile
                 src/Makefile
                 include/Makefile
                 macros/Makefile
                 examples/Makefile
                 scripts/Makefile
                 scripts/pentester/Makefile
                 plugins/Makefile
                 plugins/bbedit/Makefile
                 plugins/crimson/Makefile
                 plugins/gedit/Makefile
                 plugins/notepadpp/Makefile
                 plugins/vim/Makefile
                 plugins/xemacs/Makefile
                 test/Makefile])
AC_OUTPUT

