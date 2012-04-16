#!/bin/bash

#
# print "OK"
#
function print_ok {
  # bold green
  echo "$(tput bold)$(tput setaf 2)OK$(tput sgr 0)"
}

#
# print "OK (up to date)"
#
function print_ok_up_to_date {
  # bold blue
  echo "$(tput bold)$(tput setaf 4)OK$(tput sgr 0) $(tput setaf 7)(up to date)$(tput sgr 0)"
}

#
# print "FAILED"
#
function print_failed {
  # bold red
  echo "$(tput bold)$(tput setaf 1)FAILED$(tput sgr 0) $(tput setaf 7)(see target/build.log for details)$(tput sgr 0)"
}

#
# determine OS
#
function do_determine_os {
  OS="unknown"
  UNIX="1"
  if [ `uname -o 2>/dev/null` ]; then
    if [ `uname -o` == "GNU/Linux" ]; then
      OS="linux"
    elif [ `uname -o` == "Cygwin" ]; then
      OS="win"
      UNIX="0"
    fi
  elif [ `uname -s` == "Darwin" ]; then
    OS="mac"
  fi
  echo "OS:   $OS"
  if [ "$OS" == "unknown" ]; then
    # yellow bold
    echo "$(tput bold)$(tput setaf 3)WARNING:$(tput sgr 0) unknown os, treating like linux"
  fi
  
  ARCH=`uname -m`
  echo "ARCH: $ARCH"
  BITS=`getconf LONG_BIT`
  echo "BITS: $BITS"  
}

#
# create target dir if it does not exist, yet
#
function do_create_target {
  echo -n "creating target dir ... "
  if [ -d "$ROOT/target" ]; then
    print_ok_up_to_date
  else
    mkdir "$ROOT/target"
    print_ok
  fi
}

#
# download und unpack lib according to LIB_* variables
#
function get_lib {
  if [ "$OS" == "mac" ]; then
    ftp "$LIB_PROT://$LIB_HOST$LIB_PATH/$LIB_FILE"
  elif [ "$LIB_PROT" == "http" ]; then
    wget "$LIB_PROT://$LIB_HOST$LIB_PATH/$LIB_FILE"
  else
    ftp -n $LIB_HOST <<EOF
    quote USER anonymous
    quote PASS htt@htt.sf.net
    cd $LIB_PATH
    bin
    get $LIB_FILE
    quit
EOF
  fi
  gzip -d -c "$LIB_FILE" > "$LIB_NAME-$LIB_VER.tar"
  tar xf "$LIB_NAME-$LIB_VER.tar"
  rm "$LIB_FILE"
  rm "$LIB_NAME-$LIB_VER.tar"
}

#
# download and unpack lib if not already there
#
function do_get_lib {
  PRE="$1_$2_"
  eval LIB_NAME="\$${PRE}NAME"
  eval LIB_VER="\$${PRE}VER"
  eval LIB_PROT="\$${PRE}PROT"
  eval LIB_HOST="\$${PRE}HOST"
  eval LIB_PATH="\$${PRE}PATH"
  eval LIB_FILE="\$${PRE}FILE"
  cd "$ROOT/target"
  echo -n "getting lib $LIB_NAME $LIB_VER ... "
  if [ -d "$LIB_NAME-$LIB_VER" ]; then
    print_ok_up_to_date
  else
    get_lib >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build apr
#
function unix_build_apr {
  cd "$ROOT/target/$UNIX_APR_NAME-$UNIX_APR_VER"
  ./configure
  make
  [ -f .libs/libapr-1.a ]
}

#
# unix: build apr if no lib, yet
#
function do_unix_build_apr {
  echo -n "building apr ... "  
  if [ -f "$ROOT/target/$UNIX_APR_NAME-$UNIX_APR_VER/.libs/libapr-1.a" ]; then
    print_ok_up_to_date
  else
    unix_build_apr >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build apr-util
#
function unix_build_apr_util {
  cd "$ROOT/target/$UNIX_APR_UTIL_NAME-$UNIX_APR_UTIL_VER"
  ./configure --with-apr="$ROOT/target/$UNIX_APR_NAME-$UNIX_APR_VER"
  make
  [ -f .libs/libaprutil-1.a ]
}

#
# unix: build apr-util if no lib, yet
#
function do_unix_build_apr_util {
  echo -n "building apr-util ... "  
  if [ -f "$ROOT/target/$UNIX_APR_UTIL_NAME-$UNIX_APR_UTIL_VER/.libs/libaprutil-1.a" ]; then
    print_ok_up_to_date
  else
    unix_build_apr_util >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# helper function for creating a simple custom *-config script
#
function create_custom_config {
  NAME=$1
  VER=$2
  CFLAGS="$3"
  LIBS="$4"
  DIR=`pwd`
  mv $NAME-config $NAME-config.orig
  cat > "$NAME-config" << EOF
#!/bin/sh

DIR=$DIR

while test \$# -gt 0; do
  case \$1 in
    --version)
      echo $VER
      ;;
    --cflags)
      echo $CFLAGS
      ;;
    --libs)
      echo $LIBS
      ;;
    *)
      echo "illegal argument" 1>&2
      exit 1
      ;;
  esac
  shift
done
EOF
  chmod +x $NAME-config
}

#
# inxi: build pcre
#
function unix_build_pcre {
  cd "$ROOT/target/$UNIX_PCRE_NAME-$UNIX_PCRE_VER"
  ./configure
  make
  create_custom_config $UNIX_PCRE_NAME $UNIX_PCRE_VER \
    "-I\${DIR}" "-L\${DIR}/.libs -lpcre"
  [ -f .libs/libpcre.a ]
}

#
# unix: build pcre if no lib, yet
#
function do_unix_build_pcre {
  echo -n "building pcre ... "  
  if [ -f "$ROOT/target/$UNIX_PCRE_NAME-$UNIX_PCRE_VER/.libs/libpcre.a" ]; then
    print_ok_up_to_date
  else
    unix_build_pcre >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build openssl
#
function unix_build_openssl {
  cd "$ROOT/target/$UNIX_OPENSSL_NAME-$UNIX_OPENSSL_VER"
  if [ "$OS" = "mac" ]; then
    ./Configure darwin64-x86_64-cc
  else
    ./config
  fi
  make
  [ -f libssl.a ]
}

#
# unix: build openssl if no lib, yet
#
function do_unix_build_openssl {
  echo -n "building openssl ... "  
  if [ -f "$ROOT/target/$UNIX_OPENSSL_NAME-$UNIX_OPENSSL_VER/libssl.a" ]; then
    print_ok_up_to_date
  else
    unix_build_openssl >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build lua if no lib, yet
#
function unix_build_lua {
  cd "$ROOT/target/$UNIX_LUA_NAME-$UNIX_LUA_VER"
  if [ "$OS" = "mac" ]; then
    make macosx
  else
    make linux
  fi
  make test
  [ -f src/liblua.a ]
}

#
# unix: build lua if no lib, yet
#
function do_unix_build_lua {
  echo -n "building lua ... "  
  if [ -f "$ROOT/target/$UNIX_LUA_NAME-$UNIX_LUA_VER/src/liblua.a" ]; then
    print_ok_up_to_date
  else
    unix_build_lua >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build js
#
function unix_build_js {
  cd "$ROOT/target/$UNIX_JS_NAME-$UNIX_JS_VER"
  cd js/src
  if [ "$OS" = "mac" ]; then
    mv configure configure.orig
    cat configure.orig | awk '
      /if test .z ..CC.; then CC=gcc.4.2; fi/ {
        print "    if test -z \"$CC\"; then CC=gcc; fi"
        next
      }
      /if test .z ..CXX.; then CXX=g...4.2; fi/ {
        print "    if test -z \"$CXX\"; then CXX=g++; fi"
        next
      }
      /CFLAGS...CFLAGS .fpascal-strings .fno-common/ {
        print "    CFLAGS=\"$CFLAGS -fno-common\""
        next
      }
      /CXXFLAGS...CXXFLAGS .fpascal-strings .fno-common/ {
        print "    CXXFLAGS=\"$CXXFLAGS -fno-common\""
        next
      }
      { print $0 }' > configure
    chmod +x configure
  fi
  ./configure --disable-shared-js
  make
  create_custom_config $UNIX_JS_NAME $UNIX_JS_VER "-I\${DIR}" "-L\${DIR} -ljs_static"
  [ -f libjs_static.a ]
}

#
# unix: build js if no lib, yet
#
function do_unix_build_js {
  echo -n "building js ... "  
  if [ -f "$ROOT/target/$UNIX_JS_NAME-$UNIX_JS_VER/js/src/libjs_static.a" ]; then
    print_ok_up_to_date
  else
    unix_build_js >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build libmlx2
#
function unix_build_libxml2 {
  cd "$ROOT/target/$UNIX_LIBXML2_NAME-$UNIX_LIBXML2_VER"
  ./configure
  make
  create_custom_config "xml2" $UNIX_LIBXML2_VER \
    "-I\${DIR}/include" "-L\${DIR} -lxml2"
  [ -f .libs/libxml2.a ]
}

#
# unix: build libmlx2 if no lib, yet
#
function do_unix_build_libxml2 {
  echo -n "building libxml2 ... "  
  if [ -f "$ROOT/target/$UNIX_LIBXML2_NAME-$UNIX_LIBXML2_VER/.libs/libxml2.a" ]; then
    print_ok_up_to_date
  else
    unix_build_libxml2 >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: run buildconf.sh
#
function unix_buildconf {
  cd "$ROOT/.."
  ./buildconf.sh
  [ -f configure ]
}

#
# unix: run buildconf.sh if not configure script, yet
#
function do_unix_buildconf {
  echo -n "building htt configuration ... "  
  if [ -f "$ROOT/../configure" ]; then
    print_ok_up_to_date
  else
    unix_buildconf >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: (re-(build httest binaries with all libraries listed below
# statically linked (note "make clean all" which makes sure binaries
# are always built that way here...)
#
function unix_build_htt {
  cd "$ROOT/.."
  ./configure \
    --with-apr="$ROOT/target/$UNIX_APR_NAME-$UNIX_APR_VER" \
    --with-apr-util="$ROOT/target/$UNIX_APR_UTIL_NAME-$UNIX_APR_UTIL_VER" \
    --with-pcre="$ROOT/target/$UNIX_PCRE_NAME-$UNIX_PCRE_VER" \
    --with-ssl="$ROOT/target/$UNIX_OPENSSL_NAME-$UNIX_OPENSSL_VER" \
    --with-lua="$ROOT/target/$UNIX_LUA_NAME-$UNIX_LUA_VER/src" \
    --enable-lua-module=yes \
    --with-spidermonkey="$ROOT/target/$UNIX_JS_NAME-$UNIX_JS_VER/js/src" \
    --enable-js-module=yes \
    --with-libxml2="$ROOT/target/$UNIX_LIBXML2_NAME-$UNIX_LIBXML2_VER" \
    --enable-html-module=yes \
    enable_use_static=yes
  make clean all
  [ -f src/httest ]
  
  # get and remember version for later
  HTT_VER=`cat Makefile | awk '/^VERSION/ { print $3 }'`
}

#
# unix: (re-)build httest binaries (always)
#
function do_unix_build_htt {
  echo -n "building htt ... "
  unix_build_htt >>"$BUILDLOG" 2>>"$BUILDLOG"
  print_ok
  if [ "$HTT_VER" == "snapshot" ]; then
    # violet bold
    echo "VERSION: $(tput bold)$(tput setaf 5)$HTT_VER$(tput sgr 0)"
  else
    # blue bold
    echo "VERSION: $(tput bold)$(tput setaf 4)$HTT_VER$(tput sgr 0)"
  fi
}

#
# unix: run some basic tests
#
# just to make sure that all binaries have been built
# and httest has been built with all required modules
#
function do_unix_basic_tests_htt {
  echo -n "running basic tests ... "  
  [ `"$ROOT/../src/httest" --version | grep "^httest $HTT_VER$" | wc -l` -eq 1 ]
  [ `"$ROOT/../src/htntlm" --version | grep "^htntlm $HTT_VER$" | wc -l` -eq 1 ]
  [ `"$ROOT/../src/htproxy" --version | grep "^htproxy $HTT_VER$" | wc -l` -eq 1 ]
  [ `"$ROOT/../src/htremote" --version | grep "^htremote $HTT_VER$" | wc -l` -eq 1 ]
  [ `"$ROOT/../tools/hturlext" --version | grep "^hturlext $HTT_VER$" | wc -l` -eq 1 ]
  [ `"$ROOT/../tools/htx2b" --version | grep "htx2b $HTT_VER$" | wc -l` -eq 1 ]
  cd "$ROOT/../test"
  ./run.sh block.htt >>"$BUILDLOG" 2>>"$BUILDLOG"
  ./run.sh block_lua.htt >>"$BUILDLOG" 2>>"$BUILDLOG"
  ./run.sh block_js.htt >>"$BUILDLOG" 2>>"$BUILDLOG"
  ./run.sh html.htt >>"$BUILDLOG" 2>>"$BUILDLOG"
  print_ok
}

#
# unix: "shrink-wrap", i.e. get binaries, create README and zip/tgz it
#
function do_unix_shrinkwrap {
  # determine name to use for file name
  SHORT_NAME="$OS-$ARCH-$BITS"
  if [ "$OS" == "mac" -a "$ARCH" == "x86_64" -a "$BITS" == "64" ]; then
    # intel 64 bit like almost every mac today
    SHORT_NAME="$OS"
  elif [ "$OS" == "linux" ]; then
    # omit architeture if intel
    if [ "$ARCH" == "i686" -a "$BITS" == "32" ]; then
      SHORT_NAME="$OS-$BITS"
    elif [ "$ARCH" == "x86_64" -a "$BITS" == "64" ]; then
      SHORT_NAME="$OS-$BITS"
    fi
  fi
  NAME="httest-$HTT_VER-$SHORT_NAME"
  
  echo "NAME: $NAME"
  echo -n "shrink-wrap ... "
  
  # clean
  DIR="$ROOT/target/$NAME"
  rm -rf "$DIR"
  rm -f "$DIR.tar.gz"
  rm -f "$DIR.zip"
  
  mkdir "$DIR"

  # copy executables
  cp "$ROOT/../src/httest" "$DIR"
  cp "$ROOT/../src/htntlm" "$DIR"
  cp "$ROOT/../src/htproxy" "$DIR"
  cp "$ROOT/../src/htremote" "$DIR"
  cp "$ROOT/../tools/hturlext" "$DIR"
  cp "$ROOT/../tools/htx2b" "$DIR"
  
  # create readme
  cat > "$DIR/README" << EOF
httest binaries

OS:      $OS
VERSION: $HTT_VER
ARCH:    $ARCH
BITS:    $BITS

The following libraries have been statically linked:

- apr       $UNIX_APR_VER
- apr-util  $UNIX_APR_UTIL_VER
- pcre      $UNIX_PCRE_VER
- openssl   $UNIX_OPENSSL_VER
- lua       $UNIX_LUA_VER
- js        $UNIX_JS_VER
- libxml2   $UNIX_LIBXML2_VER

This is "provided as is", no warranty of any kind.

$(date)

EOF

  # everything there?
  [ `ls "$DIR" | wc -w` -eq 7 ]
  
  # tgz
  cd "$DIR/.."
  # ignore "file changed as we read it" on linux
  tar cvzfh "$NAME.tar.gz" "$NAME" >>"$BUILDLOG" 2>>"$BUILDLOG" && true
  [ -f $DIR.tar.gz ]
  
  # zip
  if [ "$OS" == "mac" ]; then
    zip -r "$NAME.zip" "$NAME" >>"$BUILDLOG" 2>>"$BUILDLOG"
    [ -f $DIR.zip ]
  fi
  
  print_ok
}

#
# start of "main"
#

# stop at errors
set -e
trap "echo; print_failed" EXIT

# cd to parent dir of this script
cd "${0%/*}/.."
ROOT=`pwd`

do_determine_os
do_create_target
BUILDLOG="$ROOT/target/build.log"
echo "" >"$BUILDLOG"

if [ "$UNIX" == "1" ]; then
  # unix
  . "$ROOT/source/unix/libs.sh"
  do_get_lib "UNIX" "APR"
  do_get_lib "UNIX" "APR_UTIL"
  do_get_lib "UNIX" "OPENSSL"
  do_get_lib "UNIX" "PCRE"
  do_get_lib "UNIX" "LUA"
  do_get_lib "UNIX" "JS"
  do_get_lib "UNIX" "LIBXML2"
  do_unix_build_apr
  do_unix_build_apr_util
  do_unix_build_pcre
  do_unix_build_openssl
  do_unix_build_lua
  do_unix_build_js
  do_unix_build_libxml2
  do_unix_buildconf
  do_unix_build_htt
  do_unix_basic_tests_htt
  do_unix_shrinkwrap
else
  # windows
  . "$ROOT/source/win/libs.sh"
  do_get_lib "WIN" "APR"
  do_get_lib "WIN" "APR_UTIL"
  do_get_lib "WIN" "OPENSSL"
  do_get_lib "WIN" "PCRE"
  do_get_lib "WIN" "LUA"
  do_get_lib "WIN" "JS"
  do_get_lib "WIN" "LIBXML2"
  # TODO build win sln and build binaries
fi

# success
trap "echo; print_ok" EXIT
