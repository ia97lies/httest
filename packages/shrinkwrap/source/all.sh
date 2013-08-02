#!/bin/bash

#
# main function, called when this script is run
#
function main {
  # stop at errors
  set -e
  trap "echo; print_failed" EXIT

  # cd to parent dir of this script
  cd "${0%/*}/.."
  SW=`pwd`
  TARGET="$SW/target"

  # httest directory
  TOP="$SW/../.."
  
  # create target dir if it does not exist, yet
  if [ ! -d "$TARGET" ]; then
    mkdir "$TARGET"
  fi

  echo
  do_determine_os
  do_determine_version
  do_determine_binaries
  do_determine_libs
  echo
  
  # build log
  BUILDLOG="target/build.log"
  # blue bold
  printf "see \e[34;1m$BUILDLOG\e[0m for build log ...\n"
  echo
  BUILDLOG="$SW/$BUILDLOG"
  echo "" >"$BUILDLOG"

  if [ "$1" == "sln" ]; then
    # just visual studio solution on unix or win
    for LIBVAR in $LIBVARS; do
      do_get_lib "WIN" "$LIBVAR"
    done
    do_buildconf
    do_dummy_configure_htt
    do_create_sln	
  elif [ "$OS" != "win" ]; then
    # all unix targets on unix
    for LIBVAR in $LIBVARS; do
      do_get_lib "UNIX" "$LIBVAR"
    done
    for LIBVAR in $LIBVARS; do
      do_unix_build_$LIBVAR
    done
    do_buildconf
    do_unix_build_htt
    do_basic_tests_htt
    do_make_check
    do_shrinkwrap
  else
    # all win targets on win
    for LIBVAR in $LIBVARS; do
      do_get_lib "WIN" "$LIBVAR"
    done
    do_buildconf
    do_dummy_configure_htt
    do_create_sln
    do_win_build_htt
    do_basic_tests_htt
    do_make_check
    do_shrinkwrap
  fi

  # success
  trap "echo; print_ok" EXIT
}

#
# print "OK"
#
function print_ok {
  # bold green
  printf "\e[32;1mOK\e[0m\n"
}

#
# print "OK (up to date)"
#
function print_ok_up_to_date {
  # bold blue
  printf "\e[34;1mOK\e[0m \e[37m(up to date)\e[0m\n"
}

#
# print "FAILED"
#
function print_failed {
  # bold red
  printf "\e[31;1mFAILED\e[0m\n"
}

#
# print "WARN (some checks failed)"
#
function print_warn_some_checks_failed {
  # bold yellow
  printf "\e[33;1mWARN\e[0m \e[37m(some checks failed)\e[0m\n"
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
  elif [ `uname -s` == "SunOS" ]; then
    OS="solaris"
  fi
  echo "OS:      $OS"
  if [ "$OS" == "unknown" ]; then
    # yellow bold
    printf "\e[33;1mWARNING:\e[0m unknown os, treating like linux\n"
  fi
  
  ARCH=`uname -m`
  echo "ARCH:    $ARCH"
  BITS=`getconf LONG_BIT`
  echo "BITS:    $BITS"  
}

#
# determine httest version
#
function do_determine_version {
  HTT_VER=`cat "$TOP/configure.in" | awk ' BEGIN { FS="," } /AC_INIT.httest/ { print $2 }'`
  HTT_VER=`echo $HTT_VER`
  NAME=`echo $HTBIN | awk ' BEGIN { FS="/" } { print $2 }'`
  if [ "$HTT_VER" == "snapshot" ]; then
    # violet bold
    printf "VERSION: \e[35;1m$HTT_VER\e[0m\n"
  else
    # blue bold
    printf "VERSION: \e[34;1m$HTT_VER\e[0m\n"
  fi
}

#
# determine name and dir of all htt binaries
#
function do_determine_binaries {
  echo -n "BINS:    "
  HTBIN_PATHS="src tools"
  HTBINS=""
  for HTBIN_PATH in $HTBIN_PATHS; do
    BINS=`cat "$TOP/$HTBIN_PATH/Makefile.am" | awk \
      '/bin_PROGRAMS =/ {
        for (i=3; i<=NF; i++) {
          printf("%s ", $(i));
        }
      }
      # httest 2.1
      /bin_PROGRAMS=/ {
        printf("%s ", substr($1, 14));
        for (i=2; i<=NF; i++) {
          printf("%s ", $(i));
        }
      }'`
    for BIN in $BINS; do
      echo -n "$BIN "
      HTBINS="$HTBINS $HTBIN_PATH/$BIN"
    done
  done
  echo
}

#
# determine libraries
#
function do_determine_libs {
  echo -n "LIBS:    "
  LIBVARS="APR APU SSL PCRE"
  if [ `cat "$TOP/configure.in" | grep with-lua | wc -l` -eq 1 ]; then
    LIBVARS="$LIBVARS LUA"
  fi
  if [ `cat "$TOP/configure.in" | grep with-spidermonkey | wc -l` -eq 1 ]; then
    LIBVARS="$LIBVARS JS"
  fi
  if [ `cat "$TOP/configure.in" | grep with-libxml2 | wc -l` -eq 1 ]; then
    LIBVARS="$LIBVARS XML2"
  fi
  . "$SW/source/unix/libs.sh"
  . "$SW/source/win/libs.sh"
  for LIBVAR in $LIBVARS; do
    eval NAME="\$UNIX_${LIBVAR}_NAME"
    echo -n "$NAME "
  done
  echo
}

#
# download und unpack lib according to LIB_* variables
#
function get_lib {
  URL="$LIB_PROT://$LIB_HOST$LIB_PATH/$LIB_FILE"
  echo -n "getting $URL ... "
  if [ "$OS" == "mac" ]; then
    ftp "$URL"
  elif [ "$LIB_PROT" == "http" ]; then
    wget -q "$URL"
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
  echo "ok"
  
  echo -n "unpacking $LIB_FILE ... "
  if [ "$LIB_OS" == "WIN" ]; then
    unzip -q "$LIB_FILE" -d tmp
	mv tmp/* "$LIB_DIRNAME"
	rmdir tmp
  else
    gzip -d -c "$LIB_FILE" > "$LIB_DIRNAME.tar"
    tar xf "$LIB_DIRNAME.tar"
    rm "$LIB_DIRNAME.tar"
  fi
  rm "$LIB_FILE"
  echo "ok"
  
  echo -n "checking that directory $LIB_DIRNAME exists ... "
  [ -d "$LIB_DIRNAME" ]
  echo "ok"
}

#
# download and unpack lib if not already there
#
function do_get_lib {
  LIB_OS="$1"
  LIB_VAR="$2"
  PRE="${LIB_OS}_${LIB_VAR}_"
  eval LIB_NAME="\$${PRE}NAME"
  eval LIB_VER="\$${PRE}VER"
  eval LIB_PROT="\$${PRE}PROT"
  eval LIB_HOST="\$${PRE}HOST"
  eval LIB_PATH="\$${PRE}PATH"
  eval LIB_FILE="\$${PRE}FILE"
  LIB_DIRNAME="$LIB_NAME-$LIB_VER"
  INFo=""
  if [ "$LIB_OS" == "WIN" ]; then
    LIB_DIRNAME="win-$LIB_DIRNAME"
    INFO=" win"
  fi

  cd "$TARGET"
  echo -n "($(date +%H:%M)) getting$INFO lib $LIB_NAME $LIB_VER ... "
  if [ -d "$LIB_DIRNAME" ]; then
    print_ok_up_to_date
  else
    get_lib >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build apr
#
function unix_build_APR {
  cd "$TARGET/$UNIX_APR_NAME-$UNIX_APR_VER"
  ./configure
  make
  
  echo -n "checking that apr lib has been built ... "
  [ -f .libs/libapr-1.a ]
  echo "ok"
}

#
# unix: build apr if no lib, yet
#
function do_unix_build_APR {
  echo -n "($(date +%H:%M)) building apr ... "  
  if [ -f "$TARGET/$UNIX_APR_NAME-$UNIX_APR_VER/.libs/libapr-1.a" ]; then
    print_ok_up_to_date
  else
    unix_build_APR >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build apr-util
#
function unix_build_APU {
  cd "$TARGET/$UNIX_APU_NAME-$UNIX_APU_VER"
  ./configure --with-apr="$TARGET/$UNIX_APR_NAME-$UNIX_APR_VER"
  make

  echo -n "checking that apr-util lib has been built ... "
  [ -f .libs/libaprutil-1.a ]
  echo "ok"
}

#
# unix: build apr-util if no lib, yet
#
function do_unix_build_APU {
  echo -n "($(date +%H:%M)) building apr-util ... "  
  if [ -f "$TARGET/$UNIX_APU_NAME-$UNIX_APU_VER/.libs/libaprutil-1.a" ]; then
    print_ok_up_to_date
  else
    unix_build_APU >>"$BUILDLOG" 2>>"$BUILDLOG"
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
function unix_build_PCRE {
  cd "$TARGET/$UNIX_PCRE_NAME-$UNIX_PCRE_VER"
  ./configure
  make
  create_custom_config $UNIX_PCRE_NAME $UNIX_PCRE_VER \
    "-I\${DIR}" "-L\${DIR}/.libs -lpcre"
	
  echo -n "checking that pcre lib has been built ... "
  [ -f .libs/libpcre.a ]
  echo "ok"
}

#
# unix: build pcre if no lib, yet
#
function do_unix_build_PCRE {
  echo -n "($(date +%H:%M)) building pcre ... "  
  if [ -f "$TARGET/$UNIX_PCRE_NAME-$UNIX_PCRE_VER/.libs/libpcre.a" ]; then
    print_ok_up_to_date
  else
    unix_build_PCRE >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build openssl
#
function unix_build_SSL {
  cd "$TARGET/$UNIX_SSL_NAME-$UNIX_SSL_VER"
  if [ "$OS" = "mac" ]; then
    ./Configure darwin64-x86_64-cc
  else
    ./config
  fi
  make

  echo -n "checking that openssl lib has been built ... "
  [ -f libssl.a ]
  echo "ok"
}

#
# unix: build openssl if no lib, yet
#
function do_unix_build_SSL {
  echo -n "($(date +%H:%M)) building openssl ... "  
  if [ -f "$TARGET/$UNIX_SSL_NAME-$UNIX_SSL_VER/libssl.a" ]; then
    print_ok_up_to_date
  else
    unix_build_SSL >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build lua if no lib, yet
#
function unix_build_LUA {
  cd "$TARGET/$UNIX_LUA_NAME-$UNIX_LUA_VER"
  if [ "$OS" = "mac" ]; then
    make macosx
  elif [ "$OS" = "solaris" ]; then
    mv src/Makefile src/Makefile.bak
    cat src/Makefile.bak | sed 's/CC= gcc/CC= cc/' | sed 's/CFLAGS= -O2 -Wall/CFLAGS= -O2/' >src/Makefile
    make solaris
  else
    make linux
  fi
  make test
  
  echo -n "checking that lua lib has been built ... "
  [ -f src/liblua.a ]
  echo "ok"
}

#
# unix: build lua if no lib, yet
#
function do_unix_build_LUA {
  echo -n "($(date +%H:%M)) building lua ... "  
  if [ -f "$TARGET/$UNIX_LUA_NAME-$UNIX_LUA_VER/src/liblua.a" ]; then
    print_ok_up_to_date
  else
    unix_build_LUA >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build js
#
function unix_build_JS {
  cd "$TARGET/$UNIX_JS_NAME-$UNIX_JS_VER"
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
  if [ "$OS" == "solaris" ]; then
    # workaround for sun cc limit on enum values for 32 bit target
    cp jsclone.cpp jsclone.cpp.bak
    cat jsclone.cpp.bak | awk '
      BEGIN { skip=0 }
      /enum StructuredDataType/ { skip=1 }
      { if (skip==0) {
          print $0
        } else if (skip==1 && $0 == "};") {
          skip=0
          print "#define SCTAG_FLOAT_MAX           0xFFF00000"
          print "#define SCTAG_NULL                0xFFFF0000"
          print "#define SCTAG_UNDEFINED           0xFFFF0001"
          print "#define SCTAG_BOOLEAN             0xFFFF0002"
          print "#define SCTAG_INDEX               0xFFFF0003"
          print "#define SCTAG_STRING              0xFFFF0004"
          print "#define SCTAG_DATE_OBJECT         0xFFFF0005"
          print "#define SCTAG_REGEXP_OBJECT       0xFFFF0006"
          print "#define SCTAG_ARRAY_OBJECT        0xFFFF0007"
          print "#define SCTAG_OBJECT_OBJECT       0xFFFF0008"
          print "#define SCTAG_ARRAY_BUFFER_OBJECT 0xFFFF0009"
          print "#define SCTAG_BOOLEAN_OBJECT      0xFFFF000A"
          print "#define SCTAG_STRING_OBJECT       0xFFFF000B"
          print "#define SCTAG_NUMBER_OBJECT       0xFFFF000C"
          print "#define SCTAG_TYPED_ARRAY_MIN     0xFFFF0100"
          print "#define SCTAG_TYPED_ARRAY_MAX     (SCTAG_TYPED_ARRAY_MIN + TypedArray::TYPE_MAX - 1)"
          print "#define SCTAG_END_OF_BUILTIN_TYPES (SCTAG_TYPED_ARRAY_MAX + 1)"
        }
      }' >jsclone.cpp
    # use gmake
    gmake
  else
    make
  fi

  LIBS="-L\${DIR} -ljs_static"
  if [ "$OS" == "solaris" ]; then
    LIBS="$LIBS -L/usr/sfw/lib -lstdc++ -lCrun"
  fi 
  create_custom_config $UNIX_JS_NAME $UNIX_JS_VER "-I\${DIR}" "$LIBS"

  echo -n "checking that js lib has been built ... "
  [ -f libjs_static.a ]
  echo "ok"
}

#
# unix: build js if no lib, yet
#
function do_unix_build_JS {
  echo -n "($(date +%H:%M)) building js ... "  
  if [ -f "$TARGET/$UNIX_JS_NAME-$UNIX_JS_VER/js/src/libjs_static.a" ]; then
    print_ok_up_to_date
  else
    unix_build_JS >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build libxml2
#
function unix_build_XML2 {
  cd "$TARGET/$UNIX_XML2_NAME-$UNIX_XML2_VER"
  ./configure
  make
  create_custom_config "xml2" $UNIX_XML2_VER \
    "-I\${DIR}/include" "-L\${DIR} -lxml2"
	
  echo -n "checking that libxml2 lib has been built ... "
  [ -f .libs/libxml2.a ]
  echo "ok"
}

#
# unix: build libmlx2 if no lib, yet
#
function do_unix_build_XML2 {
  echo -n "($(date +%H:%M)) building libxml2 ... "  
  if [ -f "$TARGET/$UNIX_XML2_NAME-$UNIX_XML2_VER/.libs/libxml2.a" ]; then
    print_ok_up_to_date
  else
    unix_build_XML2 >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix/win: run buildconf.sh
#
function buildconf {
  cd "$TOP"
  rm -f configure
  ./buildconf.sh

  echo -n "checking that configure file has been built ... "
  [ -f configure ]
  echo "ok"
}

#
# unix/win: run buildconf.sh if no configure script, yet
#
function do_buildconf {
  echo -n "($(date +%H:%M)) building htt configuration ... "  
  if [ -f "$TOP/configure" ]; then
    print_ok_up_to_date
  else
    buildconf >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: (re-)build httest binaries with all libraries listed below
# statically linked (note "make clean all" which makes sure binaries
# are always built that way here...)
#
function unix_build_htt {
  cd "$TOP"

  WITH=""
  for LIBVAR in $LIBVARS; do
    case $LIBVAR in
      APR)
        WITH="$WITH --with-apr=$TARGET/$UNIX_APR_NAME-$UNIX_APR_VER"
        ;;
      APU)
        WITH="$WITH --with-apr-util=$TARGET/$UNIX_APU_NAME-$UNIX_APU_VER"
        ;;
      SSL)
        WITH="$WITH --with-ssl=$TARGET/$UNIX_SSL_NAME-$UNIX_SSL_VER"
        ;;
      PCRE)
        WITH="$WITH --with-pcre=$TARGET/$UNIX_PCRE_NAME-$UNIX_PCRE_VER"
        ;;
      LUA)
        WITH="$WITH --with-lua=$TARGET/$UNIX_LUA_NAME-$UNIX_LUA_VER/src"
        WITH="$WITH --enable-lua-module=yes"
        ;;
      JS)
        WITH="$WITH --with-spidermonkey=$TARGET/$UNIX_JS_NAME-$UNIX_JS_VER/js/src"
        WITH="$WITH --enable-js-module=yes"
        ;;
      XML2)
        WITH="$WITH --with-libxml2=$TARGET/$UNIX_XML2_NAME-$UNIX_XML2_VER"
        WITH="$WITH --enable-html-module=yes"
        ;;
    esac
  done
 
  echo "$WITH" 
  ./configure $WITH enable_use_static=yes
  make clean all

  echo -n "checking that httest has been built ... "
  [ -f src/httest ]
  echo "ok"
  
  # number of binaries for later
  HTT_NBIN=`echo $HTBINS | wc -w`
}

#
# unix: (re-)build httest binaries (always)
#
function do_unix_build_htt {
  echo -n "($(date +%H:%M)) building htt ... "
  unix_build_htt >>"$BUILDLOG" 2>>"$BUILDLOG"
  print_ok
}

#
# unix/win: configure htt in order to get e.g. modules.c
#
function dummy_configure_htt {
  # create dummy config scripts
  DUMMYDIR="$TARGET/dummy-configs"
  if [ ! -d  "$DUMMYDIR" ]; then
    mkdir "$DUMMYDIR"
  fi
  PREFIXES="apr-1 apu-1 openssl pcre lua js xml2"
  for PREFIX in $PREFIXES; do
    FILE="$DUMMYDIR/$PREFIX-config"
    echo "echo dummy" >> "$FILE"
    chmod +x "$FILE"
  done
  
  cd "$TOP"
  ./configure \
    --with-apr="$DUMMYDIR" \
    --with-apr-util="$DUMMYDIR" \
    --with-pcre="$DUMMYDIR" \
    --with-ssl="$DUMMYDIR" \
    --with-lua="$DUMMYDIR" \
    --enable-lua-module=yes \
    --with-spidermonkey="$DUMMYDIR" \
    --enable-js-module=yes \
    --with-libxml2="$DUMMYDIR" \
    --enable-html-module=yes
  
  echo -n "checking that httest has been configured ... "
  [ -f "src/modules.c" ]
  echo "ok"
}

#
# unix/win: dummy configure htt (always)
#
function do_dummy_configure_htt {
  echo -n "($(date +%H:%M)) dummy configuring htt ... "
  if [ "$OS" == "win" ]; then
    # configure is very slow on cygwin, so only do once automatically
    if [ -f "$TARGET/win.configured" ]; then
      print_ok_up_to_date
    else
      dummy_configure_htt >>"$BUILDLOG" 2>>"$BUILDLOG"
	  touch "$TARGET/win.configured"
      print_ok
    fi
  else
    dummy_configure_htt >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix/win: create visual studio solution
#
function create_sln {
  SLN="httest-$HTT_VER-win-sln"
  SLN_NIGHTLY="httest-nightly-win-sln"
  WINSLN="$TARGET/$SLN"
  rm -rf "$WINSLN"
  mkdir "$WINSLN"
  
  # build settings, note that backslashes are escaped twice for sed further below
  RELEASE_DEFINES="HAVE_CONFIG_H;WIN32;NDEBUG;_CONSOLE;_WINDOWS;_CRT_SECURE_NO_DEPRECATE;_MBCS"
  RELEASE_INCLUDES="..\\\\src"
  RELEASE_LIBDIRS=""
  RELEASE_LIBS="Ws2_32.lib"
  RELEASE_POSTBUILD=""
  
  # copy libs and add to build settings
  mkdir "$WINSLN/include"
  mkdir "$WINSLN/lib"
  mkdir "$WINSLN/dll"
  echo "httest $HTT_VER" >"$WINSLN/versions.txt"
  for LIBVAR in $LIBVARS; do
    eval NAME="\$WIN_${LIBVAR}_NAME"
    eval VER="\$WIN_${LIBVAR}_VER"
	echo "$NAME $VER" >>"$WINSLN/versions.txt"
	mkdir "$WINSLN/include/$NAME"
	cp -r "$TARGET/win-$NAME-$VER/include"/* "$WINSLN/include/$NAME"
	mkdir "$WINSLN/lib/$NAME"
	cp -r "$TARGET/win-$NAME-$VER/lib"/* "$WINSLN/lib/$NAME"
	mkdir "$WINSLN/dll/$NAME"
	cp -r "$TARGET/win-$NAME-$VER/dll"/* "$WINSLN/dll/$NAME"
	# make sure DLLs can be loaded on win
    chmod 755 "$WINSLN/dll/$NAME"/*.dll
    RELEASE_INCLUDES="$RELEASE_INCLUDES;..\\\\include\\\\$NAME"
    RELEASE_LIBDIRS="$RELEASE_LIBDIRS;..\\\\lib\\\\$NAME"
	cd "$WINSLN/lib/$NAME"
	for LIB in `ls *.lib`; do
      RELEASE_LIBS="$RELEASE_LIBS;$LIB"
	done
	# note how spaces are escaped
	RELEASE_POSTBUILD="${RELEASE_POSTBUILD}copy##SP##\"\$(SolutionDir)dll\\\\$NAME\\\\*.dll\"##SP##\"\$(OutDir)\"##SP##\&amp;##SP##"
  done
  
  # debug build settings
  DEBUG_DEFINES="$RELEASE_DEFINES"
  DEBUG_INCLUDES="$RELEASE_INCLUDES"
  DEBUG_LIBDIRS="$RELEASE_LIBDIRS"
  DEBUG_LIBS="$RELEASE_LIBS"
  DEBUG_POSTBUILD="$RELEASE_POSTBUILD"
  
  WINSRC="$SW/source/win"
  
  # create visual studio solution
  HTTSLN="$WINSLN/httest.sln"
  GUID_PRE="8BC9CEB8-8B4A-11D0-8D11-00A0C91BC94"
  SLN_GUID="${GUID_PRE}0"
  cat >"$HTTSLN" <<EOF

Microsoft Visual Studio Solution File, Format Version 11.00
# Visual C++ Express 2010
EOF
  N=0
  PROJECTS=""
  for HTBIN in $HTBINS; do
    NAME=`echo $HTBIN | awk ' BEGIN { FS="/" } { print $2 }'`
	N=`expr $N + 1`
	GUID="$GUID_PRE$N"
	PROJECTS="$PROJECTS $NAME:$GUID"
    echo "Project(\"{$SLN_GUID}\") = \"$NAME\", \"$NAME\\$NAME.vcxproj\", \"{$GUID}\"" >>"$HTTSLN"
	echo "EndProject" >>"$HTTSLN"
  done
  cat >>"$HTTSLN" <<EOF
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|Win32 = Debug|Win32
		Release|Win32 = Release|Win32
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
EOF
  N=0
  for HTBIN in $HTBINS; do
    BINNAME=`echo $HTBIN | awk ' BEGIN { FS="/" } { print $2 }'`
	N=`expr $N + 1`
	PROJ_GUID="$GUID_PRE$N"
    echo "		{$PROJ_GUID}.Debug|Win32.ActiveCfg = Debug|Win32" >>"$HTTSLN"
    echo "		{$PROJ_GUID}.Debug|Win32.Build.0 = Debug|Win32" >>"$HTTSLN"
    echo "		{$PROJ_GUID}.Release|Win32.ActiveCfg = Release|Win32" >>"$HTTSLN"
    echo "		{$PROJ_GUID}.Release|Win32.Build.0 = Release|Win32" >>"$HTTSLN"
  done
  cat >>"$HTTSLN" <<EOF
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
EndGlobal
EOF
  
  # get header file names
  cd "$TOP/src"
  H_FILES_SRC=`ls *.h | awk '
    { printf("%s ", $0); }
  '`
  cd "$TOP/include"
  for DIR in */; do
    DIR=${DIR%*/}
	INCLUDE_DIRS="$INCLUDE_DIRS $DIR"
	cd "$TOP/include/$DIR"
	HEADERS=`ls *.h | awk -v dir="$DIR" '
      { printf("%s\\\\\\\\%s ", dir, $0); }
	'`
	H_FILES_INCLUDE="$HFILES_INCLUDE $HEADERS"
  done
  echo "INCLUDE_DIRS: '$INCLUDE_DIRS'"
  H_FILES="$H_FILES_SRC $H_FILES_INCLUDE"
  echo "H_FILES: '$H_FILES'"
  
  # create ht* projects
  for PROJECT in $PROJECTS; do
    NAME=`echo $PROJECT | awk ' BEGIN { FS=":" } { print $1 }'`
    GUID=`echo $PROJECT | awk ' BEGIN { FS=":" } { print $2 }'`
    echo "$NAME : $GUID"

    # create project file and replace variables with sed
    mkdir "$WINSLN/$NAME"
	WINPRJ="$WINSLN/$NAME/$NAME.vcxproj"
    cp "$WINSRC/httest.vcxproj.in" "$WINPRJ"
    sed -i.bak 's/##PROJECT_NAME##/'$NAME'/g' $WINPRJ
    sed -i.bak 's/##PROJECT_GUID##/'$GUID'/g' $WINPRJ
    sed -i.bak 's/##RELEASE_DEFINES##/'$RELEASE_DEFINES'/g' $WINPRJ
    sed -i.bak 's/##RELEASE_INCLUDES##/'$RELEASE_INCLUDES'/g' $WINPRJ
    sed -i.bak 's/##RELEASE_LIBDIRS##/'$RELEASE_LIBDIRS'/g' $WINPRJ
    sed -i.bak 's/##RELEASE_LIBS##/'$RELEASE_LIBS'/g' $WINPRJ
    sed -i.bak 's/##RELEASE_POSTBUILD##/'$RELEASE_POSTBUILD'/g' $WINPRJ
    sed -i.bak 's/##DEBUG_DEFINES##/'$DEBUG_DEFINES'/g' $WINPRJ
    sed -i.bak 's/##DEBUG_INCLUDES##/'$DEBUG_INCLUDES'/g' $WINPRJ
    sed -i.bak 's/##DEBUG_LIBDIRS##/'$DEBUG_LIBDIRS'/g' $WINPRJ
    sed -i.bak 's/##DEBUG_LIBS##/'$DEBUG_LIBS'/g' $WINPRJ
    sed -i.bak 's/##DEBUG_POSTBUILD##/'$DEBUG_POSTBUILD'/g' $WINPRJ
    sed -i.bak 's/##SP##/ /g' $WINPRJ
    
    # determine c files
    C_FILES=`cat "$TOP/src/Makefile.am" "$TOP/tools/Makefile.am" | awk \
      -v name="${NAME}_SOURCES" '
      {
        if (match($0,name)) {
          process=1;
          next;
        } else if (process) {
          n = NF -1 ;
          if ($NF != "\134") {
            n = NF;
            process=0;
          }
          for (i=1; i<=n; i++) {
            printf ("%s ", $(i));
          }
        }
      }'`
    
    # insert references to headers and c files
    mv "$WINPRJ" "$WINPRJ.bak"
    cat "$WINPRJ.bak" | awk \
      -v name="$NAME" -v hfiles="$H_FILES" -v cfiles="$C_FILES" '
      /##H_FILES##/ {
        split(hfiles, arr, " ");
        for (i in arr) {
          printf("    <ClInclude Include=\"..\\src\\%s\" />\r\n", arr[i]);
        }
        printf("    <ClInclude Include=\"..\\src\\config.h\" />\r\n");
        next;
      }
      /##C_FILES##/ {
        split(cfiles, arr, " ");
        for (i in arr) {
          printf("    <ClCompile Include=\"..\\src\\%s\" />\r\n", arr[i]);
        }
        printf("    <ClCompile Include=\"..\\src\\%s.c\" />\r\n", name);
        next;
      }
      { print $0 }
    ' > "$WINPRJ"
    rm "$WINPRJ.bak"
  done
  echo
  
  # create sources
  mkdir "$WINSLN/src"
  cp "$TOP/src/"*.c "$WINSLN/src"
  cp "$TOP/src/"*.h "$WINSLN/src"
  #cp "$TOP/tools/"*.c "$WINSLN/src"
  for DIR in $INCLUDE_DIRS; do
    mkdir "$WINSLN/src/$DIR"
    cp "$TOP/include/$DIR/"*.h "$WINSLN/src/$DIR"
  done
  echo -e "#define PACKAGE_VERSION \"$HTT_VER\"\n#define VERSION \"$HTT_VER\""\
    >"$WINSLN/src/config.h"
  
  # create version resource
  HTT_VER_NUM=`echo $HTT_VER | awk 'BEGIN { FS="-" } { print $1 }'| awk '
    BEGIN { v="0.0.0" } /^[0-9]+\.[0-9]+\.[0-9]+$/ { v=$1 } END { print v }'`
  echo "HTT_VER_NUM='$HTT_VER_NUM'"
  HTT_VER_COMMAS=`echo $HTT_VER_NUM | sed 's/\./\,/g'`
  echo "HTT_VER_COMMAS='$HTT_VER_COMMAS'"
  WINRC="$WINSLN/src/version.rc"
  echo "1 VERSIONINFO" >"$WINRC"
  echo "FILEVERSION $HTT_VER_COMMAS" >>"$WINRC"
  echo "BEGIN" >>"$WINRC"
  echo "END" >>"$WINRC"
  
  # zip solution
  cd "$TARGET"
  zip -r "$SLN.zip" "$SLN"
  echo -n "checking that visual studio solution has been created ... "  
  [ -f "$SLN.zip" ]
  if [ ! -f "$SLN_NIGHTLY.zip" ]; then
    cp "$SLN.zip" "$SLN_NIGHTLY.zip"
  fi
  echo "ok"
}

#
# unix/win: create visual studio solution (always)
#
function do_create_sln {
  echo -n "($(date +%H:%M)) creating visual studio solution ... "
  create_sln >>"$BUILDLOG" 2>>"$BUILDLOG"
  print_ok
}

#
# win: (re-)build httest binaries
#
function win_build_htt {
  SLN="httest-$HTT_VER-win-sln"
  WINSLN="$TARGET/$SLN"
  rm -rf "$WINSLN/Release"
  
  # find visual c++ 2010
  MSVSVER="Microsoft Visual Studio 10.0"
  PAT="$MSVSVER/VC/bin/vcvars32.bat"
  # search drive c first, don't want to scan all drives unless necessary
  VCVARS=`find /cygdrive/c | grep "$PAT" & true` 
  if [ "$VCVARS" == "" ];  then
    VCVARS=`find /cygdrive | grep "$PAT" & true`
  fi
  if [ "$VCVARS" == "" ];  then
    echo "visual c++ 2010 not found"
  fi
  # convert to windows path with backslashes
  VCVARS=`cygpath -aw "$VCVARS"`
  echo "using '$VCVARS'"
  
  cd "$WINSLN"
  cat > "build.bat" << EOF
  call "$VCVARS"
  msbuild httest.sln /p:Configuration=Release
  if %errorlevel% neq 0 (
    exit 1
  )
EOF
  cmd /c build.bat
  
  # count DLLs for later checks
  HTT_NDLL=`ls -l "$WINSLN/Release"/*.dll | wc -l`

  for HTBIN_PATH in $HTBIN_PATHS; do
    rm -f "$TOP/$HTBIN_PATH"/*.exe "$TOP/$HTBIN_PATH/"*.dll
	cp "$WINSLN/Release/"*.dll "$TOP/$HTBIN_PATH"
  done
  for HTBIN in $HTBINS; do
    BINDIR=`echo $HTBIN | awk ' BEGIN { FS="/" } { print $1 }'`
    BINNAME=`echo $HTBIN | awk ' BEGIN { FS="/" } { print $2 }'`
    cp "$WINSLN/Release/$BINNAME.exe" "$TOP/$BINDIR"
  done

  echo -n "checking that httest has been built ... "
  [ -f "$WINSLN/Release/httest.exe" ]
  echo "ok"
}

#
# win: build httest binaries (always)
#
function do_win_build_htt {
  echo -n "($(date +%H:%M)) building htt ... "
  win_build_htt >>"$BUILDLOG" 2>>"$BUILDLOG"
  print_ok
}

#
# unix/win: run some basic tests
#
function basic_tests_htt {    
  for HTBIN in $HTBINS; do
    NAME=`echo $HTBIN | awk ' BEGIN { FS="/" } { print $2 }'`
    CALL="$TOP/$HTBIN"
    "$CALL" --version | grep "$NAME"
    OUT=`"$CALL" --version | grep "$NAME.* $HTT_VER"`
    [ `echo "$OUT" | grep "$NAME.* $HTT_VER" | wc -l` -eq 1 ]
  done

  cd "$TOP/test"
  TESTS="block.htt"
  for LIBVAR in $LIBVARS; do
    case $LIBVAR in
      LUA)
        TESTS="$TESTS block_lua.htt"
        ;;
      JS)
        TESTS="$TESTS block_js.htt"
        ;;
      XML2)
        TESTS="$TESTS html.htt"
        ;;
    esac
  done

  for TEST in $TESTS; do
    echo -n "running $TEST ... "
    ./run.sh $TEST >"$TARGET/$TEST.out" 2>&1
    echo "ok"
  done
}

#
# unix/win: run some basic tests (always)
#
function do_basic_tests_htt {
  echo -n "($(date +%H:%M)) running basic tests ... "
  basic_tests_htt >>"$BUILDLOG" 2>>"$BUILDLOG"
  print_ok
}

#
# unix/win: run "make check"
#
function make_check {    
  cd "$TOP/test"
  if [ "$OS" != "win" ]; then
    set +e
    make check > "$TARGET/report.log"
    MAKE_CHECK_STATUS=$?
    set -e
  else
    echo "No report for win (yet)" > "$TARGET/report.log"
    MAKE_CHECK_STATUS=0
  fi
  echo MAKE_CHECK_STATUS > "$TARGET/report.status"
  
  # create html report
  if [ $MAKE_CHECK_STATUS -eq 0 ]; then
    RESULT="<span class=\"ok\">OK</span>"
  else
    RESULT="<span class=\"warn\">FAILURES</span>"
  fi
  cat "$TARGET/report.log" | awk '
    /^Please report/ { next }
    { 
      gsub(/</, "&lt;");
      gsub(/.\[1;32mOK.\[0m/, "<span class=\"ok\">OK</span>");
      gsub(/.\[1;33mSKIP.\[0m/, "<span class=\"warn\">SKIP</span>");
      gsub(/.\[1;31mFAILED.\[0m/, "<span class=\"error\">FAILED</span>");
      print
    }' >"$TARGET/report.body"
  REPORT="$TARGET/report.html"
  cat >"$REPORT" <<EOF
<html>
  <head>
    <title>httest report ($OS $BITS)</title>
    <style type="text/css">
      span.ok { font-weight:bold; color:green }
      span.warn { font-weight:bold; color:orange }
      span.error { font-weight:bold; color.red }
    </style>
  </head>

  <body>
    <h2>httest report ($OS $BITS)</h2>
    
    <p>For the build system on which these binaries were built.</p>
    <p>Failed or skipped tests do not necessarily indicate a significant issue,
    but see comments for @:SKIP's in the respective test scripts,
    and not all features are supported on all platforms (most are).</p>
    <p>httest is Open Source - feel free to chase bugs and report proposed fixes :)</p>
    <p>This is "provided as is", no warranty of any kind.</p>
    
    <h3>$RESULT</h3>
    <pre>
EOF
  cat "$TARGET/report.body" >>$REPORT
  cat >>"$REPORT" <<EOF
    </pre>
  </body>
EOF
}

#
# unix/win: run "make check" (if no report exists)
#
function do_make_check {
  echo -n "($(date +%H:%M)) running make check ... "
  if [ -f "$TARGET/report.html" ]; then
    print_ok_up_to_date
  else
    make_check >>"$BUILDLOG" 2>>"$BUILDLOG"
    MAKE_CHECK_STATUS=22
    if [ $MAKE_CHECK_STATUS -eq 0 ]; then
      print_warn_some_checks_failed
    else
      print_ok
    fi
  fi
}

#
# unix/win: "shrink-wrap"
#
function shrinkwrap {
  NAME=$1
  NAME_NIGHLY=$2
  
  # clean
  DIR="$TARGET/$NAME"
  rm -rf "$DIR"
  rm -f "$DIR.tar.gz"
  rm -f "$DIR.zip"
  
  mkdir "$DIR"

  # copy executables
  if [ "$OS" == "win" ]; then
    cp "$WINSLN/Release/"*.exe "$DIR"
    cp "$WINSLN/Release/"*.dll "$DIR"
  else
    for HTBIN in $HTBINS; do
      cp "$TOP/$HTBIN" "$DIR"
    done
  fi
  
  # create readme
  echo "creating readme ..."
  if [ "$OS" == "win" ]; then
    README="$DIR/readme.txt"
    LIBINF="are included"
    SYS="WIN"
  else
    README="$DIR/README"
    LIBINF="have been statically linked"
    SYS="UNIX"
  fi
  cat >"$README" <<EOF
httest binaries

OS:       $OS
VERSION:  $HTT_VER
ARCH:     $ARCH
BITS:     $BITS

The following libraries $LIBINF:

EOF
  for LIBVAR in $LIBVARS; do
    eval LIBNAME="\$${SYS}_${LIBVAR}_NAME"
	eval LIBVER="\$${SYS}_${LIBVAR}_VER"
	printf "%-11s %s\n" "- $LIBNAME" "$LIBVER" >>"$README"
  done
  if [ "$OS" == "win" ]; then
    echo >>"$README"
	echo "Visual C++ 2005 and 2008 runtimes are required, e.g.:" >>"$README"
    echo "http://www.microsoft.com/download/en/details.aspx?id=5638" >>"$README"
    echo "http://www.microsoft.com/download/en/details.aspx?id=5582" >>"$README"
  fi
  cat >>"$README" <<EOF

This is "provided as is", no warranty of any kind.

$(date -u "+%Y-%m-%d %H:%M:%S %Z")

--
EOF

  # append some more info
  CMDS="${CMDS}uname -srmp\n"
  if [ "$OS" == "solaris" ]; then
    CMDS="${CMDS}uname -i\n"
  elif [ "$OS" != "mac" ]; then
    CMDS="${CMDS}uname -io\n"
  fi
  CMDS="${CMDS}getconf LONG_BIT\n"
  if [ "$OS" == "mac" ]; then
    CMDS="${CMDS}sw_vers\n"
  elif [ "$OS" == "win" ]; then
    CMDS="${CMDS}cmd /c ver\n"
  elif [ "$OS" == "linux" ]; then
    CMDS="${CMDS}cat /etc/*version\n"
    CMDS="${CMDS}lsb_release -drc\n"
    CMDS="${CMDS}dpkg --list | grep linux-image\n"
    CMDS="${CMDS}rpm -q kernel\n"
    CMDS="${CMDS}cat /proc/version\n"
  elif [ "$OS" == "solaris" ]; then
    CMDS="${CMDS}cat /etc/release\n"
    CMDS="${CMDS}showrev | grep Kernel\n"
  fi
  if [ "$OS" == "win" ]; then
    CMDS="${CMDS}echo $MSVSVER\n"
  elif [ "$OS" == "solaris" ]; then
    CMDS="${CMDS}cc -V\n"
  else
    CMDS="${CMDS}gcc --version\n"
  fi
  if [ "$OS" == "mac" ]; then
    LDD="otool -L"
  else
    LDD="ldd"
  fi
  cd "$TOP"
  for HTBIN in $HTBINS; do
    CMDS="${CMDS}$LDD $HTBIN\n"
  done
  printf "$CMDS" | while read -r CMD; do
    echo "> $CMD"
    echo >>$README
    echo "> $CMD" >>$README
    set +e
    OUT=`eval $CMD 2>&1`
    set -e
    printf "%s\n" "$OUT" >>$README
  done
  if [ "$OS" == "win" ]; then
    unix2dos "$README"
  fi
  echo "ok"
  
  # copy report (make check)
  echo "copying report ..."
  cp "$TARGET/report.html" "$DIR/report.html"

  # check that correct number of files in release
  # (number of binaries plus readme and report)
  NEXPECTED=`echo "$HTBINS" | wc -w`
  if [ "$OS" == "win" ]; then
    NEXPECTED=`expr $NEXPECTED + $HTT_NDLL`
  fi
  NEXPECTED=`expr $NEXPECTED + 2`
  echo -n "checking that $NEXPECTED files are in release ... "
  [ `ls "$DIR" | wc -w` -eq $NEXPECTED ]
  echo "ok"
  
  # tgz
  cd "$TARGET"
  tar cvf "$NAME.tar" "$NAME"
  gzip "$NAME.tar"
  rm -f "$NAME.tar"
  echo -n "checking that tar.gz has been created ... "
  [ -f $DIR.tar.gz ]
  if [ ! -f $NAME_NIGHTLY.tar.gz ]; then
    cp $NAME.tar.gz $NAME_NIGHTLY.tar.gz
  fi
  echo "ok"
  
  # zip
  if [ "$OS" == "mac" -o "$OS" == "win" ]; then
    zip -r "$NAME.zip" "$NAME"
	echo -n "checking that zip has been created ... "
    [ -f $DIR.zip ]
    if [ ! -f $NAME_NIGHTLY.zip ]; then
      cp $NAME.zip $NAME_NIGHTLY.zip
    fi
	echo "ok"
  fi
  print_ok
}

#
# unix/win: "shrink-wrap", i.e. get binaries, create README and zip/tgz it (always)
#
function do_shrinkwrap {
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
  elif [ "$OS" == "win" -a "$ARCH" == "i686" -a "$BITS" == "32" ]; then
    SHORT_NAME="$OS"
  elif [ "$OS" == "solaris" -a "$ARCH" == "sun4u" ]; then
    SHORT_NAME="$OS-sparc-$BITS"
  fi
  NAME="httest-$HTT_VER-$SHORT_NAME"
  NAME_NIGHTLY="httest-nightly-$SHORT_NAME"
  
  echo -n "($(date +%H:%M)) shrink-wrap $NAME ... "
  shrinkwrap "$NAME" "$NAME_NIGHLTY" >>"$BUILDLOG" 2>>"$BUILDLOG"
  print_ok
  
}

main $@
