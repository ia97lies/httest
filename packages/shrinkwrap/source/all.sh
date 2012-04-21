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

  # httest directory
  TOP="$SW/../.."

  do_determine_os
  do_create_target

  BUILDLOG="target/build.log"
  # blue bold
  echo "see $(tput bold)$(tput setaf 4)$BUILDLOG$(tput sgr 0) for build log"
  BUILDLOG="$SW/$BUILDLOG"
  echo "" >"$BUILDLOG"
   
  # get name and dir of all htt binaries
  HTBIN_PATHS="src tools"
  HTBINS=""
  for HTBIN_PATH in $HTBIN_PATHS; do
    BINS=`cat "$TOP/$HTBIN_PATH/Makefile.am" | awk \
      '/bin_PROGRAMS =/ {
        for (i=3; i<=NF; i++) {
          printf("%s ", $(i));
        }
      }'`
    for BIN in $BINS; do
      HTBINS="$HTBINS $HTBIN_PATH/$BIN"
    done
  done
  echo "$HTBINS" >>"$BUILDLOG"

  LIBVARS="APR APU SSL PCRE LUA JS XML2"

  if [ "$UNIX" == "1" ]; then
    # unix
    . "$SW/source/unix/libs.sh"
    for LIBVAR in $LIBVARS; do
      do_get_lib "UNIX" "$LIBVAR"
    done
    for LIBVAR in $LIBVARS; do
      do_unix_build_$LIBVAR
    done
    do_buildconf
    do_unix_build_htt
    do_basic_tests_htt
    do_shrinkwrap
  else
    # windows
    . "$SW/source/win/libs.sh"
    for LIBVAR in $LIBVARS; do
      do_get_lib "WIN" "$LIBVAR"
    done
    do_buildconf
    do_win_configure_htt
    do_win_create_sln
    do_win_build_htt
    do_basic_tests_htt
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
  echo "$(tput bold)$(tput setaf 1)FAILED$(tput sgr 0)"
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
  if [ -d "$SW/target" ]; then
    print_ok_up_to_date
  else
    mkdir "$SW/target"
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
  if [ "$OS" == "win" ]; then
    unzip "$LIB_FILE" -d tmp
	mv tmp/* "$LIB_NAME-$LIB_VER"
	rmdir tmp
  else
    gzip -d -c "$LIB_FILE" > "$LIB_NAME-$LIB_VER.tar"
    tar vxf "$LIB_NAME-$LIB_VER.tar"
    rm "$LIB_NAME-$LIB_VER.tar"
  fi
  rm "$LIB_FILE"
  
  echo -n "checking that directory $LIB_NAME-$LIB_VER exists ... "
  [ -d "$LIB_NAME-$LIB_VER" ]
  echo "ok"
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
  cd "$SW/target"
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
function unix_build_APR {
  cd "$SW/target/$UNIX_APR_NAME-$UNIX_APR_VER"
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
  echo -n "building apr ... "  
  if [ -f "$SW/target/$UNIX_APR_NAME-$UNIX_APR_VER/.libs/libapr-1.a" ]; then
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
  cd "$SW/target/$UNIX_APU_NAME-$UNIX_APU_VER"
  ./configure --with-apr="$SW/target/$UNIX_APR_NAME-$UNIX_APR_VER"
  make

  echo -n "checking that apr-util lib has been built ... "
  [ -f .libs/libaprutil-1.a ]
  echo "ok"
}

#
# unix: build apr-util if no lib, yet
#
function do_unix_build_APU {
  echo -n "building apr-util ... "  
  if [ -f "$SW/target/$UNIX_APU_NAME-$UNIX_APU_VER/.libs/libaprutil-1.a" ]; then
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
  cd "$SW/target/$UNIX_PCRE_NAME-$UNIX_PCRE_VER"
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
  echo -n "building pcre ... "  
  if [ -f "$SW/target/$UNIX_PCRE_NAME-$UNIX_PCRE_VER/.libs/libpcre.a" ]; then
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
  cd "$SW/target/$UNIX_SSL_NAME-$UNIX_SSL_VER"
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
  echo -n "building openssl ... "  
  if [ -f "$SW/target/$UNIX_SSL_NAME-$UNIX_SSL_VER/libssl.a" ]; then
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
  cd "$SW/target/$UNIX_LUA_NAME-$UNIX_LUA_VER"
  if [ "$OS" = "mac" ]; then
    make macosx
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
  echo -n "building lua ... "  
  if [ -f "$SW/target/$UNIX_LUA_NAME-$UNIX_LUA_VER/src/liblua.a" ]; then
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
  cd "$SW/target/$UNIX_JS_NAME-$UNIX_JS_VER"
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

  echo -n "checking that js lib has been built ... "
  [ -f libjs_static.a ]
  echo "ok"
}

#
# unix: build js if no lib, yet
#
function do_unix_build_JS {
  echo -n "building js ... "  
  if [ -f "$SW/target/$UNIX_JS_NAME-$UNIX_JS_VER/js/src/libjs_static.a" ]; then
    print_ok_up_to_date
  else
    unix_build_JS >>"$BUILDLOG" 2>>"$BUILDLOG"
    print_ok
  fi
}

#
# unix: build libmlx2
#
function unix_build_XML2 {
  cd "$SW/target/$UNIX_XML2_NAME-$UNIX_XML2_VER"
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
  echo -n "building libxml2 ... "  
  if [ -f "$SW/target/$UNIX_XML2_NAME-$UNIX_XML2_VER/.libs/libxml2.a" ]; then
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
  echo -n "building htt configuration ... "  
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
  ./configure \
    --with-apr="$SW/target/$UNIX_APR_NAME-$UNIX_APR_VER" \
    --with-apr-util="$SW/target/$UNIX_APU_NAME-$UNIX_APU_VER" \
    --with-pcre="$SW/target/$UNIX_PCRE_NAME-$UNIX_PCRE_VER" \
    --with-ssl="$SW/target/$UNIX_SSL_NAME-$UNIX_SSL_VER" \
    --with-lua="$SW/target/$UNIX_LUA_NAME-$UNIX_LUA_VER/src" \
    --enable-lua-module=yes \
    --with-spidermonkey="$SW/target/$UNIX_JS_NAME-$UNIX_JS_VER/js/src" \
    --enable-js-module=yes \
    --with-libxml2="$SW/target/$UNIX_XML2_NAME-$UNIX_XML2_VER" \
    --enable-html-module=yes \
    enable_use_static=yes
  make clean all

  echo -n "checking that httest has been built ... "
  [ -f src/httest ]
  echo "ok"
  
  # get and remember version for later
  HTT_VER=`cat Makefile | awk '/^VERSION/ { print $3 }'`
  HTT_NBIN=6
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
# win: configure htt in order to get e.g. modules.c
#
function win_configure_htt {
  # create dummy config scripts
  DUMMYDIR="$SW/target/dummy-configs"
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
# win: configure htt (always)
#
function do_win_configure_htt {
  echo -n "configuring htt ... "
  if [ -f "$SW/target/win.configured" ]; then
    # configure is very slow on cygwin, so only do once automatically
    print_ok_up_to_date
  else
    win_configure_htt >>"$BUILDLOG" 2>>"$BUILDLOG"
	touch "$SW/target/win.configured"
    print_ok
  fi
  
  # get and remember version for later
  HTT_VER=`cat "$TOP/Makefile" | awk '/^VERSION/ { print $3 }'`

  if [ "$HTT_VER" == "snapshot" ]; then
    # violet bold
    echo "VERSION: $(tput bold)$(tput setaf 5)$HTT_VER$(tput sgr 0)"
  else
    # blue bold
    echo "VERSION: $(tput bold)$(tput setaf 4)$HTT_VER$(tput sgr 0)"
  fi
}

#
# win: create visual studio solution
#
function win_create_sln {
  WINSLN="$SW/target/solution"
  rm -rf "$WINSLN"
  mkdir "$WINSLN"
  
  # build settings, note that backslashes are escaped twice for sed further below
  RELEASE_DEFINES="HAVE_CONFIG_H;WIN32;NDEBUG;_CONSOLE;_WINDOWS;_CRT_SECURE_NO_DEPRECATE;_MBCS"
  RELEASE_INCLUDES="..\\\\src"
  RELEASE_LIBDIRS=""
  RELEASE_LIBS="Ws2_32.lib"
  
  for LIBVAR in $LIBVARS; do
    eval NAME="\$WIN_${LIBVAR}_NAME-\$WIN_${LIBVAR}_VER"
	echo "name: $NAME"
    RELEASE_INCLUDES="$RELEASE_INCLUDES;..\\\\..\\\\$NAME\\\\include"
    RELEASE_LIBDIRS="$RELEASE_LIBDIRS;..\\\\..\\\\$NAME\\\\lib"
	cd "$SW/target/$NAME/lib"
	for LIB in `ls *.lib`; do
      RELEASE_LIBS="$RELEASE_LIBS;$LIB"
	done
  done

  DEBUG_DEFINES="$RELEASE_DEFINES"
  DEBUG_INCLUDES="$RELEASE_INCLUDES"
  DEBUG_LIBDIRS="$RELEASE_LIBDIRS"
  DEBUG_LIBS="$RELEASE_LIBS"
  
  WINSRC="$SW/source/win"
  cp "$WINSRC/httest.sln" "$WINSLN"
  
  # get header file names
  cd "$TOP/src/"
  H_FILES=`ls *.h | awk '
    { printf("%s ", $0); }
  '`
  
  # get project names and guids from solution
  PROJECT_NAMES=`cat "$WINSRC/httest.sln" | awk '
    /^Project.*= \"ht.*\"/ {
      printf("%s ", substr($3, 2, length($3)-3));
    }
  '`
  # note that $5 below ends with \r...
  PROJECT_GUIDS=`cat "$WINSRC/httest.sln" | awk '
    /^Project.*= \"ht.*\"/ {
      printf("%s ", substr($5, 3, length($5)-5));
    }
  '`
  # create ht* projects
  for NAME in $PROJECT_NAMES; do
    echo -n "$NAME : "
    GUID=`echo $NAME | awk -v pnames="$PROJECT_NAMES" -v pguids="$PROJECT_GUIDS" '{
      n = split(pnames, pname_arr, " ");
      split(pguids, pguid_arr, " ");
      for (i=1; i<=n; i++) {
        if (pname_arr[i] == $0) { print pguid_arr[i]; }
      }
    }'`
    echo "$GUID"

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
    sed -i.bak 's/##DEBUG_DEFINES##/'$DEBUG_DEFINES'/g' $WINPRJ
    sed -i.bak 's/##DEBUG_INCLUDES##/'$DEBUG_INCLUDES'/g' $WINPRJ
    sed -i.bak 's/##DEBUG_LIBDIRS##/'$DEBUG_LIBDIRS'/g' $WINPRJ
    sed -i.bak 's/##DEBUG_LIBS##/'$DEBUG_LIBS'/g' $WINPRJ
    
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
  cp "$TOP/tools/"*.c "$WINSLN/src"
  echo -e "#define PACKAGE_VERSION \"$HTT_VER\"\n#define VERSION \"$HTT_VER\""\
    >"$WINSLN/src/config.h"
  
  # create version resource
  if [ "$HTT_VER" == "snapshot" ]; then
    HTT_VER_COMMAS="0,0,0"
  else
    HTT_VER_COMMAS=`echo $HTT_VER | sed 's/\./\,/g'`
  fi
  WINRC="$WINSLN/src/version.rc"
  echo "1 VERSIONINFO" >"$WINRC"
  echo "FILEVERSION $HTT_VER_COMMAS" >>"$WINRC"
  echo "BEGIN" >>"$WINRC"
  echo "END" >>"$WINRC"

  echo -n "checking that visual studio solution has been created ... "  
  [ -f "$WINRC" ]
  echo "ok"
}

#
# win: create visual studio solution (always)
#
function do_win_create_sln {
  echo -n "creating visual studio solution ... "
  win_create_sln >>"$BUILDLOG" 2>>"$BUILDLOG"
  print_ok
}

#
# win: (re-)build httest binaries
#
function win_build_htt {
  WINSLN="$SW/target/solution"
  #rm -rf "$WINSLN/Release"
  
  # find visual c++ 2010
  PAT="Microsoft Visual Studio 10.0/VC/bin/vcvars32.bat"
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
  
  for LIBVAR in $LIBVARS; do
    eval DIRNAME="\$WIN_${LIBVAR}_NAME-\$WIN_${LIBVAR}_VER"
	cp "$SW/target/$DIRNAME/dll/"*.dll "$WINSLN/Release"
  done
  chmod 755 "$WINSLN/Release"/*.dll
  HTT_NBIN=`ls -l "$WINSLN/Release"/*.dll | wc -l`

  for HTBIN_PATH in $HTBIN_PATHS; do
    rm -f "$TOP/$HTBIN_PATH"/*.exe "$TOP/$HTBIN_PATH/"*.dll
	cp "$WINSLN/Release/"*.dll "$TOP/$HTBIN_PATH"
  done
  for HTBIN in $HTBINS; do
    BINDIR=`echo $HTBIN | awk ' BEGIN { FS="/" } { print $1 }'`
    BINNAME=`echo $HTBIN | awk ' BEGIN { FS="/" } { print $2 }'`
    cp "$WINSLN/Release/$BINNAME.exe" "$TOP/$BINDIR"
	HTT_NBIN=`expr $HTT_NBIN + 1`
  done

  echo -n "checking that httest has been built ... "
  [ -f "$WINSLN/Release/httest.exe" ]
  echo "ok"
}

#
# win: build httest binaries (always)
#
function do_win_build_htt {
  echo -n "building htt ... "
  win_build_htt >>"$BUILDLOG" 2>>"$BUILDLOG"
  print_ok
}

#
# unix/win: run some basic tests
#
function basic_tests_htt {
  if [ "$OS" == "win" ]; then
    EXE_EXT=".exe"
	SH_EXT=".bat"
  else
    EXE_EXT=""
	SH_EXT=".sh"
  fi
  
  for HTBIN in $HTBINS; do
    NAME=`echo $HTBIN | awk ' BEGIN { FS="/" } { print $2 }'`
	echo "NAME=$NAME"
    CALL="$TOP/$HTBIN$EXE_EXT"
	echo "CALL=$CALL"
    "$CALL" --version | grep "$NAME"
	[ `"$CALL" --version | grep "$NAME.* $HTT_VER" | wc -l` -eq 1 ]
  done

  cd "$TOP/test"
  TESTS="block.htt block_lua.htt block_js.htt html.htt"
  for TEST in $TESTS; do
    ./run$SH_EXT $TEST
  done
}

#
# unix/win: run some basic tests (always)
#
function do_basic_tests_htt {
  echo -n "running basic tests ... "
  basic_tests_htt >>"$BUILDLOG" 2>>"$BUILDLOG"
  print_ok
}

#
# unix/win: "shrink-wrap"
#
function shrinkwrap {
  NAME=$1
  
  # clean
  DIR="$SW/target/$NAME"
  rm -rf "$DIR"
  rm -f "$DIR.tar.gz"
  rm -f "$DIR.zip"
  
  mkdir "$DIR"

  # copy executables
  if [ "$OS" == "win" ]; then
    cp "$SW/target/solution/Release/"*.exe "$DIR"
    cp "$SW/target/solution/Release/"*.dll "$DIR"
  else
    for HTBIN in $HTBINS; do
      cp "$TOP/$HTBIN" "$DIR"
    done
  fi
  
  # create readme
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
	echo "In addition, a Visual C++ 2008 Runtime is required, e.g.:" >>"$README"
    echo "http://www.microsoft.com/download/en/details.aspx?id=5582" >>"$README"
  fi
  cat >>"$README" <<EOF

This is "provided as is", no warranty of any kind.

$(date -u "+%Y-%m-%d %H:%M:%S %Z")

EOF
  if [ "$OS" == "win" ]; then
    unix2dos "$README"
  fi

  NEXPECTED=`expr $HTT_NBIN + 1`
  echo -n "checking that $NEXPECTED files are in release ... "
  [ `ls "$DIR" | wc -w` -eq $NEXPECTED ]
  echo "ok"
  
  # tgz
  cd "$DIR/.."
  tar cvzf "$NAME.tar.gz" "$NAME"
  echo -n "checking that tar.gz has been created ... "
  [ -f $DIR.tar.gz ]
  echo "ok"
  
  # zip
  if [ "$OS" == "mac" -o "$OS" == "win" ]; then
    zip -r "$NAME.zip" "$NAME"
	echo -n "checking that zip has been created ... "
    [ -f $DIR.zip ]
	echo "ok"
  fi
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
  fi
  NAME="httest-$HTT_VER-$SHORT_NAME"
  
  echo "NAME: $NAME"
  echo -n "shrink-wrap ... "
  shrinkwrap "$NAME" >>"$BUILDLOG" 2>>"$BUILDLOG"
  print_ok
}

main
