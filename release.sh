TOP=`pwd`

VERSION=$1
OPTION=${2:-"release"}

CUR=`pwd`

trap error 1 2 3 15

function error() {
  cd $CUR
  if [ ! $OPTION = "try" ]; then
    git checkout master 2>/dev/null >/dev/null;
    git tag -d $VERSION 2>/dev/null >/dev/null;
  fi 
  echo "Release build FAILED"
  exit $1
}

if [ $OPTION = "try" ]; then
  echo
  echo "*** Try mode ***"
fi

echo
echo "Release httest-$VERSION"
if [ ! $OPTION = "try" ]; then
  git commit -m"new release $VERSION" configure.ac
fi

if [ ! $OPTION = "try" ]; then
  echo
  echo "Check repository"
  git status | grep modified
  if [ $? -eq 0 ]; then
    echo "Please commit first all changes"
    error 1
  fi
fi

if [ ! $OPTION = "try" ]; then
  echo "Tag release $VERSION"
  git tag $VERSION
fi

if [ ! $OPTION = "try" ]; then
  echo "Checkout new tag"
  git checkout $VERSION
  git clean -f
fi

echo
echo "  Check Version"
echo "    configure.ac"
grep "AC_INIT(httest, $VERSION, ia97lies@sourceforge.net)" configure.ac >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  echo Version specified in configure.ac is not $VERSION
  error 1
fi

echo "    ChangeLog"
grep `grep "\<AC_INIT\>" configure.ac | awk 'BEGIN { FS=","} { print $2 }'` ChangeLog >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  echo No ChangeLog Entry for version $VERSION 
  error 1
fi

echo "    NEWS"
MAINT=`grep "\<AC_INIT\>" configure.ac | awk 'BEGIN { FS=","} { print $2 }' | awk 'BEGIN { FS="."} { print $1"."$2.".0" }'`
grep `echo $MAINT` NEWS >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  echo No NEWS Entry for version $MAINT
  error 1
fi

echo "    XXX"
./check_XXX.sh
if [ $? -ne 0 ]; then
  echo There are still XXX marks in the code of version $VERSION
  error 1
fi

echo
echo "  Check Test List"
cd test
./generate_makefile_am.sh >/var/tmp/httests
diff /var/tmp/httests Makefile.am
if [ $? -ne 0 ]; then
  echo Some tests are not included
  error 1
fi
cd ..

set -e

echo
echo "  Build Configuration"
./buildconf.sh

echo
echo "  Make Distribution"
export CPPFLAGS="-I/share/xpository/osp/lua/5.2.2/${ARCH}/dist-bin/include"
export LDFLAGS="-L/share/xpository/osp/lua/5.2.2/${ARCH}/dist-bin/lib"
#CONFIG="--enable-lua-module --enable-html-module --enable-xml-module --enable-h2-module --with-apr=/share/xpository/apache/apr/1.5.2/$ARCH/dist-bin/bin --with-apr-util=/share/xpository/apache/apr-util/1.5.4/$ARCH/dist-bin/bin --with-ssl=/share/install/adnssl/3.2.4.2/adnssl/spool/$ARCH-prod --with-pcre=/share/xpository/pcre/pcre/8.41/$ARCH/dist-bin/bin --with-libxml2=/share/xpository/gnome/libxml2/2.9.4/$ARCH/dist-bin/bin --with-nghttp2=/share/xpository/github/nghttp2/1.18.0/${ARCH}/dist-bin"
CONFIG="--with-ssl=/home/cli/workspace/openssl"
CFLAGS="-g -Wall --std=c99 -Wdeclaration-after-statement -Werror" ./configure $CONFIG
./configure $CONFIG
make clean all
#make distcheck DISTCHECK_CONFIGURE_FLAGS="$CONFIG"
make check
make dist
echo
echo "  Build User Guide"
cd doc/users-guide
make all VERSION=$VERSION
cd -

if [ ! $OPTION = "try" ]; then
  echo
  echo Checkout master
  git checkout master

  echo
  echo "Build Packages"
  echo "  Gentoo"
  cp packages/gentoo/httest.ebuild packages/gentoo/overlays/net-analyzer/httest/httest-$VERSION.ebuild
  git add packages/gentoo/overlays/net-analyzer/httest/httest-$VERSION.ebuild
  git commit -m"New release $VERSION"
fi

echo
echo Release build SUCCESS 

if [ $OPTION = "try" ]; then
    error 0
fi
