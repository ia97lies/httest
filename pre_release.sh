TOP=`pwd`

VERSION=$1

set -u

trap error 1 2 3 15 ERR

function error() {
  sed < configure.in > configure.in.tmp -e "s/$VERSION/snapshot/"
  mv configure.in.tmp configure.in
  echo "Release build FAILED"
  exit 1
}

echo
echo "Release httest-$VERSION"
sed < configure.in > configure.in.tmp -e "s/snapshot/$VERSION/"
mv configure.in.tmp configure.in

echo
echo "Check repository"
git status | grep modified
if [ $? -eq 0 ]; then
  echo "Please commit first all changes"
  error 
fi

echo
echo "  Check Version"
echo "    configure.in"
grep "AC_INIT(httest, $VERSION, ia97lies@sourceforge.net)" configure.in >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  echo Version specified in configure.in is not $VERSION
  error 
fi

echo "    ChangeLog"
grep `grep "\<AC_INIT\>" configure.in | awk 'BEGIN { FS=","} { print $2 }'` ChangeLog >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  echo No ChangeLog Entry for version $VERSION 
  error 
fi

echo "    NEWS"
MAINT=`grep "\<AC_INIT\>" configure.in | awk 'BEGIN { FS=","} { print $2 }' | awk 'BEGIN { FS="."} { print $1"."$2.".0" }'`
grep `echo $MAINT` NEWS >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  echo No NEWS Entry for version $MAINT
  error 
fi

echo "    XXX"
./check_XXX.sh
if [ $? -ne 0 ]; then
  echo There are still XXX marks in the code of version $VERSION
  error 
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
CONFIG="--enable-lua-module --enable-js-module --enable-html-module --with-spidermonkey=$HOME/workspace/local/bin --with-libxml2=$HOME/workspace/local/bin"
CFLAGS="-g -Wall -ansi" ./configure $CONFIG
make clean all
make distcheck DISTCHECK_CONFIGURE_FLAGS="$CONFIG"
echo
echo "  Build User Guide"
cd doc/users-guide
make all VERSION=$VERSION
cd -

echo
echo Release build SUCCESS 

