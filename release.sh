TOP=`pwd`

VERSION=$1

set -u

trap "git checkout master; \
      git tag -d $VERSION; \
      sed < configure.in > configure.in.tmp -e \"s/$VERSION/snapshot\"; \
      mv configure.in.tmp configure.in; \
      echo \"Release Build FAILED\"" EXIT

echo
echo "Release httest-$VERSION"
sed < configure.in > configure.in.tmp -e "s/snapshot/$VERSION/"
mv configure.in.tmp configure.in
git commit -m"new release" .

echo "Tag release $VERSION"
  git tag $VERSION

echo "Checkout new tag"
  git checkout $VERSION
  git clean -f

echo
echo "  Check Version"
echo "    configure.in"
grep "AC_INIT(httest, $VERSION, ia97lies@sourceforge.net)" configure.in >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  echo Version specified in configure.in is not $VERSION
  exit 1
fi

echo "    ChangeLog"
grep `grep "\<AC_INIT\>" configure.in | awk 'BEGIN { FS=","} { print $2 }'` ChangeLog >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  echo No ChangeLog Entry for version $VERSION 
  exit 1
fi

echo "    NEWS"
MAINT=`grep "\<AC_INIT\>" configure.in | awk 'BEGIN { FS=","} { print $2 }' | awk 'BEGIN { FS="."} { print $1"."$2.".0" }'`
grep `echo $MAINT` NEWS >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  echo No NEWS Entry for version $MAINT
  exit 1
fi

echo "    XXX"
./check_XXX.sh
if [ $? -ne 0 ]; then
  echo There are still XXX marks in the code of version $VERSION
  exit 1
fi

echo
echo "  Check Test List"
cd test
./generate_makefile_am.sh >/var/tmp/httests
diff /var/tmp/httests Makefile.am
if [ $? -ne 0 ]; then
  echo Some tests are not included
  exit 1
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
echo Checkout master
git checkout master

echo
echo "Build Packages"
echo "  Gentoo"
cp packages/gentoo/httest.ebuild packages/gentoo/overlays/net-analyzer/httest/httest-$VERSION.ebuild
git add packages/gentoo/overlays/net-analyzer/httest/httest-$VERSION.ebuild
git commit -m"New release $VERSION"

sed < configure.in > configure.in.tmp -e "s/$VERSION/snapshot/"
mv configure.in.tmp configure.in
git commit -m"Prepare next release" configure.in

echo
echo Release build SUCCESS 

trap - EXIT
