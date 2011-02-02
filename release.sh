TOP=`pwd`

CVS_TAG=$1

# check if ChangeLog ist
VERSION=`echo $CVS_TAG | awk 'BEGIN { FS="_" } { printf("%d.%d.%d", $3, $4, $5) }'`

echo
echo "Release httest-$VERSION"

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

set +e
set +u
echo
echo "  Check Release"
echo "    cvs -q -n -f up"
rm -f /var/tmp/diff.txt
cvs -q -n up 2>>/var/tmp/diff.txt >>/var/tmp/diff.txt 
# Remove lines starting with U<space>
mv /var/tmp/diff.txt /var/tmp/diff.txt.tmp
egrep -v '^U ' /var/tmp/diff.txt.tmp >/var/tmp/diff.txt
rm /var/tmp/diff.txt.tmp
echo "    cvs -q -f diff -r $CVS_TAG"
cvs -q diff -r -f $CVS_TAG  2>>/var/tmp/diff.txt >>/var/tmp/diff.txt
mv /var/tmp/diff.txt /var/tmp/diff.txt.tmp
grep -v "no longer exists, no comparison available" /var/tmp/diff.txt.tmp >/var/tmp/diff.txt
rm /var/tmp/diff.txt.tmp

set -e
set -u
# Now we have a file containing the filtered output from cvs update, cvs diff,
# count the number of lines
DIFF_LINES=0
WC_OUT=`cat /var/tmp/diff.txt | wc -l`
if [ "$WC_OUT" != "0" ]; then
  echo $WC_OUT
  echo cvs and local version does not match 
  cat /var/tmp/diff.txt
  echo Release build FAILED
  rm /var/tmp/diff.txt
  exit -1
fi
rm /var/tmp/diff.txt
echo

echo
echo "  Build Man Pages"
./generate_man_pages.sh

echo
echo "  Build Configuration"
./buildconf.sh

echo
echo "  Make Distribution"
make distcheck 

echo
echo "Build Packages"
echo "  Gentoo"
cd packages/gentoo
./mkpkg.sh $VERSION
mv *.ebuild ../../.
cd ../..

echo
echo Release build SUCCESS 

