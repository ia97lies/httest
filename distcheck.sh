TOP=`pwd`

echo
echo "  Make Distribution"
CONFIG="--enable-lua-module --enable-js-module --enable-html-module --enable-xml-module --with-spidermonkey=$HOME/workspace/local/bin --with-libxml2=$HOME/workspace/local/bin"
CFLAGS="-O0 -g -Wall -ansi -Wdeclaration-after-statement -Werror" ./configure $CONFIG
make clean all
make distcheck DISTCHECK_CONFIGURE_FLAGS="$CONFIG"

