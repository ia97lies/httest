TOP=`pwd`

echo
echo "  Make Distribution"
export CPPFLAGS="-I/share/xpository/osp/lua/5.2.2/${ARCH}/dist-bin/include"
export LDFLAGS="-L/share/xpository/osp/lua/5.2.2/${ARCH}/dist-bin/lib"
CONFIG="--enable-lua-module --enable-js-module --enable-html-module --enable-xml-module --enable-h2-module --with-spidermonkey=$HOME/workspace/local/bin --with-apr=/share/xpository/apache/apr/1.4.6/$ARCH/dist-bin/bin --with-apr-util=/share/xpository/apache/apr-util/1.5.2/$ARCH/dist-bin/bin --with-ssl=/share/install/adnssl/3.0.18.0/adnssl/spool/$ARCH-prod --with-pcre=/share/xpository/pcre/pcre/8.36/$ARCH/dist-bin/bin --with-libxml2=/share/xpository/gnome/libxml2/2.9.1/$ARCH/dist-bin/bin --with-nghttp2=/home/cli/tmp/nghttp2-1.3.1"
CFLAGS="-O0 -g -Wall -ansi -Wdeclaration-after-statement" ./configure $CONFIG
./configure $CONFIG
make clean all
#make distcheck DISTCHECK_CONFIGURE_FLAGS="$CONFIG"
make check

