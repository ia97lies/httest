#!/bin/bash
#
# generate a gentoo ebuild package
#

set -e # abort on error
set -u # error on undefined variables

VERSION=$1

cat >httest-${VERSION}.ebuild << EOF
# Copyright 1999-2008 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# \$Header: /cvsroot/htt/httest/packages/gentoo/mkpkg.sh,v 1.1 2009/05/15 05:48:52 ia97lies Exp $

inherit eutils

DESCRIPTION="Http Test Tool"
HOMEPAGE="http://htt.sourceforge.net/"
SRC_URI="mirror://sourceforge/htt/\${P}.tar.gz"
LICENSE="Apache License V2.0"
DEPEND="dev-libs/apr
	dev-libs/apr-util
	dev-libs/libpcre
	dev-libs/openssl"
RDEPEND="\${DEPEND}"

SLOT="0"
KEYWORDS="x86"

src_compile() {
	econf || die "econf failed"
	emake || die "emake failed"
}

src_install() {
	emake DESTDIR="\${D}" install || die "emake install failed"
}

EOF
