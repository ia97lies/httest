#!/bin/bash
#
# generate a gentoo ebuild package
#

set -e # abort on error
set -u # error on undefined variables

VERSION=$1

cp httest.ebuild httest-${VERSION}.ebuild

