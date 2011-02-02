#!/bin/bash

CVS_TAG=$1

# check if ChangeLog ist
VERSION=`echo $CVS_TAG | awk 'BEGIN { FS="_" } { printf("%d.%d.%d", $3, $4, $5) }'`

scp ChangeLog ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt/httest-${VERSION}/.
scp NEWS ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt/httest-${VERSION}/.
scp httest-${VERSION}.tar.gz ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt/httest-${VERSION}/.
scp httest-${VERSION}.ebuild ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt/httest-${VERSION}/.
scp httest-${VERSION}.exe ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt/httest-${VERSION}/.
