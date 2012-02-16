#!/bin/bash

VERSION=$1

if [ "$VERSION" != "snapshots" ]; then
  HTTEST=httest-${VERSION}
else
  HTTEST=snapshot
fi
scp ChangeLog ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt2.1/${HTTEST}/.
scp NEWS ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt2.1/${HTTEST}/.
scp httest-${VERSION}.tar.gz ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt2.1/${HTTEST}/.
scp doc/users-guide/users-guide.pdf ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt2.1/${HTTEST}/.

