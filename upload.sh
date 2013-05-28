#!/bin/bash

VERSION=$1

git push --tags

if [ "$VERSION" != "snapshots" ]; then
  HTTEST=httest-${VERSION}
else
  HTTEST=snapshot
fi
scp ChangeLog ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt2.4/${HTTEST}/.
scp NEWS ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt2.4/${HTTEST}/.
scp httest-${VERSION}.tar.gz ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt2.4/${HTTEST}/.
scp doc/users-guide/users-guide.pdf ia97lies,htt@frs.sourceforge.net:/home/pfs/project/h/ht/htt/htt2.4/${HTTEST}/.

