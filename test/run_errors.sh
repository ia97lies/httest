#!/bin/bash

if [ -z $srcdir ]; then
  srcdir=.
fi

. $srcdir/run_lib.sh

function run_single {
  E=$1
  OUT=$2

  B=`echo $E | sed -e 's/\(.*\)\.hte/\1/'`
  if [ -f $B.txt ]; then
    ./run.sh -n $B.hte 2>/tmp/tmp.txt >/dev/null
    if [ $? -eq 2 ]; then
      return 2
    fi
    cat /tmp/tmp.txt | sort >/tmp/tmpA.txt
    cat $B.txt | sort >/tmp/tmpB.txt
    diff -Bw /tmp/tmpA.txt /tmp/tmpB.txt >>$OUT
  else
    printf "SKIP"
  fi
}

echo error scripts tests
LIST=`ls *.hte`
COUNT=`ls *.hte | wc -l`
run_all "$LIST" $COUNT

