#!/bin/bash

if [ -z $srcdir ]; then
  srcdir=.
fi

. $srcdir/run_lib.sh

function run_single {
  E=$1
  OUT=$2

  B=`echo $E | sed -e 's/\(.*\)\.hte/\1/'`
  if [ -f $B.tx2 ]; then
    ./run.sh -ln $B.hte 2>/tmp/tmp0.txt >/dev/null
    cat /tmp/tmp0.txt | sed -e 's/^[0-9]*/./' >/tmp/tmp1.txt
    cat /tmp/tmp1.txt | sort >/tmp/tmpA.txt
    cat $B.tx2 | sed -e 's/^[0-9]*/./' >/tmp/tmp2.txt
    cat /tmp/tmp2.txt | sort >/tmp/tmpB.txt
    diff -Bw /tmp/tmpA.txt /tmp/tmpB.txt >>$OUT
  else
    echo @:SKIP true true > /tmp/exit.htt
    ./run.sh -ns /tmp/exit.htt
  fi
}

echo error scripts tests
LIST=`ls *.hte`
COUNT=`ls *.hte | wc -l`
run_all "$LIST" $COUNT

