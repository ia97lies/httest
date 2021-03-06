#!/bin/bash

if [ -z $srcdir ]; then
  srcdir=.
fi

. $srcdir/run_lib.sh

function run_single {
  E=$1
  OUT=$2

  B=`echo $E | sed -e 's/\(.*\)\.visual/\1/'`
  if [ -f $B.visual ]; then
    ./run.sh $B.htt >/tmp/tmp.txt 2>/dev/null
    if [ $? -eq 2 ]; then
      return 2
    fi
    lines=`wc -l $B.visual | awk '{ print $1 }'`
    tail -n ${lines} /tmp/tmp.txt | sed 's/\r$//' >/tmp/tmp2.txt
    diff /tmp/tmp2.txt $B.visual >$OUT
  else
    printf "SKIP"
  fi
}

echo visual tests
LIST=`ls *.visual`
COUNT=`ls *.visual | wc -l`
run_all "$LIST" $COUNT


