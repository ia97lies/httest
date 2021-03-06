#!/bin/bash

if [ -z $srcdir ]; then
  srcdir=.
fi

. $srcdir/run_lib.sh

function run_single {
  E=$1
  OUT=$2
  HTTEST_PRE="valgrind --log-file=/tmp/tmp.txt --leak-check=full --track-origins=yes"
  export HTTEST_PRE

  B=`echo $E | sed -e 's/\(.*\)\.valgrind/\1/'`
  if [ -f $B.valgrind ]; then
    ./run.sh $B.htt >/dev/null 2>/dev/null
    lines=`wc -l $B.valgrind | awk '{ print $1 }'`
    tail -n ${lines} /tmp/tmp.txt | sed -e 's/==[0-9]*==//' >/tmp/tmp2.txt
    cat $B.valgrind | sed -e 's/==[0-9]*==//' >/tmp/tmp3.txt
    diff /tmp/tmp2.txt /tmp/tmp3.txt
  else
    printf "SKIP"
  fi
}

echo valgrind tests
LIST=`ls *.valgrind`
COUNT=`ls *.valgrind | wc -l`
run_all "$LIST" $COUNT


