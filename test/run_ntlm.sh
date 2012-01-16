#!/bin/bash

if [ -z $srcdir ]; then
  srcdir=.
fi

. $srcdir/run_lib.sh

function run_single {
  E=$1
  OUT=$2

  ./run.sh $E >> $OUT 2>> $OUT
}

echo ntlm tests
LIST=`ls *.ntlm`
COUNT=`ls *.ntlm | wc -l`
run_all "$LIST" $COUNT

