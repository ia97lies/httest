#!/bin/bash

. run_lib.sh

function run_single {
  E=$1
  OUT=$2

  cat $E | ./run.sh 2>>.out.txt >>.out.txt
}

echo pipe script into httest
LIST=`ls *.htt`
COUNT=`ls *.htt | wc -l`
run_all "$LIST" $COUNT

