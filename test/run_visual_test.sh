#!/bin/bash

TOP=..
export TOP
HTT_ERRORS=0
PFX=.

COPY=0
ls *.htt >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  cp ../../test/*.htt .
  cp ../../test/*.htb .
  cp ../../test/*.visual .
  cp ../../test/*.pem .
  cp ../../test/run.sh .
  PFX=../../test
  COPY=1
fi

# start testing
echo
echo Test error output
$PFX/run_visual.sh
HTT_ERRORS=`expr $HTT_ERRORS + $?`

rm -f tmp.txt

if [ $COPY -ne 0 ]; then
  rm -f *.htt
  rm -f *.htb
  rm -f *.visual
  rm -f *.pem
  rm -f run.sh
fi

echo "Success"
exit 0

