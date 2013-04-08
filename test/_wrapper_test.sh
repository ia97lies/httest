#!/bin/bash

SCRIPT=$1
TOP=..
export TOP
HTT_ERRORS=0
PFX=.
errors=0

set +e

COPY=0
ls *.htt >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  cp ../../test/*.txt .
  cp ../../test/*.visual .
  cp ../../test/*.ntlm .
  cp ../../test/*.htt .
  cp ../../test/*.hte .
  cp ../../test/*.htb .
  cp ../../test/*.pem .
  cp ../../test/run.sh .
  cp ../../macros/*.htb ../macros/.
  PFX=../../test
  COPY=1
fi

# start testing
echo
. $PFX/$SCRIPT

rm -f tmp.txt

if [ $COPY -ne 0 ]; then
  rm -f .out.txt
  rm -f *.log
  rm -f *.txt
  rm -f *.ntlm
  rm -f *.visual
  rm -f *.htt
  rm -f *.hte
  rm -f *.htb
  rm -f *.pem
  rm -f run.sh
  rm -f ../macros/*.htb
fi

cores=`ls core* 2>/dev/null | wc -l` 
if [ $errors -ne 0 -o $cores -ne 0 ]; then
  if [ $cores -gt 0 ]; then
    echo $cores coredumps
  fi
  echo "Failed"
  exit 1
else
  echo "Success"
  exit 0
fi

