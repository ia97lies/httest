#!/bin/bash

TOP=..
export TOP
HTT_ERRORS=0
PFX=.

COPY=0
ls *.htt >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  cp ../../test/*.htb .
  cp ../../test/*.ntlm .
  cp ../../test/run.sh .
  PFX=../../test
  COPY=1
fi

# start testing
echo
echo Test ntlm:
$PFX/run_ntlm.sh
HTT_ERRORS=`expr $HTT_ERRORS + $?`

if [ $COPY -ne 0 ]; then
  rm -f *.htb
  rm -f *.ntlm
  rm -f run.sh
fi

CORES=`ls core* 2>/dev/null | wc -l` 
if [ $HTT_ERRORS -ne 0 -o $CORES -gt 0 ]; then
  echo "$HTT_ERRORS Errors"
  if [ $CORES -gt 0 ]; then
    echo $CORES coredumps
  fi
  exit 1
fi
echo "Success"
exit 0

