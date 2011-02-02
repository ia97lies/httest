#!/bin/bash

HTT_ERRORS=0

for E in `ls *.ntlm`; do
  CORES_PRE=`ls core* 2>/dev/null | wc -l` 
  ./run.sh -e $E
  if [ $? -ne 0 ]; then
    HTT_ERRORS=`expr $HTT_ERRORS + 1`
  fi
  CORES_POST=`ls core* 2>/dev/null | wc -l` 
  if [ $CORES_POST -gt $CORES_PRE ]; then
    echo Coredump detected!
  fi
done

exit $HTT_ERRORS
