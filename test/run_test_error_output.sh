#!/bin/bash

HTT_ERRORS=0

for E in `ls *.hte`; do
  B=`echo $E | sed -e 's/\(.*\)\.hte/\1/'`
  if [ -f $B.txt ]; then
    CORES_PRE=`ls core* 2>/dev/null | wc -l` 
    printf "Run $B.hte "
    ./run.sh -e $B.hte 2>/tmp/tmp.txt >/dev/null
    diff -B /tmp/tmp.txt $B.txt 
    ret=$?
    if [ $ret -ne 0 ]; then
      HTT_ERRORS=`expr $HTT_ERRORS + 1`
      echo FAILED
    else
      echo OK
    fi
    CORES_POST=`ls core* 2>/dev/null | wc -l` 
    if [ $CORES_POST -gt $CORES_PRE ]; then
      echo Coredump detected!
    fi
  fi
done

exit $HTT_ERRORS
