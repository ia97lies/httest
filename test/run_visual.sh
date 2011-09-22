#!/bin/bash

HTT_ERRORS=0

for E in `ls *.visual`; do
  B=`echo $E | sed -e 's/\(.*\)\.visual/\1/'`
  if [ -f $B.visual ]; then
    ./run.sh $B.htt >/tmp/tmp.txt 2>/dev/null
    lines=`wc -l $B.visual | awk '{ print $1 }'`
    tail -n ${lines} /tmp/tmp.txt >/tmp/tmp2.txt
    diff /tmp/tmp2.txt $B.visual
    ret=$?
    if [ $ret -ne 0 ]; then
      HTT_ERRORS=`expr $HTT_ERRORS + 1`
      echo $B FAILED
    else
      echo $B OK
    fi
  fi
done

exit $HTT_ERRORS
