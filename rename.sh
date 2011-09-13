#!/bin/bash

OLD=$1
NEW=$2

for i in `ls src/*.[c,h]`; do 
  echo "$i: \"$OLD\" -> \"$NEW\""
  sed < $i > $i.tmp -e "s/$OLD/$NEW/g" 
  mv $i.tmp $i
done
