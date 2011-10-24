#!/bin/bash

./src/httest -L | grep "\<_" | grep -v "\<_[A-Z]\+:[A-Z]\+" | grep -v "_RPS" | grep -v "_LOOP"| grep -v "_FOR"| grep -v "_IF" | grep -v "_BPS" | grep -v "_ERROR" | awk '{ printf "syn keyword httStatement        %s\n", $1 }'
./src/httest -L  | grep -v "\->" | grep "_[A-Z]\+:" | awk '{ printf "syn match httStatement          \"\\<%s\\>\"\n", $1}'

