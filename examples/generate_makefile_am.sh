#!/bin/bash

printf "EXTRA_DIST= "
for e in `ls -1 *.htt`; do echo \\; printf "\t$e "; done
echo
