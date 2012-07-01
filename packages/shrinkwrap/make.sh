#!/bin/bash

set -e
trap "printf \"\e[31;1mFAILED\e[0m\n\"" EXIT
if [ "$#" == "0" ]; then
  ARGS="all"
else
  ARGS="$@"
fi
for ARG in $ARGS; do
  echo "make: source/$ARG.sh ... "
  source/$ARG.sh
  printf "make: source/$ARG.sh ... \e[32;1mOK\e[0m\n"
done
trap - EXIT
