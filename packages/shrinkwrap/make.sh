#!/bin/bash

set -e
trap "echo \"$(tput bold)$(tput setaf 1)FAILED$(tput sgr 0)\"" EXIT
if [ "$#" == "0" ]; then
  ARGS="all"
else
  ARGS="$@"
fi
for ARG in $ARGS; do
  echo "make: source/$ARG.sh ... "
  source/$ARG.sh
  echo "make: source/$ARG.sh ... $(tput bold)$(tput setaf 2)OK$(tput sgr 0)"
done
trap - EXIT
