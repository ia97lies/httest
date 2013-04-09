#!/bin/bash

if [ -z $srcdir ]; then
  srcdir=.
fi

. $srcdir/run_lib.sh

printf "Test print command list ..."
./run.sh -L | grep "_REQ" >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    printf "\e[1;31mFAILED\e[0m\n"
	printf "Error: _REQ is not in the command list\n"
	exit 1
fi
printf "\e[1;32mOK\e[0m\n"

printf "Test print help text for _REQ ..."
./run.sh -C _REQ | grep "_REQ" >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    printf "\e[1;31mFAILED\e[0m\n"
	printf "Error: Help text for _REQ missing\n"
	exit 1
fi
printf "\e[1;32mOK\e[0m\n"

