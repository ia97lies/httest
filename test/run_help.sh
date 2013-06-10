#!/bin/bash

if [ -z $srcdir ]; then
  srcdir=.
fi

. $srcdir/run_lib.sh

printf "Test print command list\n"
printf "Check CLIENT ..."
./run.sh -L | grep "CLIENT" >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    printf "\e[1;31mFAILED\e[0m\n"
	printf "Error: CLIENT is not in the command list\n"
	exit 1
fi
printf "\e[1;32mOK\e[0m\n"

printf "Check _REQ ..."
./run.sh -L | grep "_REQ" >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    printf "\e[1;31mFAILED\e[0m\n"
	printf "Error: _REQ is not in the command list\n"
	exit 1
fi
printf "\e[1;32mOK\e[0m\n"

printf "Check _SSL:TRACE ..."
./run.sh -L | grep "_SSL:TRACE" >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    printf "\e[1;31mFAILED\e[0m\n"
	printf "Error: _SSL:TRACE is not in the command list\n"
	exit 1
fi
printf "\e[1;32mOK\e[0m\n"

printf "Test print help text\n"
printf "Check CLIENT ..."
./run.sh -C CLIENT | grep "CLIENT" >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    printf "\e[1;31mFAILED\e[0m\n"
	printf "Error: Help text for CLIENT missing\n"
	exit 1
fi
printf "\e[1;32mOK\e[0m\n"

printf "Check _REQ ..."
./run.sh -C _REQ | grep "_REQ" >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    printf "\e[1;31mFAILED\e[0m\n"
	printf "Error: Help text for _REQ missing\n"
	exit 1
fi
printf "\e[1;32mOK\e[0m\n"

printf "Check _SSL:TRACE ..."
./run.sh -C _SSL:TRACE | grep "_SSL:TRACE" >/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
    printf "\e[1;31mFAILED\e[0m\n"
	printf "Error: Help text for _SSL:TRACE missing\n"
	exit 1
fi
printf "\e[1;32mOK\e[0m\n"

