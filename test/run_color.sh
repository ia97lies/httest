#!/bin/bash

TOP=..
export TOP

HTTEST=../src/httest
HTCOLOR=../tools/htcolor
# set if you need the httest exit code
#set -o pipefail
{ { $HTTEST $@ 1>&3 2>&4; } 4>&1 | $HTCOLOR -e; } 3>&1 1>&2 | $HTCOLOR
#exit $?
