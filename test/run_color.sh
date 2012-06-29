#!/bin/bash

TOP=..
export TOP

HTTEST=../src/httest
HTCOLOR=../tools/htcolor
{ $HTTEST $@ 2>&3 | $HTCOLOR; } 3>&1 1>&2 | $HTCOLOR -e
