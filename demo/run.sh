#!/bin/bash

TOP=..
export TOP

HTTEST=../src/httest
$HTTEST_PRE $HTTEST $@
