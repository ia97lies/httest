#!/bin/bash

TOP=../..
export TOP

HTTEST=$TOP/src/httest
$HTTEST_PRE $HTTEST $@
