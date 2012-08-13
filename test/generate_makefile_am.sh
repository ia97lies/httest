#!/bin/bash

echo "test_htt_stack_SOURCES=test_htt_stack.c \$(top_srcdir)/src/store.c"
echo "AM_CFLAGS=-I\$(top_srcdir)/src"
echo "check_PROGRAMS=test_htt_stack"
echo "TESTS = test_htt_stack"

