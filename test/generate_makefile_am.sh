#!/bin/bash

printf "EXTRA_DIST= "
for e in `ls -1 *.htt *.htb *.hte *.txt *.sh *.pem *.ntlm *.visual`; do echo \\; printf "\t$e "; done
echo
echo
echo "test_store_SOURCES=test_store.c \$(top_srcdir)/src/store.c"
echo "AM_CFLAGS=-I\$(top_srcdir)/src"
echo "check_PROGRAMS=test_store"
echo "TESTS = test_store test_run_all.sh test_run_errors.sh test_run_visual.sh test_run_ntlm.sh test_check_coredumps.sh"

