#!/bin/bash

printf "EXTRA_DIST= "
for e in `ls -1 *.htt *.htb *.hte *.txt *.sh *.pem *.ntlm`; do echo \\; printf "\t$e "; done
echo
echo
echo "test_store_SOURCES=test_store.c \$(top_srcdir)/src/store.c"
echo "AM_CFLAGS=-I\$(top_srcdir)/src"
echo "check_PROGRAMS=test_store"
echo "TESTS = test_store run_htt_test.sh run_htt_shell_test.sh run_hte_test.sh run_visual_test.sh run_ntlm_test.sh run_coredump_test.sh"

