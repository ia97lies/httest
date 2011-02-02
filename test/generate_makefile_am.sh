#!/bin/bash

printf "EXTRA_DIST= "
for e in `ls -1 *.htt *.htb *.hte *.txt *.sh *.pem *.ntlm`; do echo \\; printf "\t$e "; done
echo
echo
echo TESTS = run_htt_test.sh run_htt_shell_test.sh run_hte_test.sh run_ntlm_test.sh run_coredump_test.sh
