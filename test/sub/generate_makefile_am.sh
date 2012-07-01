#!/bin/bash

printf "EXTRA_DIST= "
for e in `ls -1 *.htt *.htb *.hte *.txt *.sh *.pem *.ntlm *.visual`; do echo \\; printf "\t$e "; done
echo
echo
echo "TESTS = test_run_all.sh test_check_coredumps.sh"

