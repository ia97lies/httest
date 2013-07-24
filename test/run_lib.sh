#!/bin/bash

OS="unknown"
if [ `uname -o 2>/dev/null` ]; then
  if [ `uname -o` == "GNU/Linux" ]; then
    OS="linux"
  elif [ `uname -o` == "Cygwin" ]; then
    OS="cygwin"
  fi
elif [ `uname -s` == "Darwin" ]; then
  OS="mac"
elif [ `uname -s` == "SunOS" ]; then
  OS="solaris"
fi
if [ "$OS" == "unknown" ]; then
  OS="linux"
fi
export OS

function run_all {
  list=$1
  count=$2

  errors=0
  i=1
  for E in $list; do
    rm -f .out.txt
    printf "$i/$count $(date) $E "
    CORES_PRE=`ls core* 2>/dev/null | wc -l` 
    run_single $E .out.txt
    ret=$?
    if [ $ret -eq 1 ]; then
      printf "...\e[1;31mFAILED\e[0m\n\n"
      tail .out.txt
      mv .out.txt $E.error
      let errors++
      echo
    elif [ $ret -eq 2 ]; then
      printf "...\e[1;33mSKIP\e[0m\n"
    else
      printf "...\e[1;32mOK\e[0m\n"
    fi
    CORES_POST=`ls core* 2>/dev/null | wc -l` 
    if [ $CORES_POST -gt $CORES_PRE ]; then
      echo Coredump detected!
    fi
    let i++
  done

  if [ $errors -ne 0 ]; then
    printf "\e[1;31m$errors Errors found\e[0m\n"
  fi
}
