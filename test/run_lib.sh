#!/bin/bash

function run_all {
  list=$1
  count=$2

  errors=0
  i=1
  for E in $list; do
    rm -f .out.txt
    printf "$i/$count $(date) $E "
    grep REQUIRE $E >/dev/null 2>/dev/null
    if [ $? -eq 0 ]; then
      REQUIRE=`grep REQUIRE $E | awk '{ print $2 }'`
      ./run.sh -C $REQUIRE >/dev/null 2>/dev/null
      if [ $? -ne 0 ]; then
        printf "\e[1;31mSKIP\e[0m\n"
        let i++
        continue;
      fi
    fi
    CORES_PRE=`ls core* 2>/dev/null | wc -l` 
    run_single $E .out.txt
    if [ $? -ne 0 ]; then
      printf "\e[1;31mFAILED\e[0m\n\n"
      tail .out.txt
      mv .out.txt $E.error
      let errors++
      echo
    else
      printf "\e[1;32mOK\e[0m\n"
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
