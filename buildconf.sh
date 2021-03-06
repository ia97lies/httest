#!/bin/bash

function auto_all() {
  echo "> aclocal"
  aclocal
  echo "> autoconf"
  autoconf
  echo "> automake --add-missing"
  automake --add-missing
  echo "> autoreconf"
  autoreconf
  echo "> autoheader"
  autoheader
  echo "> automake -i -f -a"
  automake -i -f -a
  if hash libtoolize 2>/dev/null; then
    echo "> libtoolize"
    libtoolize
  else
    echo "> glibtoolize"
    glibtoolize
  fi
}

if [ ! -d config ]; then mkdir config; fi
if [ ! -d m4 ]; then mkdir m4; fi

# first run without output (known to fail)
auto_all >/dev/null 2>&1

# second run with output and stops at errors
set -e
trap "echo FAILED" EXIT
auto_all
trap - EXIT
