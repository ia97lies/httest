#!/bin/bash

grep -r XXX src/*.[c,h] | grep -v httXXXXXX
if [ $? -eq 0 ]; then
  exit 1;
else
  exit 0;
fi
