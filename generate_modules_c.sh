#!/bin/bash

LIST=$1

TEMPLATE=src/modules.c.tmpl
TARGET=modules.c

#init
cp $TEMPLATE $TARGET

for I in $LIST; do
  sed < modules.c >modules.c.tmp \
    -e "s/\/\/MODULES_DECLARATION\/\//void ${I}_module_init(foo);\n\/\/MODULES_DECLARATION\/\//g" \
    -e "s/\/\/MODULES_REGISTRATION\/\//{${I}_module_init(foo)},\n  \/\/MODULES_REGISTRATION\/\//g"
  mv modules.c.tmp modules.c 
done

