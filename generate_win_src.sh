#!/bin/bash

rm -rf win/src/*
mkdir -p win/src
cp -r src/conf.[c,h] src/defines.h src/file.[c,h] src/htproxy.c src/htremote.c src/htntlm.c src/httest.c src/regex.[c,h] src/socket.[c,h] src/ssl.[c,h] src/util.[c,h] src/worker.[c,h]  win/src/ 
cp -r tools/hturlext.c tools/htx2b.c win/src/
grep VERSION config/config.h > win/src/config.h
cd win
pwd
tar czvSpf httest-win-src.tar.gz src
cd -
mv win/httest-win-src.tar.gz .
