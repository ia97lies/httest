#!/bin/bash

rm -rf win/src/*
mkdir -p win/src
cp -r src/*.[c,h] win/src/ 
cp -r tools/hturlext.c tools/htx2b.c win/src/
grep VERSION config/config.h > win/src/config.h
cd win
pwd
tar czvSpf httest-win-src.tar.gz src
cd -
mv win/httest-win-src.tar.gz .
