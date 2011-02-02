#!/bin/bash

help2man -N -n "test HTTP driven application" -i man/httest.ext  src/httest > man/httest.1
#gzip -f man/httest.1
help2man -N -n "record a HTTP session" src/htproxy > man/htproxy.1
#gzip -f man/htproxy.1
help2man -N -n "read/write NTLM message"  src/htntlm > man/htntlm.1
#gzip -f man/htntlm.1
help2man -N -n "control interactive programs over TCP/IP"  src/htremote > man/htremote.1
#gzip -f man/htremote.1
help2man -N -n "extract url from a HTML page" tools/hturlext > man/hturlext.1
#gzip -f man/hturlext.1
help2man -N -n "translate hex digits to binary"  tools/htx2b > man/htx2b.1
#gzip -f man/htx2b.1

