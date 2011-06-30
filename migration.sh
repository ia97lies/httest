#!/bin/bash

for i in `find $1`; do
  if [ -f $i ];then
    echo $i
    sed < $i > $i.tmp \
      -e "s/\<_SSL_CONNECT\>/_SSL:CONNECT/g" \
      -e "s/\<_SSL_ACCEPT\>/_SSL:ACCEPT/g" \
      -e "s/\<_CLOSE +SSL\>/_SSL:CLOSE/g" \
      -e "s/\<_SSL_SESSION_ID\>/_SSL:GET_SESSION_ID/g" \
      -e "s/\<_SSL_GET_SESSION\>/_SSL:GET_SESSION/g" \
      -e "s/\<_SSL_SET_SESSION\>/_SSL:SET_SESSION/g" \
      -e "s/\<_RENEG\>/_SSL:RENEG/g"
    mv $i.tmp $i
  fi
done

