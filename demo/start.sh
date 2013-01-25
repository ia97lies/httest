#!/bin/bash

if [ ! -d server/logs ]; then
  mkdir server/logs
fi
$HOME/local/sbin/nginx -p server

