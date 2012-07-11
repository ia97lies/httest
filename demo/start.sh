#!/bin/bash

if [ ! -d server/logs ]; then
  mkdir server/logs
fi
$HOME/workspace/local/sbin/nginx -p server

