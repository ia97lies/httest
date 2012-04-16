#!/bin/bash

set -e
trap "echo FAILED" EXIT

cd "${0%/*}/.."
ROOT=`pwd`

rm -rf "$ROOT/target"
rm -f "$ROOT/../src"/*.exe "$ROOT/src"/*.dll
rm -f "$ROOT/../tools"/*.exe "$ROOT/tools"/*.dll

trap - EXIT
