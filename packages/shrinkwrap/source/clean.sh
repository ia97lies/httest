#!/bin/bash

set -e
trap "echo FAILED" EXIT

cd "${0%/*}/.."
SW=`pwd`

# httest directory
TOP="$SW/../.."

rm -rf "$SW/target"
rm -f "$TOP/src"/*.exe "$TOP/src"/*.dll
rm -f "$TOP/tools"/*.exe "$TOP/tools"/*.dll

trap - EXIT
