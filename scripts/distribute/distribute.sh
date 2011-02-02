
if [ $# != 3 ]; then
  echo "usage:"
  echo "$0 <host> <port> <htt-script>"
  echo "       host: target host"
  echo "       port: target port"
  echo "       htt-script: httest script to distribute"
fi

DIST_HOST=$1
export DIST_HOST
DIST_PORT=$2
export DIST_PORT
DIST_HTT_SCRIPT=$3
export DIST_HTT_SCRIPT
HTTEST=../../src/httest
export HTTEST

../../src/httest client.htt
