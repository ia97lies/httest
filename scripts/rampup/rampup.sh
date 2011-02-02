if [ $# != 6 ]; then
  echo "usage:"
  echo "$0 <init-clients> <step-width> <steps> <sleep-between-steps[ms]> <test-duration> <test-script>"
  echo "       init-clients: start with a inital number of clients concurrent"
  echo "       step-width: every step a number of concurrent client will be started additionaly"
  echo "       steps: How many times we will increase the concurrent clients"
  echo "       sleep-between-steps: sleep x ms between the steps"
  echo "       test-duration: duration of the clients started at a step"
  echo "       test-script: the script to make performance tests"
  exit 1
fi

HTT_RAMPUP_INIT_CLIENTS=$1
export HTT_RAMPUP_INIT_CLIENTS
HTT_RAMPUP_STEP=$2
export HTT_RAMPUP_STEP2
HTT_RAMPUP_TO=$3
export HTT_RAMPUP_TO
HTT_RAMPUP_SLEEP=$4
export HTT_RAMPUP_SLEEP
HTT_RAMPUP_DURATION=$5
export HTT_RAMPUP_DURATION
HTT_RAMPUP_SCRIPT=$6
export HTT_RAMPUP_SCRIPT
HTTEST=../../src/httest
export HTTEST

$HTTEST main.htt
