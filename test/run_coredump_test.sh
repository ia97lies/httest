echo
echo Test if there are coredumps:
CORES=`ls core* 2>/dev/null | wc -l` 
if [ $CORES -gt 0 ]; then
  echo $CORES coredumps
else
  echo no cordumps
fi

