#!/bin/bash

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 <app name> <thread range e.g. 1-6> [--verbose]"
  exit 1
fi

app=$1
range=$2
verbose_flag=""
first=$(echo "$range" | cut -d'-' -f1)
second=$(echo "$range" | cut -d'-' -f2)
gap=$((second - first + 1))
echo "First:  $first"
echo "Second: $second"
echo "Gap:    $gap"

if [ "$3" == "--verbose" ]; then
  verbose_flag="-v"

  #Readelf for 
  echo "🚀 Saving readelf..."
fi


cd ~/${app}
readelf -s ./$app | awk '$4 == "OBJECT" && $5 == "GLOBAL" && $6 == "DEFAULT"' > /tmp/readelf.txt

cp dsm_barrier_pages.txt /tmp/dsm_barrier_pages.txt


rm -r images
cp -r backup images

cd ~/${app}/images || { echo "Image directory not found"; exit 1; }
cp ranges.txt /tmp/ranges.txt
# Apply thread filtering
if [ "$3" == "--verbose" ]; then
  python3 ~/criu/dsm/scripts/thread_filter_ranged.py "$range" 
else
  python3 ~/criu/dsm/scripts/thread_filter_ranged.py "$range" > /dev/null 2>&1
fi

# Remove previous PID file
rm -f /tmp/criu-restored.pid
touch /tmp/haltcode
# Setting program arguments
echo $gap > /tmp/restored_threads.txt
echo $first > /tmp/authorized_barrier_thread.txt

# Restore the application with CRIU
touch /tmp/.restore_flag
~/criu/criu/criu restore --shell-job --dsm_client 10.2.11.10 $verbose_flag
rm -f /tmp/.restore_flag 