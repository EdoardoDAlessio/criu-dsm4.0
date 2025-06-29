#!/bin/bash

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 <app name> <number of thread> [--verbose]"
  exit 1
fi

app=$1
threads=$2
verbose_flag=""

if [ "$3" == "--verbose" ]; then
  verbose_flag="-v"
fi

cd ~/${app}/images || { echo "Image directory not found"; exit 1; }

# Apply the thread filter
python3 ~/criu/dsm/thread_filter.py "$threads" > /dev/null 2>&1

# Remove previous PID file
rm -f /tmp/criu-restored.pid


# Restore using CRIU
touch /tmp/.restore_flag
sudo ~/criu/criu/criu restore --shell-job --dsm_server $verbose_flag
