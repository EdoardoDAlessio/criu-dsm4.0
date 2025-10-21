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

if [ "$3" == "--verbose" ]; then
  verbose_flag="-v"
  echo "🚀 Saving readelf..."
fi

# Change to app folder and dump readelf
cd ~/"${app}" || { echo "App directory not found"; exit 1; }
readelf -s "./$app" | awk '$4 == "OBJECT" && $5 == "GLOBAL" && $6 == "DEFAULT"' > /tmp/readelf.txt

rm -rf images
cp -r backup images

# Go to images directory
cd ~/"${app}/images" || { echo "Image directory not found"; exit 1; }
cp ranges.txt /tmp/ranges.txt

# Apply thread filtering (range passed directly)
if [ "$3" == "--verbose" ]; then
  python3 ~/criu/dsm/scripts/thread_filter_ranged.py "$range"
else
  python3 ~/criu/dsm/scripts/thread_filter_ranged.py "$range" > /dev/null 2>&1
fi

# Remove previous PID file
rm -f /tmp/criu-restored.pid


# Setting program arguments
echo $gap > /tmp/restored_threads.txt
echo $first > /tmp/authorized_barrier_thread.txt

# Trigger CRIU restore
touch /tmp/.restore_flag
touch /tmp/haltcode
sudo ~/criu/criu/criu restore --shell-job --dsm_server $verbose_flag
