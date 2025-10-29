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

sudo kill -9 $(pidof criu) 2>/dev/null || true
sudo kill -9 $(pidof "$app") 2>/dev/null || true

# Change to app folder and dump readelf
cd ~/"${app}" || { echo "App directory not found"; exit 1; }
readelf -s "./$app" | awk '$4 == "OBJECT" && $5 == "GLOBAL" && $6 == "DEFAULT"' > /tmp/readelf.txt

sudo rm -rf images
cp -r backup images

# Go to images directory
cd ~/"${app}/images" || { echo "Image directory not found"; exit 1; }
cp ranges.txt /tmp/ranges.txt
cp dsm_barrier_pages.txt /tmp/dsm_barrier_pages.txt
# Apply thread filtering (range passed directly)
if [ "$3" == "--verbose" ]; then
  python3 ~/criu/dsm/scripts/thread_filter_ranged.py "$range"
else
  python3 ~/criu/dsm/scripts/thread_filter_ranged.py "$range" > /dev/null 2>&1
fi

# Remove previous PID file
sudo rm -f /tmp/criu-restored.pid


# Setting program arguments
echo $gap > /tmp/restored_threads.txt
echo $first > /tmp/authorized_barrier_thread.txt

# Trigger CRIU restore
touch /tmp/.restore_flag
touch /tmp/haltcode

# Clean up defunct processes with same PID as in CRIU image
#defunct_pid=$(ps -ef | awk '/\[.*\] <defunct>/{print $2}' | head -n1)
echo "🧹 Checking for defunct processes of $app..."
defunct_pid=$(pidof $app) 
if [ -n "$defunct_pid" ]; then
  echo "🧹 Cleaning zombie PID $defunct_pid..."
  sudo kill -9 $(ps -o ppid= -p "$defunct_pid" 2>/dev/null) 2>/dev/null || true
fi



sudo ~/criu/criu/criu restore --shell-job --dsm_server $verbose_flag
