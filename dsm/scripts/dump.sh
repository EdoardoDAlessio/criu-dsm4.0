#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <app name> <client host name> <number of threads>"
  exit 1
fi

app=$1
client=$2
threads=$3
rm -f /tmp/haltcode
rm -f /tmp/ranges.txt
rm -f /tmp/dsm_barrier_pages.txt
rm -f /tmp/dsm_mutex.txt
# Ensure the directory exists
mkdir -p ~/${app}/images
cp ~/criu/dsm/test/${app} ~/${app}
cd ~/${app}
# Run the application with the specified number of threads
sudo ./${app} "$threads" &
sleep 3

# Dump the running process
sudo ~/criu/criu/criu dump -t "$(pidof $app)" --images-dir ~/${app}/images --shell-job -v 

# Copy the entire app directory to the client machine after cleaning old imgages
scp -r ~/${app} "$client":
