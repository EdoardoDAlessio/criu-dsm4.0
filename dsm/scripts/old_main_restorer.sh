#!/bin/bash

if [ "$#" -lt 3 ] || [ "$#" -gt 5 ]; then
  echo "Usage: $0 <app name> <thread range e.g. 1-6> <n_clients> [--verbose] [--rdma]"
  exit 1
fi

app=$1
range=$2
clients=$3
first=$(echo "$range" | cut -d'-' -f1)
second=$(echo "$range" | cut -d'-' -f2)
gap=$((second - first + 1))

verbose_flag=""
rdma_flag=""

for arg in "$4" "$5"; do
  case "$arg" in
    --verbose) verbose_flag="-v" ;;
    --rdma)    rdma_flag="--dsm-rdma-enable" ;;
  esac
done



#sudo pkill -9 -f "criu" > /dev/null 2>&1
#sudo pkill -9 -f "${app}" > /dev/null 2>&1

# Change to app folder and dump readelf
cd ~/"${app}" || { echo "App directory not found"; exit 1; }

sudo rm -f /tmp/restored_threads.txt
sudo rm -f /tmp/ranges.txt
sudo rm -f /tmp/dsm_barrier_pages.txt
sudo rm -f /tmp/dsm_mutex.txt
sudo rm -rf images

cp -r backup images

# Go to images directory
cd ~/"${app}/images" || { echo "Image directory not found"; exit 1; }
cp ranges.txt /tmp/ranges.txt > /dev/null 2>&1 || true
cp dsm_barrier_pages.txt /tmp/dsm_barrier_pages.txt > /dev/null 2>&1 || true
cp dsm_mutex.txt /tmp/dsm_mutex.txt > /dev/null 2>&1 || true
# Apply thread filtering (range passed directly)
if [ "$verbose_flag" == "-v" ]; then
  python3 ~/criu/dsm/scripts/thread_filter_ranged.py "$range"
else
 python3 ~/criu/dsm/scripts/thread_filter_ranged.py "$range" > /dev/null 2>&1
fi


# Remove previous PID file
sudo rm -f /tmp/criu-restored.pid


# Setting program arguments
echo $gap > /tmp/restored_threads.txt
echo $first | sudo tee /tmp/authorized_barrier_thread.txt
unset DSM
export DSM=0
# Trigger CRIU restore
touch /tmp/.restore_flag
touch /tmp/haltcode

# Clean up defunct processes with same PID as in CRIU image
#defunct_pid=$(ps -ef | awk '/\[.*\] <defunct>/{print $2}' | head -n1)

#sudo ~/criu/criu/criu restore --shell-job --dsm_server --restore-detached --tcp-established $verbose_flag </dev/null >/dev/null 2>&1

#script -q -c "sudo ~/criu/criu/criu restore --shell-job --dsm_server $verbose_flag" /dev/null

#sudo ~/criu/criu/criu restore --shell-job --dsm_server $clients $rdma_flag $verbose_flag

#sudo ~/criu/criu/criu restore --shell-job --dsm_server "$clients" $rdma_flag $verbose_flag

cmd=(sudo ~/criu/criu/criu restore --shell-job --dsm_server "$clients")

[ -n "$rdma_flag" ] && cmd+=("$rdma_flag")
[ -n "$verbose_flag" ] && cmd+=("$verbose_flag")

echo "Running: ${cmd[@]}"
"${cmd[@]}"
