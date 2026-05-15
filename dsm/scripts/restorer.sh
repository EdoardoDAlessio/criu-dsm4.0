#!/bin/bash


if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  echo "Usage: $0 <app name> <thread range e.g. 1-6> [--verbose] [--rdma]"
  exit 1
fi
SERVER_IP="192.168.56.10"
DIRECTORY="/home/vagrant"
SCRIPTS="$DIRECTORY/criu/dsm/scripts"
THREAD_FILTER="$SCRIPTS/thread_filter_ranged.py"
PYTHON_FILE="$DIRECTORY/venv-criu/bin/python3"
app=$1
range=$2
first=$(echo "$range" | cut -d'-' -f1)
second=$(echo "$range" | cut -d'-' -f2)
gap=$((second - first + 1))
echo "First:  $first"
echo "Second: $second"
echo "Gap:    $gap"
verbose_flag=""
rdma_flag=""

for arg in "$3" "$4"; do
  case "$arg" in
    --verbose) verbose_flag="-v" ;;
    --rdma)    rdma_flag="--dsm-rdma-enable" ;;
  esac
done

sudo pkill -9 -f "criu"

cd $DIRECTORY/${app}
readelf -s ./$app | awk '$4 == "OBJECT" && $5 == "GLOBAL" && $6 == "DEFAULT"' > /tmp/readelf.txt



sudo rm -r images
cp -r backup images

cd $DIRECTORY/${app}/images || { echo "Image directory not found"; exit 1; }
sudo rm -f /tmp/ranges.txt
sudo rm -f /tmp/dsm_barrier_pages.txt
sudo rm -f /tmp/dsm_mutex.txt
cp ranges.txt /tmp/ranges.txt > /dev/null 2>&1 || true
cp dsm_barrier_pages.txt /tmp/dsm_barrier_pages.txt > /dev/null 2>&1 || true
cp dsm_mutex.txt  /tmp/dsm_mutex.txt > /dev/null 2>&1 || true
# Apply thread filtering
if [ "$verbose_flag" == "-v" ]; then
  "$PYTHON_FILE" $DIRECTORY/criu/dsm/scripts/thread_filter_ranged.py "$range" 
else
  "$PYTHON_FILE" $DIRECTORY/criu/dsm/scripts/thread_filter_ranged.py "$range" > /dev/null 2>&1
fi


# Remove previous PID file
sudo rm -f /tmp/criu-restored.pid
touch /tmp/haltcode
# Setting program arguments
echo $gap > /tmp/restored_threads.txt
echo $first > /tmp/authorized_barrier_thread.txt

# Restore the application with CRIU
touch /tmp/.restore_flag
touch /tmp/haltcode

# Clean up defunct processes with same PID as in CRIU image
#defunct_pid=$(ps -ef | awk '/\[.*\] <defunct>/{print $2}' | head -n1)
defunct_pid=$(pidof $app) 
if [ -n "$defunct_pid" ]; then
  echo "🧹 Cleaning zombie PID $defunct_pid..."
  sudo kill -9 $(ps -o ppid= -p "$defunct_pid" 2>/dev/null) 2>/dev/null || true
fi

sudo script -q -c "$DIRECTORY/criu/criu/criu restore --shell-job --dsm_client $SERVER_IP $verbose_flag $rdma_flag" /dev/null
#sudo $DIRECTORY/criu/criu/criu restore --shell-job --dsm_client $SERVER_IP $verbose_flag $rdma_flag
rm -f /tmp/.restore_flag 