#!/bin/bash

set -e

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <app name> <client host name> <number of worker threads> [--main_is_worker] [extra args...]"
  exit 1
fi

app=$1
client=$2
threads=$3  # Number of pthread-created worker threads

# Default behavior: assume main is NOT a worker (adds +1 for total thread count)
main_is_worker=false
if [ "$4" == "--main_is_worker" ]; then
  main_is_worker=true
  shift
fi

# Compute total threads and threads to trap
if [ "$main_is_worker" = true ]; then
  total_threads=$threads       # Main does work, all are active
  threads_to_trap=$((threads - 1))  # Trap all but the main thread
else
  total_threads=$((threads + 1))   # Main just spawns
  threads_to_trap=$threads         # Trap all workers
fi

shift 3
extra_args=("$@")

dump_dir=~/${app}/images

# 🛠 Compile interposer if needed
if [ ! -f trap_threads.so ]; then
  echo "🛠️ Compiling thread trap interposer..."
  gcc -Wall -fPIC -shared -o trap_threads.so /root/criu/dsm/apps/trap_threads.c -ldl
fi

# 📁 Prepare app directory and copy binaries
rm -rf ~/${app}
mkdir -p "$dump_dir"
cp ~/criu/dsm/apps/trap_threads.so ~/${app}
cp ~/criu/dsm/apps/${app} ~/${app}
cd ~/${app}

echo "🚀 Starting application with $threads worker threads..."
rm -f /tmp/criu-restored.pid
LD_PRELOAD=./trap_threads.so ./${app} "$threads" "${extra_args[@]}" &
app_pid=$!

echo "🧪 App started with PID $app_pid"

# ⏳ Wait for all threads to be visible
echo "⏳ Waiting for $total_threads threads to show up..."
while true; do
    current_threads=$(ls /proc/$app_pid/task/ 2>/dev/null | wc -l)
    echo "🧪 Current thread count: $current_threads, aiming to $total_threads"
    sleep 3
    if [[ "$current_threads" -eq "$total_threads" ]]; then
        echo "✅ All threads visible: $current_threads"
        break
    fi
    sleep 0.1
done

# 🛑 Stop main thread (already trapped others)
echo "🛑 Stopping main thread..."
kill -STOP "$app_pid"

# 🔍 Optional: print thread states
echo "🔍 Verifying thread states:"
for tid in $(ls /proc/$app_pid/task); do
    echo -n "Thread $tid: "
    grep State /proc/$app_pid/task/$tid/status
done

# 📦 Dump with CRIU
echo "📦 Dumping with CRIU..."
rm -f /tmp/.restore_flag
sudo ~/criu/criu/criu dump -t "$app_pid" --images-dir "$dump_dir" --shell-job -v

echo "✅ Dump completed successfully"

# 🚚 Copy to client
echo "🚚 Cleaning and copying to remote host..."
ssh "${client}" "rm -rf ~/${app}"
scp -r ~/${app} "${client}":~/

echo "✅ Transfer complete"
