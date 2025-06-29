#!/bin/bash

set -e

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <app name> <client host name> <number of threads>"
  exit 1
fi

app=$1
client=$2
threads=$3
total_threads=$((threads + 1))  # Main + N workers
dump_dir=~/${app}/images

# Ensure trap_threads.so is built
if [ ! -f trap_threads.so ]; then
  echo "🛠️ Compiling thread trap interposer..."
  gcc -Wall -fPIC -shared -o trap_threads.so trap_threads.c -ldl
fi

# Ensure the app directory and images directory exist
rm -rf ~/${app}
mkdir -p ~/${app}/images
cp ~/criu/dsm/trap_threads.so ~/${app}
cp ~/criu/dsm/${app} ~/${app}
cd ~/${app}

echo "🚀 Starting application with $threads worker threads..."
rm -f /tmp/criu-restored.pid
LD_PRELOAD=./trap_threads.so ./${app} "$threads" &
app_pid=$!

echo "🧪 App started with PID $app_pid"

# Wait for all threads to appear
echo "⏳ Waiting for $total_threads threads to show up..."
while true; do
    current_threads=$(ls /proc/$app_pid/task/ 2>/dev/null | wc -l)
    if [[ "$current_threads" -eq "$total_threads" ]]; then
        echo "✅ All threads visible: $current_threads"
        break
    fi
    sleep 0.1
done

# Stop the main thread
echo "🛑 Stopping main thread..."
kill -STOP $app_pid

# Optional: verify thread states
echo "🔍 Verifying thread states:"
for tid in $(ls /proc/$app_pid/task); do
    echo -n "Thread $tid: "
    grep State /proc/$app_pid/task/$tid/status
done

# Dump
echo "📦 Dumping with CRIU..."
rm -f /tmp/.restore_flag
sudo ~/criu/criu/criu dump -t "$app_pid" --images-dir "$dump_dir" --shell-job -v

echo "✅ Dump completed successfully"

# Transfer to client
echo "🚚 Cleaning and copying to remote host..."
ssh ${client} "rm -rf ~/${app}"
scp -r ~/${app} ${client}:~/

echo "✅ Transfer complete"
