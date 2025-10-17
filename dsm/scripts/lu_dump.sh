#!/bin/bash
set -e

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <app name> <client host name> <num_threads> [extra args...]"
  exit 1
fi

app=$1
client=$2
threads=$3
shift 3
extra_args=("$@")

dump_dir=~/${app}/images

# Clean previous logs
rm -f /tmp/mmapalloc_log

# 📂 Prepare build / app directory
cd ~/criu/dsm/my_malloc
if [ ! -f mymmapalloc.so ]; then
  echo "🛠️ Compiling mmap alloc interposer..."
  gcc -Wall -fPIC -shared -o mymmapalloc.so /root/criu/dsm/my_malloc/mymmapalloc.c -ldl
fi

rm -rf ~/${app}
mkdir -p "$dump_dir"
cp ~/splash2/codes/kernels/lu/contiguous_blocks/${app} ~/${app}
cd ~/${app}

echo "🚀 Starting $app with $threads threads..."
rm -f /tmp/criu-restored.pid
rm -f /tmp/haltcode

# Run LU (main thread is also a worker)
#export LD_PRELOAD=/root/criu/dsm/my_malloc/mymmapalloc.so
#export MMAPALLOC_LOG=1
#export 
DSM_BARRIER=1 ./${app} "${extra_args[@]}" &
app_pid=$!
#unset DSM_BARRIER
#unset LD_PRELOAD

echo "🧪 LU started with PID $app_pid"

# 📦 Dump with CRIU
echo "📦 Dumping with CRIU after 30s warm-up..."
sleep 5

sudo ~/criu/criu/criu dump -t "$app_pid" --images-dir "$dump_dir" --shell-job -v

cp /tmp/ranges.txt ~/${app}/images/.
echo "✅ Dump completed. Backing up images..."
cp -r ~/${app}/images ~/${app}/backup

# 🚚 Copy to client
echo "🚚 Transferring app and images to $client..."
ssh "$client" "rm -rf ~/${app}"
scp -r ~/${app} "$client":~/
scp /tmp/mmapalloc_log "$client":/tmp || true
scp /tmp/dsm_barrier_pages.txt "$client":/tmp || true
scp /tmp/ranges.txt "$client":/tmp || true
echo "✅ Transfer complete"
