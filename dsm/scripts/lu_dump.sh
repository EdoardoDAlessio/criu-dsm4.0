#!/bin/bash
set -e

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <app name> <client host name> [extra args...]"
  echo "./lu_dump.sh LU dsm_client -n256 -b64 -p4 -t -s"
  echo "For restore, use main_restore.sh script with ~/criu/dsm/scripts/main_restore.sh LU 0-1 --verbose"
  exit 1
fi


app=$1
client=$2
shift 2
extra_args=("$@")

dump_dir=~/${app}/images


rm -rf ~/${app}
mkdir -p "$dump_dir"
#cp ~/splash2/codes/kernels/lu/contiguous_blocks/${app} ~/${app}
cp ~/criu/dsm/apps/${app} ~/${app}
cd ~/${app}

echo "🚀 Starting $app...."
sudo rm -f /tmp/criu-restored.pid
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
cp /tmp/dsm_barrier_pages.txt ~/${app}/images/.
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
