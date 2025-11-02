#!/bin/bash
set -e

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <app name> <client host name> [extra args...]"
  echo "./fft_dump_malloc.sh FFT dsm_client -m22 -p4 -t"
  exit 1
fi

app=$1
client=$2
shift 2
extra_args=("$@")

dump_dir=~/${app}/images


rm -rf ~/${app}
mkdir -p "$dump_dir"
#cp ~/splash2/codes/kernels/fft/${app} ~/${app}
cp ~/criu/dsm/apps/${app} ~/${app}
cd ~/${app}

echo "🚀 Starting $app ..."
sudo rm -f /tmp/criu-restored.pid
rm -f /tmp/haltcode

# Run FFT (main thread is also a worker)
#export LD_PRELOAD=/root/criu/dsm/my_malloc/mymmapalloc.so
#export MMAPALLOC_LOG=1
#export 
DSM_BARRIER=1 ./${app} "${extra_args[@]}" &
app_pid=$!
#unset DSM_BARRIER
#unset LD_PRELOAD

echo "🧪 FFT started with PID $app_pid"

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
echo "✅ Transfer complete $client"

client=dsm_client-2
# 🚚 Copy to client
echo "🚚 Transferring app and images to $client..."
ssh "$client" "rm -rf ~/${app}"
scp -r ~/${app} "$client":~/
scp /tmp/mmapalloc_log "$client":/tmp || true
scp /tmp/dsm_barrier_pages.txt "$client":/tmp || true
scp /tmp/ranges.txt "$client":/tmp || true
echo "✅ Transfer complete $client"

client=dsm_client-3
# 🚚 Copy to client
echo "🚚 Transferring app and images to $client..."
ssh "$client" "rm -rf ~/${app}"
scp -r ~/${app} "$client":~/
scp /tmp/mmapalloc_log "$client":/tmp || true
scp /tmp/dsm_barrier_pages.txt "$client":/tmp || true
scp /tmp/ranges.txt "$client":/tmp || true
echo "✅ Transfer complete $client"
