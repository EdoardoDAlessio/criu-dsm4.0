#!/bin/bash
set -e

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <app name> <client host name> <threads> [extra args...]"
  echo "./phoenix.sh histogram-dsm dsm_client /root/phoenix/phoenix-2.0/tests/histogram/input/histogram_datafiles/small.bmp"
  exit 1
fi

app=$1
client=$2
threads=$3
shift 3
extra_args=("$@")
dump_dir=~/${app}/images


sudo rm -f /tmp/ranges.txt
sudo rm -f /tmp/dsm_barrier_pages.txt
sudo rm -f /tmp/dsm_mutex.txt
rm -rf ~/${app}
mkdir -p "$dump_dir"

#cp -r ~/phoenix/phoenix-2.0/tests/word_count/${app} ~/${app}
#cd ~/${app}
#cp "${extra_args[@]}" .

#cp -r ~/phoenix/phoenix-2.0/tests/histogram/${app} ~/${app}
#cp -r ~/phoenix/phoenix-2.0/tests/string_match/${app} ~/${app}
#cp -r ~/phoenix/phoenix-2.0/tests/kmeans/${app} ~/${app}
cp -r  ~/criu/dsm/test/${app} ~/${app}
cd ~/${app}


#cp -r ~/phoenix/phoenix-2.0/tests/pca/ ~/${app}
#cd ~/${app}/pca
#cp ~/phoenix/phoenix-2.0/tests/pca/${app} ~/${app}
#cd ~/${app}


#cp -r ~/phoenix/phoenix-2.0/tests/matrix_multiply/${app} ~/${app}
#cp -r ~/phoenix/phoenix-2.0/tests/matrix_multiply/matrix_file_A.txt ~/${app}/.
#cp -r ~/phoenix/phoenix-2.0/tests/matrix_multiply/matrix_file_B.txt ~/${app}/.
#cd ~/${app}

#cp -r ~/criu/dsm/test/${app} ~/${app}
#cd ~/${app}


#cp ~/phoenix/phoenix-2.0/tests/linear_regression/${app} ~/${app}
#cp /root/phoenix/phoenix-2.0/tests/input/histogram_datafiles/small.bmp ~/${app}/.
#cp ~/criu/dsm/apps/${app} ~/${app}

echo "🚀 Starting $app ..."
sudo rm -f /tmp/criu-restored.pid
sudo rm -f /tmp/ranges.txt
rm -f /tmp/haltcode

# Run FFT (main thread is also a worker)
#export LD_PRELOAD=/root/criu/dsm/my_malloc/mymmapalloc.so
#export MMAPALLOC_LOG=1
#export 
DSM=$threads ./${app} "${extra_args[@]}" &
app_pid=$!
#unset DSM_BARRIER
#unset LD_PRELOAD

echo "🧪 FFT started with PID $app_pid"

# 📦 Dump with CRIU
echo "📦 Dumping with CRIU after 30s warm-up..."
sleep 5

sudo ~/criu/criu/criu dump -t "$app_pid" --images-dir "$dump_dir" --shell-job -v
cp /tmp/ranges.txt            ~/${app}/images/. > /dev/null 2>&1 || true
cp /tmp/dsm_barrier_pages.txt ~/${app}/images/. > /dev/null 2>&1 || true
cp /tmp/dsm_mutex.txt         ~/${app}/images/. > /dev/null 2>&1 || true
echo "✅ Dump completed. Backing up images..."
cp -r ~/${app}/images ~/${app}/backup


# 🚚 Copy to client
echo "🚚 Transferring app and images to $client..."
ssh "$client" "sudo rm -rf ~/${app}"
scp -r ~/${app} "$client":~/
echo "✅ Transfer complete $client"


client=dsm_client2
 🚚 Copy to client
echo "🚚 Transferring app and images to $client..."
ssh "$client" "sudo rm -rf ~/${app}"
scp -r ~/${app} "$client":~/
echo "✅ Transfer complete $client"

client=dsm_client3
# 🚚 Copy to client
#echo "🚚 Transferring app and images to $client..."
ssh "$client" "sudo rm -rf ~/${app}"
scp -r ~/${app} "$client":~/
#scp /tmp/mmapalloc_log "$client":/tmp || true
#scp /tmp/dsm_barrier_pages.txt "$client":/tmp || true
#scp /tmp/ranges.txt "$client":/tmp || true
#echo "✅ Transfer complete $client"

