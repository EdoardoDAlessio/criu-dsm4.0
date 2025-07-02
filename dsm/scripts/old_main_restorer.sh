
app=$1
cd ~/${app}/images

python3 ~/criu/dsm/thread_filter.py 0;
rm -f /tmp/criu-restored.pid

echo "Images changed"

cd ~/${app}/images
sudo ~/criu/criu/criu restore --shell-job --dsm_server -v

