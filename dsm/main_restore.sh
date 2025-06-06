#node_id=$1

cd ~/dsm_write/images

python3 ~/criu/dsm/thread_filter.py 0;
rm -f /tmp/criu-restored.pid

echo "Images changed"

cd ~/dsm_write/images
sudo ~/criu/criu/criu restore -v --shell-job --dsm_server


