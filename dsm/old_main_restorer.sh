#node_id=$1

cd ~/demo/images

python3 ~/criu/dsm/thread_filter.py 0;
rm -f /tmp/criu-restored.pid

echo "Images changed"

cd ~/demo/images
sudo ~/criu/criu/criu restore --shell-job --dsm_server

