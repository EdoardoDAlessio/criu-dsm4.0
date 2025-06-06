#node_id=$1

cd ~/dsm_write/images

python3 ~/criu/dsm/main_filter.py 0;
rm -f /tmp/criu-restored.pid

echo "Images changed"
sudo ~/criu/criu/criu restore -vv --shell-job --dsm_server;


