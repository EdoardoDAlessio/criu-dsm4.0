node_id=$1

cd ~/demo/images

python3 ~/criu/dsm/thread_filter.py $node_id ;
rm -f /tmp/criu-restored.pid

echo "Images changed"
sudo ~/criu/criu/criu restore -v --shell-job --dsm_client 10.2.11.10;


