node_id=$1

cd ~/dsm_write/images

python3 ~/criu/dsm/thread_filter.py $node_id ;

echo "Images changed"
sudo ~/criu/criu/criu restore -vvvv --shell-job --dsm_client 10.2.11.10;
