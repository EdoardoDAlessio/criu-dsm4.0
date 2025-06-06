#node_id=$1

cd ~/dsm_write/images

python3 ~/criu/dsm/main_filter.py 0;

echo "Images changed"
sudo ~/criu/criu/criu restore -vvvv --shell-job;


