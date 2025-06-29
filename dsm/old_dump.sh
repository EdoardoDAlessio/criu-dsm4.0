if [ "$#" -ne 2 ]; then
  echo "Invalid number of arguments. Expected $0 <app name> <client host name>"
  exit 1
fi

app=$1
client=$2

cd ~/${app}
sudo ./${app} 2 &
sleep 3

#sudo kill -9 $(pidof sh /root/criu/dsm/dump.sh dsm_write dsm_client) ;
#sudo kill -9 $(pidof cat /tmp/pipe_scp) ;

#rm -rf ~/${app}/images
#mkdir ~/${app}/images

sudo ~/criu/criu/criu  dump -t `pidof $app` --images-dir  ~/${app}/images --shell-job -v #vv -o dump_log.txt

scp -r ~/${app} dsm_client:~/
 
