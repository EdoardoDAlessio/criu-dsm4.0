


if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    echo "Usage:"
    echo "$0 <exec name> <host>"
    exit 0
fi


app=$1 
host=$2

cd ~/${app}


sudo rm -r images/ ; mkdir images; cp *.img  images/

#### Remote Node 1
ssh ${host} -C "rm -r ~/images; sudo killall -9 ${app}" ;  
scp -r ./images ${host}:
ssh ${host} -C "echo ${app} > /tmp/cmd"


if [ -z "${3}" ];
then
	exit
fi

#### Remote Node 2
echo "========Transfer to  3rd Node====="
ssh $3 -C "rm -r ~/images/*.img; sudo killall -9 $app; mkdir ~/images/" ; 
scp  -r *.img ${3}:~/images/
ssh ${3} -C "echo $app > /tmp/cmd"

if [ -z "${4}" ];
then
	exit
fi

### Remote Node 3

ssh $4 -C "rm -r ~/images/*.img; sudo killall -9 $app; mkdir ~/images/" ; 
scp  -r *.img ${4}:~/images/
ssh ${4} -C "echo $app > /tmp/cmd"

if [ -z "${5}" ];
then
	exit
fi



ssh $5 -C "rm -r ~/images/*.img; sudo killall -9 $app; mkdir ~/images/" ; 
scp  -r *.img ${5}:~/images/
ssh ${5} -C "echo $app > /tmp/cmd"
