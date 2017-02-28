#!/bin/bash -x

if [ $# -eq 0 ];then
	echo "$0 <HOST>"
	exit 1
fi

host=$1
SCRIPT=sysinfo-snapshot.py

cat <<EOF > ttt
cd /tmp/
chmod 755 /tmp/$SCRIPT
sudo rm -rf /tmp/sysinfo-snapshot*tgz
sudo /tmp/$SCRIPT -fw --json --perf --ibdiagnet --mtusb
scp sysinfo-snapshot*tgz $HOSTNAME:$PWD
rm ttt
sudo rm -rf sysinfo-snapshot*
EOF

tar cf -  $SCRIPT ttt | ssh -t ${host} 'tar xf - -C /tmp '

ssh -t ${host} 'bash /tmp/ttt'
for FILE in sysinfo-snapshot*tgz;do
	tar xfz $FILE 
done

rm -f sysinfo*tgz
