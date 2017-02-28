#!/bin/bash
#
# Copyright (C) Mellanox Technologies, Ltd. 2001-2014.  ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of Mellanox Technologies, Ltd.
# (the "Company") and all right, title, and interest in and to the software product,
# including all associated intellectual property rights, are and shall
# remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#
#
# Capture system information on the local machine and the its IB fabric.



# default values
VERSION=2.1
PATH=/sbin:/usr/sbin:$PATH
HOST=$(hostname)
XDATE=$(date +%Y%m%d-%H%M)
OUT_DIR=/tmp/sysinfo-snapshot-$HOST-$XDATE
DEBUG=${DEBUG:-0}
IBNETDISCOVER=`which ibnetdiscover 2>/dev/null`
SAQUERY=`which saquery 2>/dev/null`

NETDEVICES=$(LIST="" ; set -- `ls /sys/class/net`; while [ $# -ne 0 ];do [[ $1 == lo ]] && shift && continue; LIST="$LIST $1" ;shift;done ; echo $LIST)
export LANG=C

declare -a commands
declare -a xfiles xfile procfiles
declare -a xfiles
declare -a ext_files
declare -a ext_files_name

DISTRO=${DISTRO:-"unknown"}

if [ ${DISTRO} == "unknown" ];then
	if [[ `grep -i ubuntu /etc/issue >/dev/null 2>&1; echo $?` -eq 0 ]];then
		DISTRO=ubuntu
	elif [[ `grep -i redhat /etc/issue >/dev/null 2>&1; echo $?` -eq 0 ]];then
		DISTRO=redhat
	elif [[ `grep -i suse /etc/issue >/dev/null 2>&1;echo $?` -eq 0 ]];then
		DISTRO=suse
	elif [[ `grep -i centos /etc/issue >/dev/null 2>&1;echo $?` -eq 0 ]];then
		DISTRO=centos
	fi
fi

function add_dummy_command() {
	local command=$1
	cat <<EOF >> ${DUMMY_FUNC}
function ${command} {
	echo "Command ${2} not found"
}
EOF
	
}

function filter_commands() {
	local array=()
	local FILE=${1}
	local TTFILE=`mktemp XXXXXX`

	local i=0

	cat ${FILE} | sort -u | while read line;do
		set -- $line
		case `type -t $1 2>/dev/null ` in
			file|alias|keyword|builtin|function) echo ${line} >> ${TTFILE}	 ;;
			*) args=$(echo $line | sed -e 's/[ \t]/_/g'); add_dummy_command ${args} "${line}" ; echo ${args} >> ${TTFILE};;
		esac
		((i++))
	done

	mv  $TTFILE ${FILE}
}

#------------------------------------------------------------------------------------------------------------------
function usage {
    echo "sysinfo-snapshot version: $VERSION usage: 
	  The sysinfo-snapshot command gathers system information and place it into a tar file. 
	  It is required to run this script as super user (root).
	  -h|--help - print this help
	  -d|--dir - set destination directory (default is /tmp)"
    exit 0
}


if [[ -f /usr/bin/whoami ]] ; then
	if [[ `/usr/bin/whoami` != "root" ]] ; then
		echo "Runing as a none root user"
		echo "Please switch to root user (super user) and run again."
		exit 1
	fi
fi

while [[ ! -z "$1" ]]; do
	# echo "$1"
      case "$1" in
	-h | --help)
	    	usage
		shift
	;;
        -d | --dir)
            	OUT_DIR=$2/sysinfo_snapshot-$HOST-$XDATE
		shift 2
        ;;
	*)  
		echo "error: unknown option $1"
	    	usage
	;;
	esac
done

OUT_FILE=$OUT_DIR/sysinfo-snapshot-${VERSION}-$HOST-$XDATE.html
OUT_DIR_TMP=$OUT_DIR/tmp

DUMMY_FUNC=${OUT_DIR}/dummy_functions
rm -f ${DUMMY_FUNC}

if [ ! -d "$OUT_DIR" ]; then
    mkdir -p "$OUT_DIR"
fi

if [ ! -d "$OUT_DIR_TMP" ]; then
    mkdir -p "$OUT_DIR_TMP"
fi

if [ ! -d "$OUT_DIR/stat" ]; then
    mkdir -p "$OUT_DIR/stat"
fi
echo "Destination directory is $OUT_DIR"
#------------------------------------------------------------------------------------------------------------------
#checks master SM is alive by sampling its activity count:
function sm_status {

	SmActivity_1=0
	NoSM=0
	
	for ((lo=0;lo<=3;lo++)) ; do
		sleep 3
		SmActivity=`sminfo |awk '{ print $10 }'`
		echo "SM activity on `date +%T` is $SmActivity"
		if [[ $SmActivity == $SmActivity_1 ]] ; then
			NoSM=1	
		else
			NoSM=0
		fi
		SmActivity_1=$SmActivity
	done

	if [ $NoSM = 0 ] ; then
		echo "Master SM activity is progressing. SM is alive."
	else
		echo "ALERT: Master SM activity has not make any progress. CHECK master SM!"
	fi
}


#------------------------------------------------------------------------------------------------------------------
function zz_proc_net_bonding_files()
{

	find /proc/net/bonding/ |xargs grep ^

}


#------------------------------------------------------------------------------------------------------------------
function zz_sys_class_net_files()
{

	find /sys/class/net/ |xargs grep ^

}


#------------------------------------------------------------------------------------------------------------------
function Multicast_Information {
	[[ ${#SAQUERY} -eq 0 ]] && return
	echo "MLIDs list: "
	${SAQUERY} -g
	echo ""
	echo "MLIDs members for each multicast group:"
	MLIDS=(`${SAQUERY} -g |grep Mlid | sed 's/\./ /g'|awk '{print $2}'`)
	MLIDC=${#MLIDS[*]}

	for ((i = 0; i< $MLIDC ; i++)); do
	        echo "Members of MLID ${MLIDS[$i]} group:"
	        ${SAQUERY} -m ${MLIDS[$i]}
	        echo "============================================================"
	done
}


#------------------------------------------------------------------------------------------------------------------
function ib_switches_FW_scan() {
	[[ ${#IBNETDISCOVER} -eq 0 ]] && return
	lid=-1
	default_shaldag_fw="07.02.00"
	default_anafa_fw="01.00.05"

#	usage() {
#		echo    "usage : $0 [OPTIONS]" 
#		echo    "Options"
#		echo    "[-u uniq_lid]		- Scan only uniq_lid"
#		echo    "[-f fw_version]		- Use user defined fw version"
#		echo    "[-t]			- Print output as a text (without colours)"
#		echo    "[-p]			- Print alarm entries only"
#		echo    "[-h]			- Show this help"
#		exit ;
#	}

	aprint_err_pc() {
	awk '
		function blue(s) {
			if (mono)
				printf s
			else 
				printf "\033[1;034m" s "\033[0;39m"
		}
		function red(s) {
			if (mono)
				printf s
	  		else
				printf "\033[1;031m" s "\033[0;39m"
		}
		function green(s) {
			if (mono)
				printf s
		   else
				printf "\033[1;032m" s "\033[0;39m"
		}
		function print_title() {
			if (!(cnt_titles % 15))
				blue(title "\n")
				cnt_titles++
		}

		BEGIN { 
			title = ("hw_dev_rev\thw_dev_id\tfw_version\tfw_build_id\tfw_date\t\tfw_psid")
			i_shaldag_alarm = 0
			fw_good = 0
			cnt_titles = 0
			mono = "'$mono'"
			supress_normal ="'$delp'"
			red("Scan Fabric\n")
			default_shaldag_fw="'$default_shaldag_fw'" 
			default_anafa_fw="'$default_anafa_fw'" 
			red("Default fw_versions are " default_shaldag_fw " for Shaldag and " default_anafa_fw " for Anafa\n")
			tb1="-----------------------------------------------------------------------------------------------" 
     		blue(tb1 "\n")
		};

		/Hca/	{
			red($0 "\n") 
			exit
		}        
		/^Switch/ {
			i_shaldag++
			ind_shaldag = sprintf("%d ",i_shaldag)
			SWITCH = $0;next
		}               

		{
		#	sub (/[\.\.\.]+/," ",$0)
		}
		/hw_dev_rev/ ||	/hw_dev_id/ || /fw_build_id/ {
			data[n++] = $NF "\t\t"
			next
		}
		/fw_version/ {
			if (( $NF == default_shaldag_fw )|| ( $NF == default_anafa_fw )) {
				fw_good = 1
			}
			data[n++] = $NF "\t"
			next
		}
		/fw_date/ || /fw_psid/ {
			data[n++] = $NF "\t"
			next
		}
		/sw_version/ {
			for (i = 0; i < n; i++)
				if (i in data) { 
					table = (table data[i] )
				}
			if (fw_good == 1) {
				if (!supress_normal) {
					print_title()
					red(ind_shaldag)
					green(SWITCH "\n")
					green(table "\n")
					blue(tb1 "\n")
				}
			}
			else {
				print_title()
				red(ind_shaldag)
				red("--> ALERT "SWITCH " ALERT <--\n");  
				red(table "\n")
				i_shaldag_alarm++
				blue(tb1 "\n")
			}
			fw_good = 0
			delete data 
			table = "" 
			n = 0
		}
		END {
			blue(title "\n")
			red("Default fw_versions are " default_shaldag_fw " for Shaldag and " default_anafa_fw " for Anafa\n")
			red("Total : CHIPs scanned : " i_shaldag ". Problems found : " i_shaldag_alarm "\n" )
		}';
	}

	get_topology_send_mad() {

	awk '	
		#$1~/Switch/ && $2 == 24 {
		$1~/Switch/ && ($2 == 36 || $2 == 24) {
			lid = $(NF-2)
			sub (/#/,"\t", $0) 
			print "echo " $0 "; vendstat -N", lid
			next
		}';
	}

	scan_all() {
		cat ${OUT_DIR}/ibnetdiscover | get_topology_send_mad |sh |aprint_err_pc ;
		exit;
	}

	scan_one() {
		lid_l=$1
		echo START
		#madstat N $lid_l | \
		smpquery nodeinfo $lid_l | \
		awk -F "." '
		/NodeType/	{
			node_type = $NF
		}
		/LocalPort/	{
			localport = $NF
		}
		/NumPorts/	{
			nports    = $NF
		}
		/node_desc/	{
			node_desc = $NF
		}
		/Guid/	{
			node_guid = $NF
		}
	
		END	{
			if (node_type == "Channel Adapter") {
				printf("echo Could Not Read Hca firmware.\n")
				exit
			}  
	   	printf("echo Switch nports %d localport %d %s 0x%s\n",nports ,localport, node_desc, node_guid)
 			print "vendstat N", '$lid_l'
		}' | sh | aprint_err_pc;
		exit;
	}

#--------- controlling logic for scan_one function ----------
	mono=1

	while getopts u:f:pht opt
		do
		case "$opt" in
	   	u) lid="$OPTARG";;
			f) defaultfw="$OPTARG";;
			t) mono=1;;
			p) delp=1;;
			h) usage;;
			\?) usage;;
  			esac
		done

	if [[ $lid -eq -1 ]];	then
		scan_all
	fi
	scan_one $lid
}

#------------------------------------------------------------------------------------------------------------------
function sm_version {
	echo "OpenSM installed packages: "
	case ${DISTRO} in
		ubuntu) dpkg -l |grep opensm;;
		*)      rpm -qa |grep opensm;;
	esac
}


#------------------------------------------------------------------------------------------------------------------
function sm_master_is {
	[[ ${#SAQUERY} -eq 0 ]] && return

	MasterLID=(`/usr/sbin/sminfo |awk '{print $4}' `)
	echo "IB fabric SM master is: (`/usr/sbin/smpquery nodedesc $MasterLID`) "
	echo "All SMs in the fabric: "
	SMS=(`${SAQUERY} -s |grep base_lid |head -1| sed 's/\./ /g'|awk '{print $2}'`)
	SMC=${#SMS[*]}

	for ((i = 0; i< $SMC ; i++)); do
	        echo ""
		echo ${SMS[$i]}
	         /usr/sbin/smpquery nodedesc ${SMS[$i]}
	         /usr/sbin/sminfo ${SMS[$i]}
	        echo ""
	done

}


#------------------------------------------------------------------------------------------------------------------
function ib_find_bad_ports {
	[[ ${#IBNETDISCOVER} -eq 0 ]] && return
	IBPATH=${IBPATH:-/usr/sbin}
	LIST=0
	SPEED=1
	WIDTH=1
	RESET=0
	echo ""

	abort_function() {
		if [[ "XXX$*" != "XXX" ]] ; then
			echo "$*"
		fi
		exit 1
	}

	trap 'abort_function "CTRL-C hit. Aborting."' 2

	count_1x=0
	checked_ports=0
	count_deg=0

	FILE="$OUT_DIR_TMP/temp.$$"
	TEMPFILE="$OUT_DIR_TMP/tempportinfo.$$"

	echo -en "Looking For Degraded Width (1X) Links .......\t"
	echo "done "
	echo -en "Looking For Degraded Speed Links ............\t"

	cat ${OUT_DIR}/ibnetdiscover_p | grep \( | grep -e "^SW" > $FILE

	exec < $FILE
	while read LINE
		do

		checked_ports=$((checked_ports+1))

		PORT="`echo $LINE |awk '{print $(3)}'`"
		GUID="`echo $LINE |awk '{print $(4)}'`"

		$IBPATH/ibportstate -G $GUID $PORT > $TEMPFILE

		ACTIVE_WIDTH="`cat $TEMPFILE | grep LinkWidthActive | head -1 | sed 's/.\.\./ /g' | awk '{print $(NF)}'`"
		ACTIVE_SPEED="`cat $TEMPFILE | grep LinkSpeedActive | head -1 | sed 's/.\.\./ /g' | awk '{print $2}'`"
		ENABLE_SPEED="`cat $TEMPFILE | grep LinkSpeedEnabled |head -1| sed 's/\.\./ /g' | awk '{print $(NF-1)}'`"

		if [ "$ACTIVE_WIDTH" == "1X" ] ; then
			count_1x=$((count_1x + 1))
			echo "GUID:$GUID PORT:$PORT run in 1X width"
		fi

		if [ "$ACTIVE_SPEED" != "$ENABLE_SPEED" ] ; then

			PEER_ENABLE_SPEED="`cat $TEMPFILE  | grep LinkSpeedEnabled |tail -1| sed 's/\.\./ /g' | awk '{print $(NF-1)}'`"

			if [ "$ACTIVE_SPEED" != "$PEER_ENABLE_SPEED" ] ; then

				count_deg=$((count_deg+1))
				echo "GUID:$GUID PORT:$PORT run in degraded speed"
				#ibportstate -G $GUID $PORT reset >/dev/null 2>&1
	        	#ibportstate -G $GUID $PORT enable >/dev/null 2>&1
			fi
		fi
	done

	CHECKED=$checked_ports
	rm -f $FILE $TEMPFILE

	echo -e "done "
	echo ""
	echo ""
	echo "## Summary: $CHECKED ports checked" 
	echo "##	  $count_1x ports with 1x width found "
	echo "##        $count_deg ports with degraded speed found "
}

function ib_find_disabled_ports {
[[ ${#IBNETDISCOVER} -eq 0 ]] && return

IBPATH=${IBPATH:-/usr/sbin}


checked_ports=0
count_disabled=0

FILE="$OUT_DIR_TMP/temp.$$"

cat ${OUT_DIR}/ibnetdiscover_p | grep -v \( | grep -e "^SW" > $FILE

exec < $FILE
while read LINE
do

PORT="`echo $LINE |awk '{print $(3)}'`"
GUID="`echo $LINE |awk '{print $(4)}'`"

checked_ports=$((checked_ports+1))
LINK_STATE="`$IBPATH/ibportstate -G $GUID $PORT | grep PhysLinkState | head -1 | sed 's/.\.\.\./ /g' | awk '{print $NF}'`"

if [ "$LINK_STATE" == "Disabled" ] ; then
	$IBPATH/ibswitches | grep $GUID | grep -q sRB-20210G-1UP
	if [ $? == 0 -a $PORT == 24 ] ; then
		Is_10G=1
	else
		count_disabled=$((count_disabled + 1))
		echo "GUID: $GUID PORT: $PORT is disabled"
	fi
fi

done

rm $OUT_DIR_TMP/temp.$$

echo ""
echo "## Summary: $checked_ports ports checked, $count_disabled disabled ports found"
}

function ib_mc_info_show {

[[ ${#SAQUERY} -eq 0 ]] && return
nodes=$OUT_DIR_TMP/MCnodes.$$
groups=$OUT_DIR_TMP/MCgroups.$$
nodeLookup=false
groupLookup=false
MAX_GROUPS=64
version=1.2

function mgid2ip()
{
	local ip=`echo $1 | awk '
	{
		mgid=$1
		n=split(mgid, a, ":")
			if (a[2] == "401b") {
			upper=strtonum("0x" a[n-1])
			lower=strtonum("0x" a[n])
			addr=lshift(upper,16)+lower
			addr=or(addr,0xe0000000)
			a1=and(addr,0xff)
			addr=rshift(addr,8)
			a2=and(addr,0xff)
			addr=rshift(addr,8)
			a3=and(addr,0xff)
			addr=rshift(addr,8)
			a4=and(addr,0xff)
			printf("%u.%u.%u.%u", a4, a3, a2, a1) 
		}
		else {
			printf ("IPv6")
		}
	}'`
	echo -en $ip
}
		node=$OPTARG
		nodeLookup=true
		group=$OPTARG
		groupLookup=true

${SAQUERY} -m | while read line; do
	k=${line%%.*}
	v=${line##*.}
	if [ "$k" == "Mlid" ]; then
		mlid=$v
	elif [ "$k" == "MGID" ]; then
		ip=`mgid2ip $v`
	elif [ "$k" == "NodeDescription" ]; then
		if $groupLookup; then
			echo $mlid $ip $v >> $groups
		fi	
		# Ignore switches and routes
		if [[ "$v" =~ "^ISR[29]|^[42]036|^IB-to-TCP|^sRB-20210G" ]]; then
			continue
		fi
		if $nodeLookup; then
			echo $v >> $nodes
		fi
	fi
done

echo  ----------------------------------
echo  -- Number of MC groups per node --
echo  ----------------------------------
if $nodeLookup ; then
		node=sum
		# Summary how many gruops for each node
		echo "Node Name	MC Groups #"
		sort $nodes | uniq -c | while read line; do
			gcount=`echo $line | cut -d " " -f 1`
			name=`echo $line | cut -d " " -f 2-`
			echo -en "$name	--->  $gcount"
			if [ $gcount -gt $MAX_GROUPS ]; then
				echo "	-- PERFORMANCE DROP WARNING --"
			fi
			echo
		done
fi

echo -------------------------------------
echo -- Number of MC members per groups --
echo -------------------------------------

if $groupLookup ; then	

		group=sum
		#summary how many members for each MC group
		awk '{print $1, $2}' $groups | sort -k1 -n | uniq -c | awk '{printf("%s %s (%s)\n", $2, ($3=="IPv6"?"":$3), $1)}'
fi

#rm -f $nodes $groups
}

function ib_topology_viewer {
		[[ ${#IBNETDISCOVER} -eq 0 ]] && return
		swVerbose=false
		caVerbose=false

		netfile="$OUT_DIR_TMP/net.$$"
		swfile="$OUT_DIR_TMP/sw"
		swguids="$OUT_DIR_TMP/swguids"
		tempfile1="$OUT_DIR_TMP/t1"
		tempfile2="$OUT_DIR_TMP/t2"

		cat ${OUT_DIR}/ibnetdiscover_p |grep -v -i sfb > $netfile

		GUIDS=`cat $netfile | grep -e ^SW | awk '{print $4}' | uniq`


		if [ "$GUIDS" == "" ] ; then
			echo "No Switch Found"
			exit
		fi

		for guid in $GUIDS ; do  
			string="$guid..x"
			desc=`cat $netfile| grep -e ^SW | grep $string  | awk -F\' '{print $2}' | uniq`
			echo $desc==$guid >>$tempfile1
		done

		sort $tempfile1 -o $swfile
		echo "-----------------------------------"
		echo "-  Printing topollogy connection  -"
		echo "-----------------------------------"

		for guid in `awk -F== '{print $2}' $swfile`; do
			swDesc=`grep $guid $swfile | awk -F== '{print $1}'` 
			ca=`awk -vg=$guid '{if ($1 ~ "SW" && $4 ~ g && $8 ~ "CA") print $0}' $netfile >$tempfile1`
			caNumber=`cat $tempfile1 | wc -l`
			sw=`awk -vg=$guid '{if ($1 ~ "SW" && $4 ~ g && $8 ~ "SW") print $0}' $netfile >$tempfile2`
			swNumber=`cat $tempfile2 | wc -l`
			notConnected=`awk -vg=$guid '{if ($1 ~ "SW" && $4 ~ g && $7 != "-") print $0}' $netfile |wc -l`
			printf "%-82s\t" "$swDesc($guid)"
			printf "$caNumber"
			printf " HCA ports and "
			printf "$swNumber"
			printf " switch ports.\n"

			if  [[ ${swNumber} > 0 ]]; then
				if $swVerbose ; then
					cat $tempfile2
					echo ""
				fi
			fi
			if [[ ${caNumber} -gt 0 ]]; then
				if $caVerbose ; then
					cat $tempfile1
					echo ""
				fi
			fi

		done

		rm -f ${netfile} ${swfile} ${swguids} ${tempfile1} ${tempfile2}

}

function eth_tool_all_interfaces {
	for interface in ${NETDEVICES}; do
		echo -e "\nethtool $interface"
		ethtool $interface
		echo "____________"
		echo -e "\nethtool -i $interface"
		ethtool -i $interface
		echo "____________"
		echo -e "\nethtool -g $interface"
		ethtool -g $interface
		echo "____________"
		echo -e "\nethtool -a $interface"
		ethtool -a $interface
		echo "____________"
		echo -e "\nethtool -k $interface"
		ethtool -k $interface
		echo "____________"
		echo -e "\nethtool -c $interface"
		ethtool -c $interface
		echo "____________"
		echo -e "\nethtool -T $interface"
		ethtool -T $interface
		echo "____________"
		echo -e "\nethtool -S $interface"
        ethtool -S $interface
		echo "____________"
		echo "--------------------------------------------------"
	done
}

function lspci_xxxvvv {
   for interface in `lspci |grep Mellanox | awk '{print $1}'`
      do
         lspci -s $interface -xxxvvv
      done
}

function show_irq_affinity_all {
   for interface in ${NETDEVICES} mlx4 mlx5
      do
      echo -e "\nshow_irq_affinity.sh $interface"
      show_irq_affinity.sh $interface 2>/dev/null
      echo "--------------------------------------------------"
   done
}

function fw_ini_dump {
   for interface in `lspci |grep Mellanox | awk '{print $1}'`
   do
	mstflint -d $interface dc > $OUT_DIR/mstflint_$interface 
   done

}

function ibdev2pcidev {

	if [ -d /sys/class/infiniband ]
	then
		IBDEVS=$(ls /sys/class/infiniband)
		for ibdev in $IBDEVS
		do
			cd /sys/class/infiniband/$ibdev/device
			pcidev=$(pwd -P | xargs basename)
			echo "$ibdev ==> $pcidev"
		done
	else
		echo "Unable to get ibdev to pci mapping: /sys/class/infiniband does not exist."
	fi
}

#============================COMMANDS PREPARE SECTION====================
function prepare_commands {
OUTFILE=$OUT_DIR_TMP/sysinfo-temp.$$
cat > ${OUTFILE} <<'EODEOD'
date
uptime
hostname
uname -a
show_irq_affinity_all
numactl --hardware
lscpu
lspci
lspci -tv
lspci_xxxvvv
ibv_devinfo -v
fw_ini_dump
ibdev2netdev
ibdev2pcidev
ifconfig -a
route -n
service iptables status
service irqbalance status
service cpuspeed status
tuned-adm active
eth_tool_all_interfaces
ip a s
ip m s
ip n s
arp -an
netstat -anp
netstat -nlp
netstat -nr
netstat -i
chkconfig --list | sort
service --status-all
initctl list
ofed_info
ofed_info -s
ompi_info
lsmod
free
sysctl -a
ulimit -a
mount
df -lh
fdisk -l
tgtadm --version
tgtadm --mode target --op show
iscsiadm --version
iscsiadm -m session
iscsiadm -m iface
iscsiadm -m host
iscsiadm -m node
blkid -c /dev/null | sort
zz_proc_net_bonding_files
zz_sys_class_net_files
ps xfalw
EODEOD

filter_commands ${OUTFILE}

exec 10< ${OUTFILE}
i=0
while read -r commands[$i] <&10; do
    ((i++))
done
exec 10>&-
rm ${OUTFILE}
}


function prepare_FabricCommands ()
{

if [[ ${#IBNETDISCOVER} -eq 0 ]];then
	return
fi
# to sort the command requires a temp file as there are spaces in the commands.

sort > $OUT_DIR_TMP/sysinfo-FabricCommands-temp.$$ <<'EODEOD'
ibcheckerrors -nocolor
ibdiagnet
ib_find_bad_ports
ib_find_disabled_ports
ib_mc_info_show
ib_topology_viewer
ibhosts
ibswitches
ibstat
ibstatus
sminfo
sm_version
sm_status
sm_master_is
ib_switches_FW_scan
Multicast_Information
EODEOD

filter_commands ${OUT_DIR_TMP}/sysinfo-FabricCommands-temp.$$

exec 10< $OUT_DIR_TMP/sysinfo-FabricCommands-temp.$$
i=0
while read -r FabricCommands[$i] <&10; do
    ((i++))
done
exec 10>&-
rm $OUT_DIR_TMP/sysinfo-FabricCommands-temp.$$

}

function prepare_files {

files+="/proc/version /proc/modules /proc/cpuinfo /proc/mounts /proc/cmdline /proc/devices /proc/diskstats /proc/dma /proc/interrupts  /proc/meminfo /proc/partitions /proc/stat /proc/uptime /etc/resolv.conf /etc/hosts /etc/hosts.allow /etc/hosts.deny /sys/class/infiniband/*/board_id /sys/class/infiniband/*/fw_ver /sys/class/infiniband/*/hca_type /sys/class/infiniband/*/hw_rev /sys/class/infiniband/*/node_desc /sys/class/infiniband/*/node_guid /sys/class/infiniband/*/node_type /sys/class/infiniband/*/sys_image_guid /sys/devices/system/node/*/cpulist /etc/issue /proc/net/dev_mcast /etc/modprobe.conf /etc/modprobe.d/* /boot/grub/grub.conf /boot/grub/grub.cfg /etc/default/grub /boot/grub/menu.lst /etc/host.conf /etc/sysctl.conf /etc/ntp.conf /etc/tuned.conf /etc/yum.conf /etc/*release* /proc/net/igmp /proc/net/dev_mcast /proc/sys/net/ipv4/igmp_max_memberships /proc/sys/net/ipv4/igmp_max_msf"


case ${DISTRO} in
	ubuntu) files+=" /etc/network/interfaces";;
	*)      files+=" $(find /etc/sysconfig/ -name 'ifcfg*')" ;;
esac

# As our filenames don't have spaces (assumption), we can used the following to sort them:
files=$(echo $files)
xfiles=( $(echo "${files// /
}" | sort -u ) )

}

function add_to_ext_files {
	#ext_files array contains actual created files
	#ext_files_name array is the names that present in HTML file
	#these array must have the same size

	local i=${#ext_files[@]}

	ext_files[$i]=$1
	if [[  0$2 == 0 ]];then
		ext_files_name[$i]=$1
	else
		ext_files_name[$i]=$2
	fi
}

function copy_files {
	ln -s /boot/config-$(uname -r)  $OUT_DIR/config-$(uname -r)
	add_to_ext_files config-$(uname -r) "kernel config"

	if [ -e /proc/config.gz ];then
		ln -s /proc/config.gz $OUT_DIR/config.gz
	fi

	dmesg > $OUT_DIR/dmesg
	add_to_ext_files dmesg

	biosdecode  > $OUT_DIR/biosdecode
	add_to_ext_files biosdecode

	dmidecode > $OUT_DIR/dmidecode
	add_to_ext_files dmidecode

	if [ -e /var/log/messages ];then
		ln -s /var/log/messages $OUT_DIR/messages
		add_to_ext_files messages "syslog"

	elif [ -e /var/log/syslog ];then	
		ln -s /var/log/syslog $OUT_DIR/syslog
		add_to_ext_files syslog "syslog"
	fi

	if [ -e /etc/libvma.conf ];then
		ln -s /etc/libvma.conf $OUT_DIR/libvma.conf
		add_to_ext_files libvma.conf
	fi

	if [ ${#IBNETDISCOVER} -ne 0 ];then
		${IBNETDISCOVER} -p > $OUT_DIR/ibnetdiscover_p
		add_to_ext_files ibnetdiscover_p "ibnetdiscover -p"

		${IBNETDISCOVER} > $OUT_DIR/ibnetdiscover
		add_to_ext_files ibnetdiscover
	fi

	case ${DISTRO} in
		ubuntu)	dpkg --list > $OUT_DIR/pkglist ;;
		*)		rpm -qva --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH} %{SIZE}\n' | sort  > ${OUT_DIR}/pkglist ;;
	esac
	add_to_ext_files pkglist "Installed packages"
}

# ------------------------------------------------------------------------
# generating the output HTML/text file.

function generate_html {
cat <<EOF
<html><head><title>$OUT_FILE</title></head>
<body><pre>
<a name="index"></a><h1>Mellanox Technologies</h1>
<a name="index"></a><h2>Linux and OFED System Information Snapshot Utility</h2>
<a name="index"></a><h2>Version: ${VERSION}</h2>
<hr>
EOF


#=======================BEGIN OF SERVER COMMANDS SECTION ====================
echo -n '<h2>Server Commands:</h2>'
echo '<table cols="4" width="100%" border="0" bgcolor="#E0E0FF">'
echo '<tr>'
rows=$(( ${#commands[@]} / 4 + ( ( ${#commands[@]} % 4 ) ? 1 : 0 ) ))
c=0
r=0
base=1000
echo "<!-- rows: $rows Server commands: ${#commands[@]} -->"

for ((i = 0; i < ${#commands[@]} ; i++)); do
  cmd=$(( r + c * rows ))
  sec=$(( base + cmd + 1 ))
  echo "<!-- sec $sec cmd $cmd -->"
  echo "<td width=\"25%\"><a href=\"#sec$sec\">${commands[$cmd]}</a></td>"
  (( c++ ))
  if [[ 0 -eq $(( c % 4 )) ]]; then
      echo '</tr><tr>'
      (( r++ ))
      c=0
  fi
done
echo -n '</tr></table>'
basesec=$(( ${#commands[@]} + 1 ))
#=======================END OF SERVER COMMANDS SECTION =======================

#=======================BEGIN OF FABRIC DIGNASTICS SECTION ===================
if [[ ${#FabricCommands[@]} -ne 0 ]];then
echo -n '<h2>Fabric Diagnostics Information:</h2>'
echo '<table cols="4" width="100%" border="0" bgcolor="#E0E0FF"><tr>'

rows=$(( ${#FabricCommands[@]} / 4 + ( ( ${#FabricCommands[@]} % 4 ) ? 1 : 0 ) ))
c=0
r=0
base=2000
echo "<!-- rows: $rows Fabric Diagnostics Information: ${#FabricCommands[@]} ${#FabricCommands[1]}-->"

for ((i = 0; i <= ${#FabricCommands[@]} ; i++)); do
  cmd=$(( r + c * rows ))
  sec=$(( base + cmd + 1 ))
  echo "<!-- sec $sec cmd $cmd -->"
  echo "<td width=\"25%\"><a href=\"#sec$sec\">${FabricCommands[$cmd]}</a></td>"
  (( c++ ))
  if [[ 0 -eq $(( c % 4 )) ]]; then
      echo '</tr><tr>'
      (( r++ ))
      c=0
  fi
done
echo -n '</tr></table>'
basesec=$(( ${#FabricCommands[@]} + 1 ))
fi

#=======================END OF FABRIC DIGNASTICS SECTION =====================

#=======================BEGIN OF FILES SECTION ===============================
echo -n '<h2>Files:</h2>'
echo '<table cols="4" width="100%" border="0" bgcolor="#E0E0FF"><tr>'
n=1
rows=$(( ${#xfiles[@]} / 4 + ( ( ${#xfiles[@]} % 4 ) ? 1 : 0 ) ))
c=0;
r=0;
base=3000
echo "<!-- rows: $rows files: ${#xfiles[@]} -->"
for ((i = 0; i < ${#xfiles[@]}; i++)) ; do
  fno=$(( r + c * rows ))
  #sec=$(( base + fno + basesec ))
  sec=$(( base + fno + 1 ))
  echo "<td width=\"25%\"><a href=\"#sec$sec\">${xfiles[$fno]}</a></td>"
  ((c++))
  if [[ 0 -eq $(( c % 4 )) ]]; then
      echo '</tr><tr>'
      ((r++))
      c=0
  fi
done
echo '</tr></table>'

#=======================EXTERNAL FILES =====================================

echo -n '<h2>External files:</h2>'
echo '<table cols="4" width="100%" border="0" bgcolor="#E0E0FF"><tr>'
n=1
rows=$(( ${#ext_files[@]} / 6 + ( ( ${#ext_files[@]} % 6 ) ? 1 : 0 ) ))
c=0;
r=0;
base=4000
echo "<!-- rows: $rows files: ${#ext_files[@]} -->"
for ((i = 0; i < ${#ext_files[@]}; i++)) ; do
  fno=$(( r + c * rows ))
  echo "<td width=\"16%\"><a href=${ext_files[$i]}>${ext_files_name[$i]}</a></td>"
  ((c++))
  if [[ 0 -eq $(( c % 6 )) ]]; then
      echo '</tr><tr>'
      ((r++))
      c=0
  fi
done
echo '</tr></table>'

#=======================END OF FILES SECTION ===============================


echo '<a href="#systemfiles">Other system files</a>'

base=1000
sec=$(( base + 1 ))
for ((i = 0; i < ${#commands[@]} ; i++)); do
  echo -n "<a name=\"sec$sec\"></a>"
  echo -n "<small><a href=\"#sec$((sec - 1))\">[&lt;&lt;prev]</a></small> "
  echo -n "<small><a href=\"#index\">[back to index]</a></small> "
  echo "<small><a href=\"#sec$((sec + 1))\">[next>>]</a></small>"
  echo -n "<h2>${commands[$i]}</h2>"
  eval "${commands[$i]}" 2>&1 | sed 's/</\&lt;/g;s/>/\&gt;/g'
  ((sec++))
done
base=2000
sec=$(( base + 1 ))
for ((i = 0; i < ${#FabricCommands[@]} ; i++)); do
  echo -n "<a name=\"sec$sec\"></a>"
  echo -n "<small><a href=\"#sec$((sec - 1))\">[&lt;&lt;prev]</a></small> "
  echo -n "<small><a href=\"#index\">[back to index]</a></small> "
  echo "<small><a href=\"#sec$((sec + 1))\">[next>>]</a></small>"
  echo -n "<h2>${FabricCommands[$i]}</h2>"
  eval "${FabricCommands[$i]}" 2>&1 | sed 's/</\&lt;/g;s/>/\&gt;/g'
  ((sec++))
done

base=3000
sec=$(( base + 1))
for ((i = 0; i < ${#xfiles[@]}; i++)) ; do
  f="${xfiles[$i]}"
  echo -n "<a name=\"sec$sec\"></a>"
  echo -n "<small><a href=\"#sec$((sec - 1))\">[&lt;&lt;prev]</a></small> "
  echo -n "<small><a href=\"#index\">[back to index]</a></small> "
  echo "<small><a href=\"#sec$((sec + 1))\">[next>>]</a></small>"
  echo -n "<h2>$f</h2>"
  cat "$f" 2>&1 | sed 's/</\&lt;/g;s/>/\&gt;/g'
  ((sec++))
done

base=4000
sec=$(( base + 1))
echo -n "<small><a href=\"#sec$((sec - 1))\">[&lt;&lt;prev]</a></small> "
echo -n "<small><a href=\"#index\">[back to index]</a></small> "
echo "<small><a href=\"#sec$((sec + 1))\">[next>>]</a></small>"
echo -n "<h2>numa_nodes</h2>"
for f in $(find /sys | grep numa_node |grep -v uevent |sort ); do
  if [[ -f $f ]]; then
    echo -n "</h2>$f </h2>"
    cat "$f" 2>&1 | sed 's/</\&lt;/g;s/>/\&gt;/g'
    ((sec++))
  fi
done

base=5000
sec=$(( base + 1))
  echo -n '<a name="systemfiles"></a>'
  echo -n "<small><a href=\"#sec$((sec - 1))\">[&lt;&lt;prev]</a></small> "
  echo -n "<small><a href=\"#index\">[back to index]</a></small> "
  echo '<h2>System Files</h2>'
  for f in $(find /sys | grep infini |grep -v uevent |sort ) ${NETDEVICES}; do
      if [[ -f $f ]]; then
          echo "File: $f: $(cat $f | sed 's/</\&lt;/g;s/>/\&gt;/g')"
      fi
  done

  echo -n "<small><a href=\"#index\">[back to index]</a></small>"
  echo '<br></pre></body></html>'

}


prepare_commands
prepare_FabricCommands
prepare_files
copy_files

source ${DUMMY_FUNC}

if [[ -z "$HTTP_HOST" ]]; then
	( generate_html ) > $OUT_FILE 2>&1
	tar -h -czf $OUT_DIR.tgz $OUT_DIR
	ls ${OUT_DIR}* 
	[[ ${DEBUG} -ne 1 ]] && rm -rf $OUT_DIR
else
	echo "Content-type: text/html"
	echo "Cache-Control: no-cache"
	echo ""
	generate_html
fi

exit 0
