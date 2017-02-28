#!/usr/bin/python

import subprocess
import sys
import re
import tarfile
import os
import commands 
import collections
import time
import signal

try:
    import json
    json_found = True
except ImportError:
    json_found = False

###########################################################
#   SIGINT-2-Interrupt from keyboard; Handlers (Ctrl+C)

def signal_handler(signal, frame):
	if (path_is_generated == 1):
		invoke_command(['rm', '-rf', path])
	else:
		# Remove tar out file
        	invoke_command(['rm', '-rf', path+file_name+".tgz"])
 		remove_unwanted_files() 
        
	print ("\nRunning sysinfo-snapshot was halted! No out directories/files.")
	sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

###########################################################
#		General Variables

version = "3.0.6"

sys_argv = sys.argv
len_argv = len(sys.argv)

json_flag = False

# is_ib = 0 if the server is configured as IB
# is_ib != 0 if the server is configured as ETH
is_ib, ib_res = commands.getstatusoutput("which ibnetdiscover 2>/dev/null")
mlnx_card_exists = True

path_is_generated = 0

path = "/tmp/"
isFile = False

for i in range(1, len(sys.argv)-1):
	if (sys.argv[i] == '-d' or sys.argv[i] == "--dir"):
		path = sys.argv[i+1]

if (len(path) > 0):
	if (not path.endswith("/")):
		path = path + "/"
	if (os.path.isfile(path[:-1]) == True):
		isFile = True		

section_count=1
ibdiagnet_res = ""
ibdiagnet_is_invoked = False

# fw_flag = False, means not to add fw_collection commands to the out file
# fw_flag = True, means to add fw_collection commands to the out file
# fw_flag can be converted to True by running the tool with -fw or --firmware flag
fw_flag = False

#no_ib_flag = False, means to add ib commands to the out file
#no_ib_flag = True, means not to add ib commands to the out file
#no_ib_flag can be converted to True by running the tool with -no_ib flag
no_ib_flag = False

fw_ini_dump_is_string = True
mstreg_dump_is_string = True

sta, date_cmd = commands.getstatusoutput("date")
sta, date_file = commands.getstatusoutput("echo $(date '+%Y%m%d-%H%M')")

###########################################################
#		OS General Variables & Confirmation

#rpm --eval %{_vendor} 
#Ubuntu prints debian
#Redhat and CentOS prints redhat
supported_os_collection = ["redhat", "suse", "debian"]

os_st, cur_os = commands.getstatusoutput("rpm --eval %{_vendor}")

if (os_st == 0):
    	if (cur_os not in supported_os_collection):
    		print ("Stopping sysinfo-snapshot. Operating system with vendor " + cur_os + " is not supported")
             	sys.exit (1)
else:
	os_st, o_systems = commands.getstatusoutput("cat /etc/issue")

	if (os_st != 0):
		print ("Unable to distinguish operating system")
		sys.exit(1)
	o_systems = o_systems.lower()
	o_systems = o_systems.split()

	if ( ("red" in o_systems and "hat" in o_systems) or ("redhat" in o_systems) or ("centos" in o_systems) or ("fedora" in o_systems) or ("scientific" in o_systems) ):
		cur_os = "redhat"
	elif ("suse" in o_systems):
		cur_os = "suse"
	elif ( ("ubuntu" in o_systems) or ("debian" in o_systems) ):
		cur_os = "debian"
	else:
        	print ("Unable to distinguish operating system")
       		sys.exit(1)

###########################################################
#       HTML Handlers And Global Variables

fw_collection = ["itrace", "mlxmcg -d", "fw_ini_dump", "mstregdump-func"]

ib_collection = ["ibdev2netdev", "ibdev2pcidev", "ibv_devinfo -v", "yy_IB_modules_parameters"]

commands_collection = ["itrace", "mlxmcg -d", "arp -an", "free", "blkid -c /dev/null | sort", "date", "df -lh", "eth_tool_all_interfaces", "fdisk -l", "fw_ini_dump", "hostname", "ibdev2netdev", "ibdev2pcidev", "ibv_devinfo -v", "ifconfig -a", "initctl list", "ip a s", "ip m s", "ip n s", "iscsiadm --version", "iscsiadm -m host", "iscsiadm -m iface", "iscsiadm -m node", "iscsiadm -m session", "lscpu", "lsmod", "lspci", "lspci -tv", "lspci_xxxvvv", "mount", "mstregdump-func", "netstat -anp", "netstat -i", "netstat -nlp", "netstat -nr", "numactl --hardware", "ofed_info", "ofed_info -s", "ompi_info", "ps xfalw", "route -n", "service --status-all", "service cpuspeed status", "service iptables status", "service irqbalance status", "show_irq_affinity_all", "sysctl -a", "tgtadm --mode target --op show", "tgtadm --version", "tuned-adm active", "ulimit -a", "uname -a", "uptime", "yy_MLX4_modules_parameters", "yy_IB_modules_parameters", "zz_proc_net_bonding_files", "zz_sys_class_net_files"]

if (cur_os != "debian"):
	commands_collection.extend(["chkconfig --list | sort"])

available_commands_collection = []


fabric_commands_collection = ["ibdiagnet", "ib_find_bad_ports", "ib_find_disabled_ports", "ib_mc_info_show", "ib_topology_viewer", "ibhosts", "ibswitches", "ibstat", "ibstatus", "sminfo", "sm_status", "sm_version", "sm_master_is", "ib_switches_FW_scan", "Multicast_Information"]

available_fabric_commands_collection = []


internal_files_collection = ["/etc/security/limits.conf", "/etc/infiniband/connectx.conf", "/boot/grub/grub.cfg", "/boot/grub/grub.conf", "/boot/grub/menu.lst", "/etc/default/grub", "/etc/host.conf", "/etc/hosts", "/etc/hosts.allow", "/etc/hosts.deny", "/etc/issue", "/etc/modprobe.conf", "/etc/ntp.conf", "/etc/resolv.conf", "/etc/sysctl.conf", "/etc/tuned.conf", "/etc/yum.conf", "/proc/cmdline", "/proc/cpuinfo", "/proc/devices", "/proc/diskstats", "/proc/dma", "/proc/interrupts", "/proc/meminfo", "/proc/modules", "/proc/mounts", "/proc/net/dev_mcast", "/proc/net/igmp", "/proc/partitions", "/proc/stat", "/proc/sys/net/ipv4/igmp_max_memberships", "/proc/sys/net/ipv4/igmp_max_msf", "/proc/uptime", "/proc/version"]

if (cur_os == "debian"):
	internal_files_collection.extend(["/etc/network/interfaces"])

available_internal_files_collection = []


external_files_collection = [["kernel config", "/boot/config-$(uname -r)"], ["config.gz", "/proc/config.gz"], ["dmesg", "dmesg"], ["biosdecode", "biosdecode"], ["dmidecode", "dmidecode"], ["syslog", "/var/log/"], ["libvma.conf", "/etc/libvma.conf"], ["ibnetdiscover", ""], ["Installed packages", ""]]

available_external_files_collection = []


###########################################################
#	JSON Handlers And Global Variables

# define and initialize dictionaries hierarchy
server_commands_dict = {}
fabric_commands_dict = {}
files_dict = {}
external_files_dict = {}
other_system_files_dict = {}

l3_dict = {}

l3_dict[str(section_count) + ". Server Commands: "] =  server_commands_dict
section_count += 1
if (is_ib == 0):
	l3_dict[str(section_count) + ". Fabric Diagnostics Information: "] = fabric_commands_dict
	section_count += 1
l3_dict[str(section_count) + ". Internal Files: "] = files_dict
section_count += 1
l3_dict[str(section_count) + ". External Files: "] = external_files_dict
section_count += 1
l3_dict[str(section_count) + ". Other System Files: "] = other_system_files_dict

l2_dict = {}
l2_dict["Version: " + version] = l3_dict

l1_dict = {}
if (is_ib == 0):
	l1_dict['Mellanox Technologies - Linux Infiniband Driver System Information Snapshot Utility'] = l2_dict
else:
	l1_dict['Mellanox Technologies - Linux Ethernet Driver System Information Snapshot Utility'] = l2_dict


###########################################################

def invoke_command(str):
        p = subprocess.Popen(str, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        return out


#**********************************************************
#		eth_tool_all_interfaces Handlers

def eth_tool_all_interfaces_handler():
	if (os.path.exists("/sys/class/net") == False):
		return "No Net Devices"

	st, net_devices = commands.getstatusoutput("ls /sys/class/net")	
	net_devices = net_devices.split()

	res = ""
	options = ["", "-i", "-g", "-a", "-k", "-c", "-T", "-S", "--show-priv-flags"]
	for interface in net_devices:
		if (interface == "lo" or interface == "bonding_masters"):
			continue
		for option in options:
                        st, ethtool_interface = commands.getstatusoutput("ethtool " + option + " " + interface)
			if (st == 0):	
				res += "ethtool " + option + " " + interface + "\n"
				res += ethtool_interface
				res += "\n____________\n\n"
		res += "--------------------------------------------------\n\n"
	
	return res

#**********************************************************
#		fw_ini_dump Handlers

def fw_ini_dump_handler():
	st, res = commands.getstatusoutput(
		"for interface in `lspci |grep Mellanox | awk '{print $1}'`; " + 
		"do " +
			"mstflint -d $interface dc > " + path + file_name  + "/mstflint_$interface; echo yes;"
		"done")
	if (st == 0 and res == ""):
		return "NULL_1"
	if (st == 0):
		return res
	return "NULL_2"

def add_fw_ini_dump_links():
	file_link = {}
       	for file in os.listdir(path + file_name):
        	if (file.startswith("mstflint")):
               		#filtered_file_name = file.translate(None, ':.')
			filtered_file_name = file.replace(":", "").replace(".", "")
			os.rename(path+file_name+"/"+file, path+file_name+"/"+filtered_file_name)
			file_link[file] = "<td><a href=" + filtered_file_name + ">" + file + "</a></td>"
	return file_link


#**********************************************************
#               ibdev2pcidev Handlers

def ibdev2pcidev_handler():
	script = "if [ -d /sys/class/infiniband ]; then IBDEVS=$(ls /sys/class/infiniband); for ibdev in $IBDEVS; do cd /sys/class/infiniband/$ibdev/device; pcidev=$(pwd -P | xargs basename); echo $ibdev '==>' $pcidev; done; else echo Unable to get ibdev to pci mapping: /sys/class/infiniband does not exist.; fi"
	st, res = commands.getstatusoutput(script)
        return res

#**********************************************************
#		itrace Handlers

def itrace_handler():
	mst_st, mst = commands.getstatusoutput("mst start")
        if (mst_st != 0):
                return "MFT is not installed, please install MFT and try again."
        dev_st, all_devices = commands.getstatusoutput("ls /dev/mst")
        if (dev_st != 0):
                return "There are no devices"
        devices = all_devices.split()
        if (len(devices) < 1):
                return "There are no devices"

	options = ["sx0", "sx1", "rx0", "rx1", "qpc"]

	itrace = ""

        for device in devices:
                if (itrace != ""):
                        itrace += "\n---------------------------------------------------------------\n\n"
                flag = 0
		for option in options:
			if (flag != 0):
				itrace += "\n****************************************\n\n"
			itrace += "itrace -d /dev/mst/" + device + " --noddr " + option + "\n\n"
			itrace_st, itrace_device_option = commands.getstatusoutput("itrace -d /dev/mst/" + device + " --noddr " + option)
			itrace += itrace_device_option + "\n"
			flag = 1
        return itrace


#**********************************************************
#               lspci_xxxvvv Handlers

def lspci_xxxvvv_handler():
        st, res = commands.getstatusoutput(
                                "for interface in `lspci |grep Mellanox | awk '{print $1}'`; " +
                                "do " +
                                        "lspci -s $interface -xxxvvv; " +
                                "done")
	if (st == 0 and res == ""):
		return "There are no Mellanox cards"        
	if (st == 0):
		return res
	return "Exception was raised while running command."
	
#**********************************************************
#		mlxmcg -d <device> Handlers

def mlxmcg_d_handler():
	mst_st, mst = commands.getstatusoutput("mst start")
	if (mst_st != 0):
		return "MFT is not installed, please install MFT and try again."
	dev_st, all_devices = commands.getstatusoutput("ls /dev/mst")
	if (dev_st != 0):
		return "There are no devices"
	devices = all_devices.split()
	if (len(devices) < 1):
		return "There are no devices"

	mlxmcg = ""
	for device in devices:
		if (mlxmcg != ""):
			mlxmcg += "\n\n-------------------------------------------------------------\n\n"
		mlxmcg += "mlxmcg -d /dev/mst/" + device +"\n\n"
		mlx_st, mlxmcg_device = commands.getstatusoutput("mlxmcg -d /dev/mst/" + device)
                mlxmcg += mlxmcg_device
        return mlxmcg
		

#**********************************************************
#		mstregdump-func Handlers

def mstregdump_func_handler():
	sleep_period = "10"
	st, res = commands.getstatusoutput("for interface in `lspci |grep Mellanox | awk '{print $1}'`; do  echo yes; for instance in 1 2 3; do temp='_'; temp=$interface$temp$instance; mstregdump $interface  > " + path + file_name + "/mstregdump_$temp; sleep " + sleep_period + "; done; done")
	
	if (st == 0 and res == ""):
		return "NULL_1"
	if (st == 0):
		return res
	return "NULL_2"

def add_mstregdump_func_links():
        mstregdump_link = {}
        for file in os.listdir(path + file_name):
                if (file.startswith("mstregdump")):
                        #filtered_file_name = file.translate(None, ':.')
                        filtered_file_name = file.replace(":", "").replace(".", "")
			os.rename(path+file_name+"/"+file, path+file_name+"/"+filtered_file_name)
                        mstregdump_link[file] = "<td><a href=" + filtered_file_name + ">" + file + "</a></td>"
	return mstregdump_link


#**********************************************************
#		show_irq_affinity_all Handlers

def show_irq_affinity_all_handler():	
        if (os.path.exists("/sys/class/net") == False):
                return "No Net Devices"

        st, net_devices = commands.getstatusoutput("ls /sys/class/net")
        net_devices += " mlx4 mlx5"
	net_devices = net_devices.split()
	
	res = ""
        for interface in net_devices:
		if (interface == "lo" or interface == "bonding_masters"):
                        continue
                res += "show_irq_affinity.sh " + interface + "\n"
		st, show_irq_affinity = commands.getstatusoutput("show_irq_affinity.sh " + interface + " 2>/dev/null")
		
		if (show_irq_affinity != ""):
			res += show_irq_affinity
		else:
			res += "Interface " + interface + " does not exist"
		res += "\n\n--------------------------------------------------\n\n"

	return res

#----------------------------------------------------------
#		Server Commands Dictionary Handler

col_count=1

iscsiadm_st, iscsiadm_res = commands.getstatusoutput("iscsiadm --version")

def add_command_if_exists(command):
	if ( (fw_flag == False) and (command in fw_collection) ):
		return	
	if ( (no_ib_flag == True) and (command in ib_collection) ):
		return
	print_err_flag = 1 
		
	# invoke command reguarly if exists or redirect to the corresponding function
	if (command == "date"):
		result = date_cmd
		status = 0
		print_err_flag = 0
	elif (command == "eth_tool_all_interfaces"):
		result = eth_tool_all_interfaces_handler()
		status = 0
		print_err_flag = 0
        elif (command == "fw_ini_dump"):
		result = fw_ini_dump_handler()
		if (result == "NULL_1"):
			result = "There are no Mellanox cards."
                elif (result == "NULL_2"):
			result = "Exception was raised while running the command"
                else:
			result = add_fw_ini_dump_links()
			global fw_ini_dump_is_string
			fw_ini_dump_is_string = False
		status = 0
		print_err_flag = 0
	elif (command == "ibdev2pcidev"):
                result = ibdev2pcidev_handler()
		status = 0
		print_err_flag = 0
	elif (command == "itrace"):
		result = itrace_handler()
		status = 0
		print_err_flag = 0
	elif (command == "lspci_xxxvvv"):
        	result = lspci_xxxvvv_handler()
		status = 0
		print_err_flag = 0
	elif (command == "mlxmcg -d"):
		result = mlxmcg_d_handler()
		status = 0
		print_err_flag = 0
	elif (command == "mstregdump-func"):
		result = mstregdump_func_handler()
		if (result == "NULL_1"):
			result = "There are no Mellanox cards."
		elif (result == "NULL_2"):
			result = "Exception was raised while running the command"
		else:
			result = add_mstregdump_func_links()
			global mstreg_dump_is_string
			mstreg_dump_is_string = False
		status = 0
		print_err_flag = 0
	elif (command == "show_irq_affinity_all"):
		result = show_irq_affinity_all_handler()
		status = 0	
		print_err_flag = 0
	elif (command == "yy_MLX4_modules_parameters"):
		st, result = commands.getstatusoutput("awk '{ print FILENAME " + '"' + "=" + '"' + " $0  }' /sys/module/mlx4_*/parameters/*")		
		status = 0
	elif (command == "yy_IB_modules_parameters"):
		st , result = commands.getstatusoutput("if [ -d /sys/class/infiniband ]; then awk '{ print FILENAME " + '"' + " = " + '"' + " $0  }' /sys/module/ib*/parameters/*; else echo Unable to get ib modules params : /sys/class/infiniband does not exist.; fi")
		status = 0
	elif (command == "zz_proc_net_bonding_files"):
            	status, result = commands.getstatusoutput("modprobe bonding; find /proc/net/bonding/ |xargs grep ^")
		if (is_ib == 0):
			status=0
			print_err_flag=0
		else:
			print_err_flag = 1
			status = 1
	elif (command == "zz_sys_class_net_files"):
                status, result = commands.getstatusoutput("modprobe bonding; find /sys/class/net/ |xargs grep ^")
		if (is_ib == 0):
			status=0
			print_err_flag=0
		else:
			print_err_flag = 1
			status = 1
	else:
		# invoking regular command
		status, result = commands.getstatusoutput(command)
	
	# if iscsiadm --version command exists, add all isciadm commands to the available ones
	if (iscsiadm_st == 0 and command.startswith("iscsiadm")):
		status = 0

	# add command to server commands dictionaty only if exists
	if ((status == 0) or (command.startswith("service"))):
		server_commands_dict[command] = result
		available_commands_collection.append(command)
	else:
		if (print_err_flag == 1):
			f = open(path+file_name+"/dummy_functions", 'a')
                	f.write("The full command is: " + command + "\n")
			f.write(result)
                	f.write("\n\n")
			f.close()

#----------------------------------------------------------
#		Fabric Commands Dictionary Handler

def multicast_information_handler():
	st_saquery, SAQUERY = commands.getstatusoutput("`which saquery 2>/dev/null`")
        if (st_saquery != 0):
      		return "which saquery: is not found"

	st, saquery_g = commands.getstatusoutput("`which saquery 2>/dev/null` -g")
	if (st != 0):
		return "which saquery -g: is not found"

	res = "MLIDs list: \n" + saquery_g + "\n\nMLIDs members for each multicast group:"
		
	st, MLIDS = commands.getstatusoutput("saquery -g | grep -i Mlid | sed 's/\./ /g'|awk '{print $2}' | sort | uniq")
	if (st != 0):
		return "which saquery -g: is not found"
	MLIDS = MLIDS.split()	

        for MLID in MLIDS:
                st, saquery_mlid = commands.getstatusoutput("SAQUERY=`which saquery 2>/dev/null`; ${SAQUERY} -m " + MLID)
                res += "\nMembers of MLID " + MLID + " group:\n" + saquery_mlid + "\n============================================================"
	res += "\n"	
	return res
	
def ib_find_bad_ports_handler():
	if (is_ib != 0):
                return "No ibnetdiscover"

	if (cur_os != "debian"):
		st, res = commands.getstatusoutput("IBNETDISCOVER=`which ibnetdiscover 2>/dev/null`; if ! [[ ${#IBNETDISCOVER} -eq 0 ]]; then IBPATH=${IBPATH:-/usr/sbin}; LIST=0; SPEED=1; WIDTH=1; RESET=0; echo "+'"'+'"'+"; abort_function() { if [[ "+'"'+"XXX$*"+'"'+" != "+'"'+"XXX"+'"'+" ]] ; then echo "+'"'+"$*"+'"'+"; fi; exit 1;}; trap 'abort_function "+'"'+"CTRL-C hit. Aborting."+'"'+"' 2; count_1x=0; checked_ports=0; count_deg=0; FILE=" + path+file_name+'"'+"/tmp/temp.$$"+'"'+"; TEMPFILE="+path+file_name+'"'+"/tmp/tempportinfo.$$"+'"'+"; echo -en "+'"'+"Looking For Degraded Width (1X) Links .......\t"+'"'+"; echo "+'"'+"done "+'"'+"; echo -en "+'"'+"Looking For Degraded Speed Links ............\t"+'"'+"; cat " + path+file_name + "/ibnetdiscover_p | grep \( | grep -e "+'"'+"^SW"+'"'+" > $FILE; exec < $FILE; while read LINE; do checked_ports=$((checked_ports+1)); PORT="+'"'+"`echo $LINE |awk '{print $(3)}'`"+'"'+"; GUID="+'"'+"`echo $LINE |awk '{print $(4)}'`"+'"'+"; $IBPATH/ibportstate -G $GUID $PORT > $TEMPFILE; ACTIVE_WIDTH="+'"'+"`cat $TEMPFILE | grep LinkWidthActive | head -1 | sed 's/.\.\./ /g' | awk '{print $(NF)}'`"+'"'+"; ACTIVE_SPEED="+'"'+"`cat $TEMPFILE | grep LinkSpeedActive | head -1 | sed 's/.\.\./ /g' | awk '{print $2}'`"+'"'+"; ENABLE_SPEED="+'"'+"`cat $TEMPFILE | grep LinkSpeedEnabled |head -1| sed 's/\.\./ /g' | awk '{print $(NF-1)}'`"+'"'+"; if [ "+'"'+"$ACTIVE_WIDTH"+'"'+" == "+'"'+"1X"+'"'+" ] ; then count_1x=$((count_1x + 1)); echo "+'"'+"GUID:$GUID PORT:$PORT run in 1X width"+'"'+"; fi; if [ "+'"'+"$ACTIVE_SPEED"+'"'+" != "+'"'+"$ENABLE_SPEED"+'"'+" ] ; then PEER_ENABLE_SPEED="+'"'+"`cat $TEMPFILE  | grep LinkSpeedEnabled |tail -1| sed 's/\.\./ /g' | awk '{print $(NF-1)}'`"+'"'+"; if [ "+'"'+"$ACTIVE_SPEED"+'"'+" != "+'"'+"$PEER_ENABLE_SPEED"+'"'+" ] ; then count_deg=$((count_deg+1)); echo "+'"'+"GUID:$GUID PORT:$PORT run in degraded speed"+'"'+"; fi; fi; done; CHECKED=$checked_ports; rm -f $FILE $TEMPFILE; echo -e "+'"'+"done "+'"'+"; echo "+'"'+'"'+"; echo "+'"'+'"'+"; echo "+'"'+"## Summary: $CHECKED ports checked"+'"'+"; echo "+'"'+"##	  $count_1x ports with 1x width found "+'"'+"; echo "+'"'+"##        $count_deg ports with degraded speed found "+'"'+"; fi")
		return res
	
	count_1x = 0
	checked_ports = 0
	count_deg = 0
	
	res = "Looking For Degraded Width (1X) Links .......\tdone\n\nlooking For Degraded Speed Links ............\n"	

	st, ibnetdiscover_p = commands.getstatusoutput("cat " + path+file_name + "/ibnetdiscover_p | grep \( | grep -e "+'"'+"^SW"+'"')
	ibnetdiscover_p = ibnetdiscover_p.split("\n")
	
	for line in ibnetdiscover_p:
		checked_ports += 1
		line = line.split()
		if ( len(line) <= 3):
			continue
		PORT = line[2]
                GUID = line[3]

		#st, GUID = commands.getstatusoutput("echo " + line + " | awk '{print $(4)}'")
		st, ACTIVE_WIDTH = commands.getstatusoutput("/usr/sbin/ibportstate -G " + GUID + " " + PORT + " | grep LinkWidthActive | head -1 | sed 's/.\.\./ /g' | awk '{print $(NF)}'" )	
		st, ACTIVE_SPEED = commands.getstatusoutput("/usr/sbin/ibportstate -G " + GUID + " " + PORT + " | grep LinkSpeedActive | head -1 | sed 's/.\.\./ /g' | awk '{print $2}'")
		st, ENABLE_SPEED = commands.getstatusoutput("/usr/sbin/ibportstate -G " + GUID + " " + PORT + " | grep LinkSpeedEnabled |head -1 | sed 's/\.\./ /g' | awk '{print $(NF-1)}'")
		
		if (ACTIVE_WIDTH == "1X"):
			count_1x += 1	
			res += "GUID:" + GUID + " PORT:" + PORT + " run in 1X width\n"
		
		if (ACTIVE_SPEED != ENABLE_SPEED):
			st, PEER_ENABLED_SPEED = commands.getstatusoutput("/usr/sbin/ibportstate -G " + GUID + " " + PORT + " | grep LinkSpeedEnabled |tail -1| sed 's/\.\./ /g' | awk '{print $(NF-1)}'")
			if (ACTIVE_SPEED != PEER_ENABLED_SPEED):
				count_deg += 1
				res += "GUID:" + GUID + " PORT:" + PORT + " runs in degraded speed\n"

	res += "done\n\n## Summary: " + str(checked_ports) + " ports checked\n"
	res += "##          " + str(count_1x) + " ports with 1x width found\n"
	res += "##          " + str(count_deg) + " ports with degraded speed found\n"
	return res	


def ib_find_disabled_ports_handler():	
	if (is_ib != 0):
		return "No ibnetdiscover"	
		
	checked_ports = 0
	count_disabled = 0

	st, ibnetdiscover_p = commands.getstatusoutput("cat " + path+file_name + "/ibnetdiscover_p | grep -v \( | grep -e "+'"'+"^SW"+'"')

	ibnetdiscover_p = ibnetdiscover_p.split("\n")
	res = ""
	for line in ibnetdiscover_p:
		st, PORT = commands.getstatusoutput("echo " + line + " | awk '{print $(3)}'")
		st, GUID = commands.getstatusoutput("echo " + line + " | awk '{print $(4)}'")
		checked_ports += 1
		st, LINK_STATE = commands.getstatusoutput("/usr/sbin/ibportstate -G " + GUID + " " + PORT + " | grep PhysLinkState | head -1 | sed 's/.\.\.\./ /g' | awk '{print $NF}'")
		
		if (LINK_STATE == "Disabled"):
			st1, res1 = commands.getstatusoutput("/usr/sbin/ibswitches")
			if (st1 == 0):
				res1 = res1.split("\n")
				res2 = ""
				for row in res1:
					if (row.lower().startswith("switch") == False):
						continue
					res2 += row + "\n"
				st, res = commands.getstatusoutput("echo " + res2 + " | grep " + GUID + " | grep -q sRB-20210G-1UP")
				if not (st == 0 and PORT == 24):
					count_disabled += 1
					res += "GUID: " + GUID + " PORT: " + PORT + " is disabled\n"

	res += "## Summary: " + str(checked_ports) + " ports checked, " + str(count_disabled) + " disabled ports found\n" 
	return res


def calc_IP(MGID):
	st, IP = commands.getstatusoutput("ip=`echo " + MGID + " | awk ' { mgid=$1; n=split(mgid, a, "+'"'+":"+'"'+"); if (a[2] == "+'"'+"401b"+'"'+") {upper=strtonum("+'"'+"0x"+'"'+" a[n-1]); lower=strtonum("+'"'+"0x"+'"'+" a[n]); addr=lshift(upper,16)+lower; addr=or(addr,0xe0000000); a1=and(addr,0xff); addr=rshift(addr,8); a2=and(addr,0xff); addr=rshift(addr,8); a3=and(addr,0xff); addr=rshift(addr,8); a4=and(addr,0xff); printf("+'"'+"%u.%u.%u.%u"+'"'+", a4, a3, a2, a1); } else { printf ("+'"'+"<IPv6>"+'"'+"); }; }'`; echo $ip")
	if (st == 0):
		return IP
	return "<N/A>"

def ib_mc_info_show_handler():
	st_saquery, SAQUERY = commands.getstatusoutput("`which saquery 2>/dev/null`")
        if (st_saquery != 0):
                return "which saquery: is not found"
	
	MAX_GROUPS=64
	
	st, saquery = commands.getstatusoutput("SAQUERY=`which saquery 2>/dev/null`; ${SAQUERY} -m")
	saquery = saquery.split("\n")
	
	res  = "------------------------------------------------------\n"
	res += "------------ Number of MC groups per node ------------\n"
	res += "------------------------------------------------------\n"

	tmp = "Node Name"
        res += tmp.ljust(41, ' ')
        res += " MC Groups #\n"

	Mlid_val = ""
	MGIP_val = ""
	IP = ""
	
	nodes_dict = {}
	nodes_collection = []

	mlids_collection = []
	mlids_ip_dict = {}
	mlids_count_dict = {}
	
	for index in range(0, len(saquery)):
		if "Mlid" in saquery[index]:
			Mlid_val = saquery[index].split('.')[-1]
			if not Mlid_val in mlids_collection:
				mlids_collection.extend([Mlid_val])
				mlids_ip_dict[Mlid_val] = IP
				mlids_count_dict[Mlid_val] = 1
			else:
				mlids_ip_dict[Mlid_val] = "<N/A>"
				mlids_count_dict[Mlid_val] += 1
		elif "MGID" in saquery[index]:
			MGID_val = saquery[index].split('.')[-1]			
			IP = calc_IP(MGID_val)
		elif "NodeDescription" in saquery[index]:
			NodeDescription = saquery[index].split('.')[-1]
			if not NodeDescription in nodes_collection:
				nodes_collection.extend([NodeDescription])
				nodes_dict[NodeDescription] = 1
			else:
				nodes_dict[NodeDescription] += 1

	nodes_collection.sort()
	for i in range(0, len(nodes_collection)):
		node = nodes_collection[i]
		node_count = nodes_dict[node]
		res += node.ljust(41, ' ')
		res += " --->  " + str(node_count)
		if (node_count > MAX_GROUPS):
			res += "\t -- PERFORMANCE DROP WARNING --" 
		res += "\n"
			
	
	res += "\n------------------------------------------------------\n"
        res += "----------- Number of MC members per group -----------\n"
        res += "------------------------------------------------------\n"

	mlids_collection.sort()
	for i in range(0, len(mlids_collection)):
		mlid = mlids_collection[i]
		res += mlid.ljust(20, ' ')
		mlid_ip = mlids_ip_dict[mlid]
		res += mlid_ip.ljust(30, ' ')
		res += "(" + str(mlids_count_dict[mlid]) + ")\n"

	return res


def add_spaces(txt):
	tmp = ""
	for i in range(20-len(txt)):
		tmp += " "
	return tmp

def represents_Int(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False

def represents_Int_base_16(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def ib_switches_FW_scan_handler():
	st_ibs, ibswitches = commands.getstatusoutput("ibswitches")
	if (st_ibs != 0):
		return "Failed to run 'ibswitches' command"
	
	ibswitches = clean_ibnodes(ibswitches, "switch")	
	
	st_ibs, ib_switches_num = commands.getstatusoutput("ibswitches | wc -l")
	if (st_ibs != 0):
		return "Failed to run 'ibswitches | wc -l' command"
	
	ib_switches_num = ib_switches_num.split("\n")[-1]
	if (represents_Int(ib_switches_num) == True):
		switches_num = int(ib_switches_num)	
	else:
		return "Failed to count ibswitches"

	res = "Scan Fabric\n---------------------------------------------------------------------------------------------------------------------------------------\n"
	res += "Switch_GUID"
	res += add_spaces("Switch_GUID")
	res += "LID"
	res += add_spaces("LID")
 	res += "Device_ID"
	res += add_spaces("Device_ID")
	res += "PSID"
	res += add_spaces("PSID")
	res += "FW_Version"
	res += add_spaces("FW_Version")
	res += "FW_Build_ID"
	res += add_spaces("FW_Build_ID")
	res += "HW_Dev_Rev"
	res += "\n"

	for i in range(1, switches_num+1):
		lid = "N/A"
		line_st, lid = commands.getstatusoutput("ibswitches | sed -n " + str(i) + "p | grep -Po '(lid\s)\K[^\s]*'") 
		if (line_st == 0):
			lid = lid.split("\n")[-1]
	
		guid = "N/A"
		line_st, guid = commands.getstatusoutput("ibswitches | sed -n " + str(i) + "p | grep -Po '(:\s)\K[^\s]*'")           
		if (line_st == 0):
			guid = guid.split("\n")[-1]             	

		res += guid 
		res += add_spaces(guid)
		res += lid 
		res += add_spaces(lid)
		
		tmp_st, row = commands.getstatusoutput("awk '/START_NODES_INFO/,/END_NODES_INFO/' " + path+file_name+"/ibdiagnet/ibdiagnet2.db_csv | grep ^" + guid )		
	
		splt_row = re.split("[" + re.escape(",\n") + "]", row)

		if ( 1 < len(splt_row) and (represents_Int_base_16(splt_row[1]) == True) ):  
			device_id = str(int(splt_row[1], 16))
		else:
			device_id = "N/A"
                res += device_id
                res += add_spaces(device_id)
		       
		if (12 < len(splt_row) ):
			fw_psid = splt_row[12]
		else:
			fw_psid = "N/A"
                res += fw_psid
                res += add_spaces(fw_psid)
	
		if (16 < len(splt_row) and (represents_Int_base_16(splt_row[14]) == True) and (represents_Int_base_16(splt_row[15]) == True)
				 and (represents_Int_base_16(splt_row[16]) == True) ):
                	fw_version = str(int(splt_row[14], 16))+"."+str(int(splt_row[15], 16))+"."+str(int(splt_row[16], 16))
        	else:
			fw_version = "N/A"
		res += fw_version
       		res += add_spaces(fw_version)

		if (7 < len(splt_row) and (represents_Int_base_16(splt_row[7]) == True) ):
             		fw_build_id = str(int(splt_row[7], 16))
		else:
			fw_build_id = "N/A"
           	res += fw_build_id
		res += add_spaces(fw_build_id)

		if (2 < len(splt_row) and (represents_Int_base_16(splt_row[2]) == True) ):
                	hw_dev_rev = str(int(splt_row[2],16))
                else:
			hw_dev_rev = "N/A"
		res += hw_dev_rev

		res += "\n" 
	
	res += "---------------------------------------------------------------------------------------------------------------------------------------\n" 	
	
	return res


def ib_topology_viewer_handler():
        if (is_ib != 0):
                return "No ibnetdiscover"
		
	st, GUIDS = commands.getstatusoutput("ibnetdiscover -p | grep -v -i sfb | grep -e ^SW | awk '{print $4}' | uniq")

	if (GUIDS == ""):
	 	return "No Switches Found"

	GUIDS = GUIDS.split("\n")
	GUIDS.sort()
	
	res  = "-----------------------------------\n"
	res += "-  Printing topollogy connection  -\n"
	res += "-----------------------------------\n\n"
	
	for index in range(0, len(GUIDS)):
		if ( len(GUIDS[index].split()) > 1 ):
			continue	
		
		st, desc = commands.getstatusoutput("ibnetdiscover -p | grep -v -i sfb | grep -e ^SW | grep " + GUIDS[index] + "..x")

		if (st == 0):
			HCA_ports_count = 0
			switch_ports_count = 0
			desc = desc.split("'")[1]
			
			st, guid_ports = commands.getstatusoutput("ibnetdiscover -p | grep -v -i sfb | grep -e ^SW | grep " + GUIDS[index] + "..x | awk '{print $8}'")
			if (st == 0):
				guid_ports = guid_ports.split("\n")
				for guid_port in guid_ports:
					if (guid_port == "CA"):
						HCA_ports_count += 1
					elif (guid_port == "SW"):
						switch_ports_count += 1					
			res += desc.ljust(30, ' ')
			tmp = "(" + GUIDS[index] + ")"
			res += tmp.ljust(30, ' ');
			res += str(HCA_ports_count) + " HCA ports and " + str(switch_ports_count) + " switch ports.\n"
	return res


def sm_master_is_handler():	
	st_saquery, SAQUERY = commands.getstatusoutput("`which saquery 2>/dev/null`")
	if (st_saquery != 0):
 		return "which saquery: is not found"

	st, MasterLID = commands.getstatusoutput("/usr/sbin/sminfo | awk '{print $4}'")	
	st, all_sms = commands.getstatusoutput("/usr/sbin/smpquery nodedesc " + MasterLID)
	
	res = "IB fabric SM master is: (" + all_sms + ")\nAll SMs in the fabric: "
	
	st, SMS = commands.getstatusoutput("SAQUERY=`which saquery 2>/dev/null`; ${SAQUERY} -s |grep base_lid |head -1| sed 's/\./ /g'|awk '{print $2}'")
	SMS = set(SMS.split())
	
	for SM in SMS:
		st, smquery_nodedesc = commands.getstatusoutput("/usr/sbin/smpquery nodedesc " + SM)
		st, sminfo = commands.getstatusoutput("/usr/sbin/sminfo " + SM)
		res += "\n\nSM: " + SM + "\n" + smquery_nodedesc + "\n" + sminfo

	return res


def sm_status_handler():	
	SmActivity_1=0
	NoSM=2 
	res = ""

	for lo in range(0,4): 
		commands.getstatusoutput("sleep 3")
		st, SmActivity = commands.getstatusoutput("sminfo |awk '{ print $10 }'")
		st, c_time = commands.getstatusoutput("date +%T")
		res += "SM activity on " + c_time + " is " + SmActivity + "\n"
		if (represents_Int(SmActivity) == True):	
			if (int(SmActivity) == SmActivity_1):
				NoSM = 1
			else:
				NoSM = 0	
			SmActivity_1=int(SmActivity)		
		else:
			NoSM=2
	if (NoSM == 0):
		res += "\nMaster SM activity is in progress. SM is alive."
	else:
		res += "\nALERT: Master SM activity has not make any progress. CHECK master SM!"

	return res


def sm_version_handler():	
	if (cur_os != "debian"):
		st, res = commands.getstatusoutput("echo OpenSM installed packages: ; rpm -qa | grep opensm")
	else:
		st, res = commands.getstatusoutput("echo OpenSM installed packages: ; dpkg -l | grep opensm")
	return res

def ibdiagnet_handler():
	if (ibdiagnet_is_invoked == False):
		global ibdiagnet_res
		if (os.path.exists(path+file_name+"/ibdiagnet") == False):
			os.mkdir(path+file_name+"/ibdiagnet")
		st, ibdiagnet_res = commands.getstatusoutput("ibdiagnet -o " + path+file_name+"/ibdiagnet")


def clean_ibnodes(ibnodes, start_string):
	res = ""
	ibnodes = ibnodes.split("\n")
        for ibnode in ibnodes:
                if (ibnode.lower().startswith(start_string) == True):
                        res += ibnode + "\n"
	return res 


def add_fabric_command_if_exists(command):
	global ibdiagnet_is_invoked 
	if (command == "Multicast_Information"):
		result = multicast_information_handler()
	elif (command == "ib_find_bad_ports"):
		result = ib_find_bad_ports_handler()
	elif (command == "ib_find_disabled_ports"):
		result = ib_find_disabled_ports_handler()
	elif (command == "ib_mc_info_show"):
		result = ib_mc_info_show_handler()
	elif (command == "ib_switches_FW_scan"):
		if (ibdiagnet_is_invoked == False):
			# ib_switches_FW_scan uses ibdiagnet out files hence need to invoke ibdiagnet before
			ibdiagnet_handler()
			ibdiagnet_is_invoked = True
		result = ib_switches_FW_scan_handler()
	elif (command == "ib_topology_viewer"):
		result = ib_topology_viewer_handler()
	elif (command == "sm_master_is"):
		result = sm_master_is_handler()
	elif (command == "sm_status"):
		result = sm_status_handler()
	elif (command == "sm_version"):
		result = sm_version_handler()
	elif (command == "ibdiagnet"):
		if (ibdiagnet_is_invoked == False):
			ibdiagnet_handler()
			ibdiagnet_is_invoked = True
		# ibdiagnet_res is updated in one of these both cases: 1. handling ibdiagnet command 2. handling ib_swtiches_FW_scan command
		result = ibdiagnet_res
	else:
		# invoking regular command
		status, result = commands.getstatusoutput(command)
	
	fabric_commands_dict[command] = result 
	available_fabric_commands_collection.append(command)


#----------------------------------------------------------
#               Internal Files Dictionary Handler

def add_internal_file_if_exists(file_full_path):
	# put provided file textual content in result
	status, result = commands.getstatusoutput("cat " + file_full_path)
	
	# add internal file to files dictionary only if exists
	if (status == 0):
		files_dict[file_full_path] = result
		available_internal_files_collection.append(file_full_path)
	else:
		f = open(path+file_name+"/dummy_paths", 'a')
		f.write(result)
		f.write("\n\n")
		f.close()

#----------------------------------------------------------
#		External Files Dictionary Handler

# field_name - the field name that will appear in the html
# fil_name - the name of the file that will be linked to
# command_output - is the content of the fil_name

def add_ext_file_handler(field_name, fil_name, command_output):
	if ( fil_name != "pkglist"):
		f = open(path+file_name+"/"+fil_name, 'w')
        	f.write(command_output)
        	f.close()
        external_files_dict[field_name] = "<td><a href=" + fil_name + ">" + field_name + "</a></td>"
	available_external_files_collection.append([field_name, fil_name])


def add_external_file_if_exists(field_name, curr_path):
	if (field_name == "kernel config"):
		status, command_output = commands.getstatusoutput("cat " + curr_path)
		if (status == 0):
			st , uname = commands.getstatusoutput("uname -r")
			add_ext_file_handler(field_name, "config-" + uname, command_output)
	elif (field_name == "config.gz"):
		unrelevant_st, unrelevant_res = commands.getstatusoutput("if [ -e /proc/config.gz ]; then cp /proc/config.gz " + path + file_name + "/config.gz; fi")
	elif (field_name == "syslog"):
		status, command_output = commands.getstatusoutput("cat " + curr_path + "messages")
		if (status == 0):
			add_ext_file_handler(field_name, "messages", command_output)
		else:
			status, command_output = commands.getstatusoutput("cat " + curr_path + "syslog")
			if (status == 0):
				add_ext_file_handler(field_name, "syslog", command_output)
	elif (field_name == "libvma.conf"):
		status, command_output = commands.getstatusoutput("cat " + curr_path)
		if (status == 0):
			add_ext_file_handler(field_name, field_name, command_output)
	elif (field_name == "ibnetdiscover"):
		if (is_ib == 0):
			status, command_output = commands.getstatusoutput(ib_res + " -p")
			add_ext_file_handler("ibnetdiscover -p", "ibnetdiscover_p", command_output)
			status, command_output = commands.getstatusoutput(ib_res)
			add_ext_file_handler("ibnetdiscover", "ibnetdiscover", command_output)
	elif (field_name == "Installed packages"):	
		if (cur_os != "debian"):
			status, unrelevant_res = commands.getstatusoutput("rpm -qva --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH} %{SIZE}\n' | sort  > "+path+file_name+"/pkglist")
		else:
			status, unrelevant_res = commands.getstatusoutput("dpkg --list > "+path+file_name+"/pkglist")
		if (status == 0):
			add_ext_file_handler(field_name, "pkglist", "")
	else:	
		status, command_output = commands.getstatusoutput(field_name)
		if (status == 0):
			add_ext_file_handler(field_name, field_name, command_output)

#----------------------------------------------------------
#		Other System Files Dictionary Handler

def arrange_numa_nodes():
        # numa_nodes
	if (cur_os != "debian"):
		st, res = commands.getstatusoutput("for f in $(find /sys | grep numa_node |grep -v uevent |sort ); do if [[ -f $f ]]; then echo $f $(cat $f); fi; done")
	else:
		st, res = commands.getstatusoutput("exec 2>/dev/null; for f in $(find /sys | grep numa_node |grep -v uevent |sort ); do if ! [[ -d $f ]]; then echo $f $(cat $f); fi; done")
	
	other_system_files_dict['numa_nodes'] = res
	

def arrange_system_files():
	other_system_files_dict['System Files'] = "No System Files"
	if (no_ib_flag == False):
		if (cur_os != "debian"):
			st, res = commands.getstatusoutput("NETDEVICES=$(LIST='' ; set -- `ls /sys/class/net`; while [ $# -ne 0 ];do [[ $1 == lo ]] && shift && continue; LIST+=' '; LIST+=$1 ;shift;done ; echo $LIST); for f in $(find /sys | grep infini |grep -v uevent |sort ) ${NETDEVICES}; do if [[ -f $f ]]; then echo File: $f: $(cat $f); fi; done")
		else:
			st, res = commands.getstatusoutput("exec 2>/dev/null; NETDEVICES=$(LIST='' ; set -- `ls /sys/class/net`; while [ $# -ne 0 ];do [[ $1 == lo ]] && shift && continue; LIST+=' '; LIST+=$1 ;shift;done ; echo $LIST); for f in $(find /sys | grep infini |grep -v uevent |sort ) ${NETDEVICES}; do if ! [[ -d $f ]]; then echo File: $f: $(cat $f); fi; done")
	
		if (st == 0 and res != ""):
			other_system_files_dict['System Files'] = res
	
		
#----------------------------------------------------------

def arrange_server_commands_section():
	# add server commands list	
	for cmd in commands_collection:
		add_command_if_exists(cmd)

def arrange_fabric_commands_section():
	# add fabric commands list if configured as IB
	for cmd in fabric_commands_collection:
		add_fabric_command_if_exists(cmd)


def arrange_internal_files_section():
	# Internal files with static paths handlers
	for static_path in internal_files_collection:
        	add_internal_file_if_exists(static_path)

	# Internal files with dynamic paths handlers
	if (os.path.exists("/etc/modprobe.d/") == True):
		for file in os.listdir("/etc/modprobe.d/"):
			if (os.path.isfile("/etc/modprobe.d/"+file) == True):	
				add_internal_file_if_exists("/etc/modprobe.d/" + file)		
	
	if (os.path.exists("/sys/class/infiniband/") == True):
		for file in os.listdir("/sys/class/infiniband/"):
			if (os.path.isfile("/sys/class/infiniband/"+file) == False):
				add_internal_file_if_exists("/sys/class/infiniband/" + file + "/board_id")
                        	add_internal_file_if_exists("/sys/class/infiniband/" + file + "/fw_ver")
                        	add_internal_file_if_exists("/sys/class/infiniband/" + file + "/hca_type")
                        	add_internal_file_if_exists("/sys/class/infiniband/" + file + "/hw_rev")
                        	add_internal_file_if_exists("/sys/class/infiniband/" + file + "/node_desc")
                        	add_internal_file_if_exists("/sys/class/infiniband/" + file + "/node_guid")
                        	add_internal_file_if_exists("/sys/class/infiniband/" + file + "/node_type")
                        	add_internal_file_if_exists("/sys/class/infiniband/" + file + "/sys_image_guid")

	if (os.path.exists("/sys/devices/system/node/") == True):
		for file in os.listdir("/sys/devices/system/node/"):
                	if (os.path.isfile("/sys/devices/system/node/"+file) == False):
				add_internal_file_if_exists("/sys/devices/system/node/"+file+"/cpulist")

	if (cur_os != "debian" and os.path.exists("/etc/sysconfig/network-scripts/") == True):
		for file in os.listdir("/etc/sysconfig/network-scripts/"):
                	if ( (os.path.isfile("/etc/sysconfig/network-scripts/"+file) == True) and (file.startswith("ifcfg")) ):
          			add_internal_file_if_exists("/etc/sysconfig/network-scripts/" + file)
	
	if (os.path.exists("/etc/") == True):
		for file in os.listdir("/etc/"):
			if ( (os.path.isfile("/etc/"+file) == True) and ("release" in file) ):
				add_internal_file_if_exists("/etc/"+file)
	

def arrange_external_files_section():
	# add external files if exist to the provided external section e.g. "kernel config"
	for pair in external_files_collection:
		add_external_file_if_exists(pair[0], pair[1])

def arrange_other_system_files_section():
	arrange_numa_nodes()	
	arrange_system_files()
	
def arrange_dicts():
	arrange_server_commands_section()
	arrange_internal_files_section()
	arrange_external_files_section()
	arrange_other_system_files_section()
        if (is_ib == 0):
                arrange_fabric_commands_section()

###########################################################
###############  Out File Name Handlers ###################

def get_json_file_name():	
	curr_hostname = invoke_command(['hostname']).replace('\n', '-')
	json_file_name = "sysinfo-snapshot-v" + version + "-" + curr_hostname + date_file
	return json_file_name

file_name = get_json_file_name()

###########################################################
############### Print Handlers ############################

def print_destination_out_file():
	print ("Temporary destination directory is " + path)
	print ("Out file name is " + path + file_name + ".tgz\n")
	if (os.path.exists(path + file_name) == True and os.path.isfile(path + file_name) == False):
		print (path + file_name + ".tgz:")
		for fi in sorted(os.listdir(path + file_name)):
			if (fi == "dummy_functions"):
				print ("dummy_functions - contains all not found commands")
			elif (fi == "dummy_paths"):
				print ("dummy_paths - contains all not existing internal files (/paths)")
			elif (fi == "ibdiagnet"):
				print ("ibdiagnet - contains all files generated from invoking ibdiagnet")
			else:
				print (fi)

def show_error_message(err_msg):
	print ("Error: Unknown option/s: " + err_msg)	

def show_usage():
	print ("sysinfo-snapshot version: " + version + " usage:"
          + "\n\tThe sysinfo-snapshot command gathers system information and places it into a tar file."
          + "\n\tIt is required to run this script as super user (root)."
          + "\n\t-h    |--help \t\t- print this help."
          + "\n\t-d    |--dir \t\t- set destination directory (default is /tmp)."
	  + "\n\t-v    |--version \t- print the tool's version information and exit."
	  + "\n\t-fw   |--firmware \t- add firmware commands/functions to the output."
	  + "\n\t-no_ib \t\t\t- do not add server IB commands to the output."
	  + "\n\t--json \t\t\t- add json file to the out put.")

###########################################################
############## Main Function's Handlers ###################

# Remove all unwanted side effect files and folders
def remove_unwanted_files():
	# Remove mstflint_lockfiles directory
	invoke_command(['rm', '-rf', "/tmp/mstflint_lockfiles"])

	# Remove untared directory out file
        invoke_command(['rm', '-rf', path+file_name])

        # Remove all unwanted side effect files
        if (os.path.exists(path) == True):
		for file in os.listdir(path):
                	if (file.startswith("tmp.") or file.startswith("hsqldb.")):
                        	invoke_command(['rm', '-rf', path+file])


def validate_not_file():
	# validate the path is not file elsewise print proper message and exit
	if (isFile == True):
		print("Generating the sysinfo-snapshot halted; The path you had provided is similar to a file name.")
		print("Please change the temporary destination directory and try again.")
		sys.exit(1)

def print_invalid_path_and_exit(err_msg):
	print(err_msg)
	print("Please change the temporary destination directory and try again.")
	sys.exit(1)


def validate_path():
	taboo_chars = [' ', '#', '%', '&', '{', '}', '<', '>', '*', '?', '$', '!', '`', '"', ':', '@', '+', "'", '|', '=', ',', '.', ';', '\ ', '(', ')']
	for ch in taboo_chars:
		if ch in path:
			print_invalid_path_and_exit("Invalid Path: directory name should not contain " + ch)
	
	if (path.startswith("/")):
		names = path[1:][:-1].split("/")
	else:
		names = path[:-1].split("/")
	
	for name in names:
		if (name.startswith("-") or name.startswith("_")):
			print_invalid_path_and_exit("Invalid Path: directory " + name + " should not start with of any of a space,hyphen or underscore")
		

def ensure_out_dir_existence():
	global path_is_generated
	if (os.path.exists(path) == False):
   		validate_path() 
		invoke_command(['mkdir', '-p', path])	
		path_is_generated = 1


###########################################################
#		HTML Handlers
	
html_path = path + file_name + "/" + file_name + ".html"
html_flag=0

def get_welcome():
	if (is_ib == 0):
        	return "Linux Infiniband Driver System Information Snapshot Utility"
	else:
		return "Linux Ethernet Driver System Information Snapshot Utility"

	
def initialize_html(html_flag):	
	if (html_flag == 1):
		return
	html_flag = 1
	html = open(html_path, 'a')

	html.write("<html>")
	html.write("<head><title>" + html_path + "</title></head>")
	html.write("<body><pre>")
	html.write("<a name=" + '"' + "index" + '"' + "></a><h1>Mellanox Technologies</h1>")
        html.write("<br/>")	
	html.write("<a name=" + '"' + "index" + '"' + "></a><h2>" + get_welcome() + "</h2>")
        html.write("<br/>")	
	html.write("<a name=" + '"' + "index" + '"' + "></a><h2>Version: " + version + "</h2>")
        html.write("<br/><hr/>")
	
	# Add firmware alert status
	if (fw_flag == False):
		html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Firmware commands are NOT included. (-fw or --firmware flags were not provided)</font></p>")	
	else:
		html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Firmware commands are included. (One of -fw or --firmware flags was provided)</font></p>")
	
	# Add no_ib alert status
	if (no_ib_flag == True):
		html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: IB commands are NOT included. (-no_ib flag was provided)</font></p>")
	else:
		html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: IB commands are included. (-no_ib flag was not provided)</font></p>")

	# Add no mlnx cards alert if needed
	if (mlnx_card_exists == False):
		html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: There are no Mellanox cards. </font></p>")

	html.close()


def html_write_section(html, title, collection, base):
        html.write("<h2>" + title + "</h2>")
	html.write("<table cols="+'"'+"4"+'"'+" width=" + '"' + "100%" + '"' + " border=" + '"' + "0" + '"' + " bgcolor="+'"'+"#E0E0FF"+'"'+">")
        html.write("<tr>")

        rows = len(collection)/4
        mod_val = len(collection) % 4

        c=0
        r=0
        html.write("<!-- rows: " + str(rows) + " " + title + str(len(collection)) + " -->")

        for i in range(len(collection)):
                if (c <= mod_val):
                        cmd = r + c*(rows+1)
                else:
                        cmd = r + mod_val*(rows+1)+(c-mod_val)*rows # = r + mod_val + c*rows

                sec = base + cmd + 1
                html.write("<!-- sec " + str(sec) + " cmd " + str(cmd) + " -->")
                html.write("<td width=" + '"' + "25%" + '"' + "><a href=" +'"'+ "#sec"+str(sec)+'"'+">" + collection[cmd]  + "</a></td>")
                c = c+1
                if ( (c % 4) == 0):
                        html.write("</tr><tr>")
                        r = r+1
                        c=0
        html.write("</tr></table>")


def html_write_prev(html, sec):
        # Add prev button if not first line
       	if (sec != 1001):
		html.write("<small><a href=" + '"' + "#sec" + str(sec-1) + '"' + ">[&lt;&lt;prev]</a></small> ")

def html_write_index(html):
	# Add index button
	html.write("<small><a href=" + '"' + "#index" + '"' + ">[back to index]</a></small> ")	

def html_write_next(html, sec):
        # Add next button if not last line
        html.write("<small><a href=" + '"' + "#sec" + str(sec + 1) + '"' + ">[next>>]</a></small> ")

def html_write_prev_index_next(html, sec):
	html_write_prev(html, sec)
	html_write_index(html)
	html_write_next(html, sec)


def html_write_paragraph(html, base, collection, dict, prev_parag_end):
        html.write("<p>")
        
	sec=base+1
        for i in range(len(collection)):
                html.write("<a name=" + '"' + "sec" + str(sec) + '"' + "></a>")
                         
		if ( (i+1) == len(collection) ):
			html_write_prev(html, sec)
			html_write_index(html)
			if (base<3000):
				if (is_ib == 0): # IB Fabric
					html.write("<small><a href=" + '"' + "#sec" + str(base+1000+1) + '"' + ">[next>>]</a></small> ")
				else:
					html.write("<small><a href=" + '"' + "#sec" + str(base+2000+1) + '"' + ">[next>>]</a></small> ")

			if (base==3000):
                       		html.write("<small><a href=" + '"' + "#numanodes" + '"' + ">[next>>]</a></small> ")
		elif (i == 0):
			if (base==2000 or base==3000):
				html.write("<small><a href=" + '"' + "#sec" + str(prev_parag_end) + '"' + ">[&lt;&lt;prev]</a></small> ")
			html_write_index(html)
			html_write_next(html, sec)
			
		else:
			html_write_prev_index_next(html, sec)

                # Add command title/header
                html.write("<h2>"+collection[i]+"</h2>")
                # Add command output/content
                if ( (collection == available_commands_collection) 
			and ( (collection[i] == "fw_ini_dump" and fw_ini_dump_is_string == False ) 
			or (collection[i] == "mstregdump-func" and mstreg_dump_is_string == False) ) ):
                        	html.write("<p>")
                        	for key, value in server_commands_dict[collection[i]].iteritems():
                                	html.write(value)
                                	html.write("&nbsp&nbsp&nbsp&nbsp")
                        	html.write("</p>")
                else:
                        replaced_command_output = dict[collection[i]].replace('<', "&lt;").replace('>', "&gt;")
                        html.write("<p>" + replaced_command_output + "</p>")	

		sec=sec+1

        html.write("</p>")
	return (sec-1)



def build_and_finalize_html():
	html = open(html_path, 'a')

	#=======================SORT COLLECTIONS FOR PRINTING HTML =================
	
	available_commands_collection.sort()
	if (is_ib == 0): # IB Fabric
		available_fabric_commands_collection.sort()
	available_internal_files_collection.sort() 

	#=======================BEGIN OF SERVER COMMANDS SECTION ====================
	
	html_write_section(html, "1. Server Commands: ", available_commands_collection, 1000) 	

	#=======================END OF SERVER COMMANDS SECTION =======================
	
	#=======================BEGIN OF FABRIC DIGNASTICS SECTION ===================
	
	if (is_ib == 0):
		html_write_section(html, "2. Fabric Diagnostic Information: ", available_fabric_commands_collection, 2000)

	#=======================END OF FABRIC DIGNASTICS SECTION =====================

	#=======================BEGIN OF FILES SECTION ===============================
	
	if (is_ib == 0):
		html_write_section(html, "3. Internal Files: ", available_internal_files_collection, 3000)
	else:	
		html_write_section(html, "2. Internal Files: ", available_internal_files_collection, 3000)

	#=======================EXTERNAL FILES =======================================
	
       	if (is_ib == 0):
                html.write("<h2>4. External Files:</h2>")
        else:
                html.write("<h2>3. External Files:</h2>")
        html.write("<table cols="+'"'+"4"+'"'+" width=" + '"' + "100%" + '"' + " border=" + '"' + "0" + '"' + " bgcolor="+'"'+"#E0E0FF"+'"'+">")
        html.write("<tr>")

        rows = len(available_external_files_collection)/6
        mod_val = len(available_external_files_collection) % 6

        c=0
        r=0
        base=4000

	html.write("<!-- rows: " + str(rows) + " External Files: " + str(len(available_external_files_collection)) + " -->")

        for pair in available_external_files_collection:
                if (c < mod_val):
                        fno = r + c*(rows+1)
                else:
                        fno = r + c*rows

		# pair[0] is field name
		# pair[1] = is external file name
                html.write("<td width=" + '"' + "16%" +'"' + "><a href=" + pair[1] + ">" + pair[0] + "</a></td>")
                c = c+1
                if ( (c % 6) == 0):
                        html.write("</tr><tr>")
                        r = r+1
                        c=0

        html.write("</tr></table>")
	

	#=======================END OF FILES SECTION =================================
	
	html.write("</br>")
	html.write("<a href=" + '"' + "#systemfiles" + '"' + ">Other System Files</a>")	
	html.write("<br/>")

	#=============================================================================
	#=======================Paragraph 1 - Server Commands ========================	
	
	parag_1_end = html_write_paragraph(html, 1000, available_commands_collection, server_commands_dict, 0)
		
	#=============================================================================
        #=======================Paragraph 2 - Fabric Commands ========================
        
	if (is_ib == 0): # IB Fabric
		parag_2_end = html_write_paragraph(html, 2000, available_fabric_commands_collection, fabric_commands_dict, parag_1_end) 
	else:
		parag_2_end = parag_1_end

	#============================================================================
	#=======================Paragraph 3 - Internal Files ========================
	
	parag_3_end = html_write_paragraph(html, 3000, available_internal_files_collection, files_dict, parag_2_end)	

	#=============================================================================
	#=======================Paragraph 4 - numa_nodes =============================
	
	html.write("<p>")

	base = 4000
	sec = base+1
        
	html.write("<a name=" + '"' + "numanodes" + '"' +"></a>")
	
        html.write("<small><a href=" + '"' + "#sec" + str(parag_3_end) + '"' + ">[&lt;&lt;prev]</a></small> ")
	html_write_index(html)	
        html.write("<small><a href=" + '"' + "#systemfiles" + '"' + ">[next>>]</a></small> ")
	
	# Add numa_node title/header
       	html.write("<h2>numa_node</h2>")
	html.write(other_system_files_dict['numa_nodes'].replace('<', "&lt;").replace('>', "&gt;"))

	html.write("</p>")
	
	#=============================================================================
	#=======================Paragraph 4 - System Files ===========================

	html.write("<p>")

	base = 5000
	sec = base+1
	
	html.write("<a name=" + '"' + "systemfiles" + '"' + "></a>")
	
        html.write("<small><a href=" + '"' + "#numanodes" + '"' + ">[&lt;&lt;prev]</a></small> ")	
	html_write_index(html)
	
        # Add System Files title/header
        html.write("<h2>System Files</h2>")
        html.write(other_system_files_dict['System Files'].replace('<', "&lt;").replace('>', "&gt;"))


	html.write("<br/><br/>")
	html.write("<small><a href=" + '"' + "#systemfiles" + '"' + ">[&lt;&lt;prev]</a></small> ")
	html_write_index(html)

	html.write("</p>")

	#=============================================================================
	

        html.write("</body></pre>")
	html.write("</html>")

	html.close()


###########################################################

def confirm_MLNX_cards():
	st, mlnx_cards_num = commands.getstatusoutput("lspci -d 15b3: | wc -l")
	if (st != 0):
		print ("Unable to count Mellanox cards")
                sys.exit(1)
	mlnx_cards_num = mlnx_cards_num.split("\n")[-1]
        if (represents_Int(mlnx_cards_num) == True):
		if not (int(mlnx_cards_num) > 0):
			print ("There are no Mellanox cards")
			global mlnx_card_exists
			mlnx_card_exists = False
	else:
		print ("Unable to count Mellanox cards")
		sys.exit (1)

# Create the output tar
def generate_output():	
	validate_not_file()
	confirm_MLNX_cards()

	# Create output directories
	ensure_out_dir_existence()
	invoke_command(['mkdir', path + file_name])
	invoke_command(['mkdir', path + file_name + "/tmp"])
	
	initialize_html(html_flag)

	# Major operations for creating the .json file
        arrange_dicts()
	if (json_flag == True and json_found == True):
		json_content = json.dumps(l1_dict, sort_keys=True)      
		json_file = open(path + file_name + "/" + file_name + ".json", 'w')
        	print >> json_file, json_content 
		json_file.close()
	elif (json_flag == True):
		print ("'json' module is not found in python, please install the module or remove the flag --json and try again.\n")

	build_and_finalize_html()

	# Remove helping directories before creating tar
	invoke_command(['rm', '-rf', path + file_name + "/tmp"])
	
	# Create result tar file
	tar = tarfile.open(path + file_name + ".tgz", "w:gz")
	tar.add(path + file_name, arcname = file_name)
	tar.close()

	# Print Destination
        print_destination_out_file()

	# Remove all unwanted files
	remove_unwanted_files()	


def confirm_valid_options(index):
	if (index > 0 and (sys.argv[index-1] == '-d' or sys.argv[index-1] == "--dir")):
        	print ("Invalid options")
		usage()
		sys.exit(1)

def update_flags():
        global fw_flag
	global no_ib_flag
	global json_flag

	fw_arg = ""
	i = 1
        j = 1
	k = 1
        index = 0
        for arg in sys.argv:
                if (arg == "-fw" or arg == "--firmware"):
                        confirm_valid_options(index)
                        fw_flag = True
                        fw_arg = arg
                        i += 1
                if (arg == "-no_ib"):
                        confirm_valid_options(index)
                        no_ib_flag = True
                        j += 1
		if (arg == "--json"):
			confirm_valid_options(index)
			json_flag = True
			k += 1
                if (i>2 or j>2 or k>2):
                        print("Invalid options. The same option was provided more than once.")
                        show_usage()
                        sys.exit(1)
                index += 1
	return fw_arg


def execute():
	global len_argv
	fw_arg = update_flags()

	if (fw_flag == True):
		sys_argv.remove(fw_arg)
		len_argv -= 1
	if (no_ib_flag == True):		
		sys_argv.remove("-no_ib")
		len_argv -= 1	
	if (json_flag == True):
		sys_argv.remove("--json")
		len_argv -= 1		
		
	if ( (len_argv == 1) or ( (len_argv == 3) and ((sys_argv[1] == '-d') or (sys_argv[1] == "--dir") ) ) ):
		generate_output()
	elif ((len(sys.argv)>1) and ( (sys.argv[1] == '-v') or (sys.argv[1] == "--version"))):
       		print ("sysinfo-snapshot version: " + version)
	else:
		if ( (len(sys.argv) > 1) and (sys.argv[1] != '-h') and (sys.argv[1] != '--help') ):
			err_msg = ""
			for i in range(1, len(sys.argv)):
				err_msg += sys.argv[i] + " "
			show_error_message(err_msg)
		show_usage()


def confirm_root():
	st, user = commands.getstatusoutput("/usr/bin/whoami")
	if (st != 0):
		print ("Unable to distinguish user")
        	sys.exit(1)
	if (user != "root"):
		print ("Runing as a none root user\nPlease switch to root user (super user) and run again.\n")
		show_usage()
       		sys.exit(1)

def main():
	if not (len(sys.argv) == 2 and (sys.argv[1] == '-v' or sys.argv[1] == "--version" or sys.argv[1] == '-h' or sys.argv[1] == "--help")):
		confirm_root()
	execute()


if __name__ == "__main__":
	main()

