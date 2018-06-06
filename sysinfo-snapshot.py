#!/usr/bin/python
# -*- python -*-
#
# Author:  Nizar Swidan  nizars@mellanox.com -- Created: 2015
# Modified:  Anan Fakheraldin  ananf@mellanox.com -- Modified: 2018
__author__ = 'nizars'


import subprocess
import sys
import re
import tarfile
import os
import collections
import time
import signal
import shutil
import platform
import csv
import argparse

from distutils.version import LooseVersion


try:
    import json
    json_found = True
except ImportError:
    json_found = False


COMMAND_CSV_HEADER = 'Command'
INVOKED_CSV_HEADER = 'Approved'
DEFAULT_CONFIG_PATH = './config.csv'

###########################################################
#        Get Status Ouptut
# (replacement old the depreciated call st, res = get_status_output("..")

def standarize_str(tmp):
    ''' if python version major is 3, then tmp is unicode (utf-8) byte string
        and need to be converted to regular string
    '''
    if sys.version_info[0] == 2:
        return tmp.strip()
    elif sys.version_info[0] == 3:
        return str(tmp.strip(),'utf-8')
    else:
        return tmp.strip()

def get_status_output(command):
    p = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = p.communicate()
    return p.returncode, standarize_str(stdout)

# Ditto but preserving the exit status.
# Returns a pair (sts, output)
#
def getstatusoutput(cmd):
    """Return (status, output) of executing cmd in a shell."""
    pipe = os.popen('{ ' + cmd + '; } 2>&1', 'r')
    text = pipe.read()
    sts = pipe.close()
    if sts is None: sts = 0
    if text[-1:] == '\n': text = text[:-1]
    return sts, text

###########################################################
#   SIGINT-2-Interrupt from keyboard; Handlers (Ctrl+C)

def signal_handler(signal, frame):
    if (path_is_generated == 1):
        get_status_output("rm -rf " + path)
        #invoke_command(['rm', '-rf', path])
    else:
        # Remove tar out file
        get_status_output("rm -rf " + path + file_name + ".tgz")
        #invoke_command(['rm', '-rf', path+file_name+".tgz"])
        remove_unwanted_files()
    if driver_required_loading:
        os.system('timeout 10s mst stop > /dev/null 2>&1')
    print("\nRunning sysinfo-snapshot was halted!\nNo out directories/files.\nNo changes in modules loading states.")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

###########################################################
#        General Variables

version = "3.3.1"

sys_argv = sys.argv
len_argv = len(sys.argv)

driver_required_loading = False
is_MFT_installed = False

all_sm_on_fabric = []
#active_subnets --> device_name
#               --> port
active_subnets = {}

#installed_cards_ports --> device_name
#                       --> port
installed_cards_ports = {}

config_dict = {}

json_flag = False

verbose_flag = False
verbose_count = 0

# is_ib = 0 if the server is configured as IB
# is_ib != 0 if the server is configured as ETH
is_ib, ib_res = get_status_output("timeout 10s which ibnetdiscover 2>/dev/null")
mlnx_cards_status = -1

path_is_generated = 0
path = "/tmp/"
config_path = ""
parser = ""

section_count=1
ibdiagnet_res = ""
ibdiagnet_is_invoked = False
# ibdiagnet_flag = False, means --ibdiagnet was not provided
# ibdiagnet_flag = True, means --ibdiagnet was provided
ibdiagnet_flag = False
ibdiagnet_error = False

# Runs ibswitches for a given card and port and returns it output and run status
def get_ibswitches_output(card, port):
    ibswitches_st, ibswitches = get_status_output("timeout 10s /usr/sbin/ibswitches -C " + card +" -P " + port)
    if ibswitches_st != 0:
        ibswitches = "Couldn't find command: ibswitches"
    else:
        # regex expression working in python 2.7 not 2.6
        #ibswitches = re.sub('^((?!Switch).)*$', '', ibswitches, re.IGNORECASE,re.MULTILINE)
        ibswitches = ibswitches.splitlines()
        ibswitches_new = ''
        for ibswitch in ibswitches:
            if ibswitch.startswith('Switch'):
                if ibswitches_new == '':
                    ibswitches_new = ibswitch
                else:
                    ibswitches_new = ibswitches_new + '\n' + ibswitch
        ibswitches = ibswitches_new
    return ibswitches_st, ibswitches

#get the cards and ports that are installed and updates the active subnets
def get_installed_cards_ports():
    global active_subnets
    global installed_cards_ports
    global all_sm_on_fabric
    st, ibstat = get_status_output("timeout 10s ibstat | grep " + '"' + "CA '\|Port " + '"' + " | grep -v GUID")
    if st != 0:
        return "Could not run: ibstat"
    str_cards = ibstat.split("CA '")
    if len(str_cards) > 0:
        str_cards.pop(0)
        if len(str_cards) > 0:
            first = True
            res = ""
            all_sm_on_fabric = []
            for card in str_cards:
                card_name = card.split("'")[0]
                installed_cards_ports[card_name] = []
                str_ports = card.split("Port ")
                if len(str_ports) > 0:
                    str_ports.pop(0)
                    if len(str_ports) > 0:
                        for port in str_ports:
                            port_num = port.split(":")[0]
                            installed_cards_ports[card_name].append(port_num)
                            i, sminfo_output = get_status_output("timeout 10s /usr/sbin/sminfo -C " + card_name + " -P " + port_num + "")
                            if i != 0:
                                continue
                            # ex: sminfo: sm lid 3 sm guid 0x248a0703009c0196, activity count 38526 priority 15 state 3 SMINFO_MASTER
                            sm_guid = sminfo_output.split()[6]
                            dec_sm = int(sm_guid.strip(','), 0)
                            if dec_sm not in all_sm_on_fabric:
                                all_sm_on_fabric.append(dec_sm)
                                if card_name not in active_subnets:
                                    active_subnets[card_name] = []
                                obj = {}
                                obj["port_num"] = port_num
                                ibswitches_st, ibswitches = get_ibswitches_output(card_name, port_num)
                                obj["ibswitches"] = {}
                                obj["ibswitches"]["ibswitches_st"] = ibswitches_st
                                obj["ibswitches"]["ibswitches_output"] = ibswitches
                                active_subnets[card_name].append(obj)


sys_class_net_exists = False
if os.path.exists("/sys/class/net"):
    sys_class_net_exists = True


# fw_flag = False, means not to add fw_collection commands to the out file
# fw_flag = True, means to add fw_collection commands to the out file
# fw_flag can be converted to True by running the tool with -fw or --firmware flag
fw_flag = False

# pcie_flag = False, means not to add pcie_collection commands to the out file
# pcie_flag = True, means to add pcie_collection commands to the out file
# pcie_flag can be converted to True by running the tool with --pcie flag
pcie_flag = False

# mtusb_flag = False, means not to add I2C dump files
# mtusb_flag = True, means to add I2C dump files
# mtusb_flag can be converted to True by running the tool with --mtusb flag
# If mtusb flag is true it runs "mst start" and then return it to the old status
mtusb_flag = False

# check_fw_flag = False, means not to add any check to adapter firmware if latest
# check_fw_flag = True, means to  add any check to adapter firmware if latest
# check_fw_flag can be converted to True by running the tool with --check_fw
# If check_fw flag is true it runs online check for the latest fw for this psid 
check_fw_flag = False

# generate_config_flag = Fals, means not to generate a new config file
# generate_config_flag = True, means to  generate a new config file
# this should be invoked with before any release with --ibdiagnet -fw -p --pcie --check_fw
generate_config_flag = False

# config_file_flag = False, means not to use default configuration all commands should be invoked
# config_file_flag = True, means to add any check to adapter firmware if latest
config_file_flag= False

#no_ib_flag = False, means to add ib commands to the out file
#no_ib_flag = True, means not to add ib commands to the out file
#no_ib_flag can be converted to True by running the tool with --no_ib flag
no_ib_flag = False

if "--no_ib" in sys.argv:
    no_ib_flag = True

#perf_flag = False, means not to include more performance commands/function like ib_write_bw and ib_write_lat
#no_ib_flag = True, means include more performance commands/functions to the out file
#perf_flag can be converted to True by running the tool with -p|--perf
perf_flag = False

mlxdump_is_string = True
fw_ini_dump_is_string = True
mstreg_dump_is_string = True

sta, date_cmd = get_status_output("timeout 10s date")
sta, date_file = get_status_output("timeout 10s echo $(date '+%Y%m%d-%H%M')")

st_saquery = 1

#return true if command should be invoked. and added to dict in case we are generating new file
def is_command_allowed(config_key):
    global config_dict

    if generate_config_flag:
        config_dict[config_key] = 'yes'
        return False

    if config_key in config_dict:
        if config_file_flag and config_dict[config_key].lower() != 'yes':
            return False
        else:
            return True
    return True


###########################################################
#        OS General Variables & Confirmation

#rpm --eval %{_vendor}
#Ubuntu prints debian
#Redhat and CentOS prints redhat
supported_os_collection = ["redhat", "suse", "debian"]

os_st, cur_os = get_status_output("timeout 10s rpm --eval %{_vendor}")

def decide():
    print("Hence running sysinfo-snapshot may throw an exception or produce an unexpected output.")
    sys.stdout.write("Continue running sysinfo-snapshot (y/n)? ")
    decision_ch = sys.stdin.read(1).lower()
    if (decision_ch == 'y'):
        cur_os = "redhat"
    else:
        if (decision_ch != 'n'):
            print("Invalid char")
        print("Halting sysinfo-snapshot")
        sys.exit(0)

if (os_st == 0):
    if (cur_os not in supported_os_collection):
        print("Operating system with vendor " + cur_os + " is not tested.")
        decide()
else:
    os_st, o_systems = get_status_output("timeout 10s cat /etc/redhat-release")
    if (os_st != 0):
        os_st, o_systems = get_status_output("timeout 10s cat /etc/issue")
        if (os_st != 0):
            print("Unable to distinguish operating system.")
            decide()
    o_systems = o_systems.lower()
    o_systems = o_systems.split()
    if ( ("red" in o_systems and "hat" in o_systems) or ("redhat" in o_systems) or ("centos" in o_systems) or ("fedora" in o_systems) or ("scientific" in o_systems) ):
        cur_os = "redhat"
    elif ("suse" in o_systems):
        cur_os = "suse"
    elif ( ("ubuntu" in o_systems) or ("debian" in o_systems) ):
        cur_os = "debian"
    else:
        print("Unable to distinguish operating system.")
        decide()

###########################################################
#               SR-IOV Global Variables

sriov_version = "1.0.0"

sriov_exists = False

sriov_commands_collection = ["bridge fdb show dev p3p1", "ip link", "ip_link_show_devices", "lspci_vf"]
available_sriov_commands_collection = []

sriov_internal_files_collection = ["/etc/infiniband/openib.conf.rpmsave", "/etc/modprobe.d/mlnx.conf"]
available_sriov_internal_files_collection = []

sriov_commands_dict = {}
sriov_internal_files_dict = {}

###########################################################
#       Performance Tunning Analyze Global Variables

perf_version = "1.0.1"

perf_setting_collection = ["IRQ Affinity", "Core Frequency", "Hyper Threading", "IP Forwarding", "AMD", "Memory Allocation", "PCI Configurations", "Bandwidth", "Latency"]
eth_setting_collection = ["IP Forwarding"]
ib_setting_collection = ["Bandwidth", "Latency"]
setting_without_status = ["IP Forwarding", "Bandwidth", "Latency"]
not_available = "N/A"
not_present = "Not Present"
present = "Present"
perf_status_dict = {}
perf_val_dict = {}
perf_external_files_collection = [["mlnx_tune -r", "mlnx_tune_r"]]

###########################################################
#        HTML Handlers And Global Variables

fw_collection = ["itrace", "mlxmcg -d", "fw_ini_dump", "mlxdump"]

pcie_collection = ["lspci -vvvxxxxx"]

ib_collection = []

commands_collection = ["ip -s link show", "rpm -qa --last", "ovs-vsctl --version", "ovs-vsctl show", "ovs-dpctl show", "brctl --version", "brctl show", "itrace", "mlxmcg -d", "arp -an", "free", "blkid -c /dev/null | sort", "date", "time", "df -lh", "/opt/mellanox/ethtool/sbin/ethtool --version", "/sbin/ethtool --version", "ethtool_all_interfaces", "fdisk -l", "fw_ini_dump", "hostname", "ibdev2netdev", "ibdev2pcidev", "ibv_devinfo -v", "ifconfig -a", "initctl list", "ip m s", "ip n s", "iscsiadm --version", "iscsiadm -m host", "iscsiadm -m iface", "iscsiadm -m node", "iscsiadm -m session", "lscpu", "lsmod", "lspci", "lspci -tv", "lspci_xxxvvv", "lspci -vvvxxxxx", "mount", "mstregdump-func", "netstat -anp", "netstat -i", "netstat -nlp", "netstat -nr", "netstat -s", "numactl --hardware", "ofed_info", "ofed_info -s", "ompi_info", "ps -eLo", "ip route show table all", "service --status-all", "service cpuspeed status", "service iptables status", "service irqbalance status", "show_irq_affinity_all", "sysctl -a", "tgtadm --mode target --op show", "tgtadm --version", "tuned-adm active", "ulimit -a", "uname -a", "uptime", "yy_MLX_modules_parameters", "yy_IB_modules_parameters", "zz_proc_net_bonding_files", "zz_sys_class_net_files", "teamdctl_state", "teamdctl_state_view", "teamdctl_config_dump", "teamdctl_config_dump_actual", "teamdctl_config_dump_noports", "mlxconfig_query", "mst status", "mst status -v", "mlxcables", "mlxcables --DDM/--read_all_regs", "ip addr show", "ip -6 addr show", "ip link show", "ip route show", "ip -6 route show", "modinfo", "show_pretty_gids", "mlxdump", "gcc --version", "python_used_version", "cma_roce_mode", "cma_roce_tos", "service firewalld status"]

if (cur_os != "debian"):
    commands_collection.extend(["chkconfig --list | sort"])

available_commands_collection = []



fabric_commands_collection = ["ibstatus", "ib_mc_info_show", "sm_version", "Multicast_Information", "ibstat", "perfquery_cards_ports"]

fabric_multi_sub_commands_collection = ["ibdiagnet", "ib_find_bad_ports", "ib_find_disabled_ports", "ib_topology_viewer", "ibhosts", "ibswitches", "sminfo", "sm_status", "sm_master_is", "ib_switches_FW_scan"]

available_fabric_commands_collection = []



internal_files_collection = ["/sys/devices/system/clocksource/clocksource0/current_clocksource", "/sys/fs/cgroup/net_prio/net_prio.ifpriomap", "/etc/opensm/partitions.conf", "/etc/opensm/opensm.conf", "/etc/infiniband/info", "/etc/infiniband/openib.conf", "/etc/modprobe.d/vxlan.conf", "/etc/security/limits.conf", "/boot/grub/grub.cfg", "/boot/grub/grub.conf", "/boot/grub/menu.lst", "/etc/default/grub", "/etc/host.conf", "/etc/hosts", "/etc/hosts.allow", "/etc/hosts.deny", "/etc/issue", "/etc/modprobe.conf", "/etc/ntp.conf", "/etc/resolv.conf", "/etc/sysctl.conf", "/etc/tuned.conf", "/etc/yum.conf", "/proc/cmdline", "/proc/cpuinfo", "/proc/devices", "/proc/diskstats", "/proc/dma", "/proc/interrupts", "/proc/meminfo", "/proc/modules", "/proc/mounts", "/proc/net/dev_mcast", "/proc/net/igmp", "/proc/partitions", "/proc/stat", "/proc/sys/net/ipv4/igmp_max_memberships", "/proc/sys/net/ipv4/igmp_max_msf", "/etc/debian_version","/proc/uptime", "/proc/version", "/etc/rdma/rdma.conf", "/proc/net/softnet_stat", "/proc/buddyinfo", "/proc/zoneinfo", "/proc/slabinfo", "/proc/pagetypeinfo"]

if (cur_os == "debian"):
    internal_files_collection.extend(["/etc/network/interfaces"])

available_internal_files_collection = []

# [field_name, file_name to cat]
external_files_collection = [["kernel config", "/boot/config-$(uname -r)"], ["config.gz", "/proc/config.gz"], ["dmesg -T", "dmesg"], ["biosdecode", "biosdecode"], ["dmidecode", "dmidecode"], ["syslog", "/var/log/"], ["libvma.conf", "/etc/libvma.conf"], ["ibnetdiscover", ""], ["Installed packages", ""], ["Performance tuning analyze", ""], ["SR-IOV", ""]]

available_external_files_collection = []

copy_under_files = [["etc_udev_rulesd", "/etc/udev/rules.d/"], ["lib_udev_rulesd", "/lib/udev/rules.d/"]]


###########################################################
#    JSON Handlers And Global Variables

# define and initialize dictionaries hierarchy
server_commands_dict = {}
fabric_commands_dict = {}
files_dict = {}
external_files_dict = {}
other_system_files_dict = {}
other_system_files_dict['System Files'] = "No System Files"
other_system_files_dict['numa_nodes'] = "No numa_nodes or could not retrieve them"

l3_dict = {}
l3_dict[str(section_count) + ". Server Commands: "] = server_commands_dict
section_count += 1
if (is_ib == 0 and no_ib_flag == False):
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

def represents_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

'''
def invoke_command(str):
    p = subprocess.Popen(str, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    return out
'''
#**********************************************************
#        show_pretty_gids Handler

def show_pretty_gids_handler():
    n_gids_found = 0
    res = "DEV\tPORT\tINDEX\tGID\t\t\t\t\t\tIPv4\n"
    res += "---\t----\t-----\t---\t\t\t\t\t\t------------\n"
    if os.path.isdir('/sys/class/infiniband'):
        for root, dirs, files in os.walk('/sys/class/infiniband'):
            for device in dirs:
                if os.path.isdir('/sys/class/infiniband/' + device + '/ports'):
                    for subroot, subdirs, subfiles in os.walk('/sys/class/infiniband/' + device + '/ports'):
                        for port in subdirs:
                            if os.path.isdir('/sys/class/infiniband/' + device + '/ports/' + port + '/gids'):
                                for subsubroot, subsubdirs, subsubfiles in os.walk('/sys/class/infiniband/' + device + '/ports/' + port + '/gids'):
                                    for gid_index in subsubfiles:
                                        gid = 'N\A'
                                        try:
                                            with open('/sys/class/infiniband/' + device + '/ports/' + port + '/gids/' + gid_index, 'r') as gid_index_file:
                                                gid = gid_index_file.readline().strip()
                                        except:
                                            continue
                                        if gid == '' or gid == 'N\A' or gid == '0000:0000:0000:0000:0000:0000:0000:0000' or gid == 'fe80:0000:0000:0000:0000:0000:0000:0000':
                                            continue
                                        n_gids_found += 1
                                        gid_type = 'N\A'
                                        try:
                                            with open('/sys/class/infiniband/' + device + '/ports/' + port + '/gid_attrs/types/' + gid_index, 'r') as gid_type_file:
                                                gid_type = gid_type_file.readline().strip()
                                        except:
                                            pass
                                        if gid_type == '':
                                            gid_type = 'N\A'
                                        gid_ndevs = 'N\A'
                                        try:
                                            with open('/sys/class/infiniband/' + device + '/ports/' + port + '/gid_attrs/ndevs/' + gid_index, 'r') as gid_ndevs_file:
                                                gid_ndevs = gid_ndevs_file.readline().strip()
                                        except:
                                            pass
                                        if gid_ndevs == '':
                                            gid_ndevs = 'N\A'
                                        if len(gid_type) < 8:
                                            gid_type += '\t'
                                        if gid.split(':')[0] == '0000':
                                            try:
                                                ipv4 = str(int(gid[30:32], 16)) + '.' + str(int(gid[32:34], 16)) + '.' + str(int(gid[35:37], 16)) + '.' + str(int(gid[37:39], 16)) + '  \t'
                                            except:
                                                ipv4 = '\t\t'
                                            res += device + '\t' + port + '\t' + gid_index + '\t' + gid + '\t\t' + ipv4 + gid_type + '\t\t' + gid_ndevs + '\n'
                                        else:
                                            res += device + '\t' + port + '\t' + gid_index + '\t' + gid + '\t\t\t\t' + gid_type + '\t\t' + gid_ndevs + '\n'
    res += '\nn_gids_found=' + str(n_gids_found) + '\n'
    return res

#**********************************************************
#        ethtool_all_interfaces Handlers

pf_devices = []

def ethtool_all_interfaces_handler():
    if not sys_class_net_exists:
        return "No Net Devices - The path /sys/class/net does not exist"

    st, lspci_devices = get_status_output("timeout 10s lspci | grep Mellanox")
    if (st != 0):
        return "Failed to run the command lspci | grep Mellanox"

    mlx_pci_devices = []
    lspci_devices = lspci_devices.splitlines()
    for line in lspci_devices:
        device_pci = line.split()
        # e.g 81:00.0 Infiniband controller: Mellanox Technologies MT27800 Family [ConnectX-5]
        mlx_pci_devices.append(device_pci[0])

    net_devices = []
    st, all_interfaces = get_status_output("timeout 10s ls -la /sys/class/net")
    if (st != 0):
        return "Failed to run the command ls -la /sys/class/net"


    for device in mlx_pci_devices:
        # e.g lrwxrwxrwx  1 root root 0 Oct 26 15:51 ens11f0 -> ../../devices/pci0000:80/0000:80:03.0/0000:81:00.0/net/ens11f0
        match = re.findall(device + '\/net\/(\w+)',all_interfaces)
        if match:
            for interface in match:
                net_devices.append(interface)

    if "lo" in net_devices:
        try:
            net_devices.remove("lo")
        except:
            pass
    if "bonding_masters" in net_devices:
        try:
            net_devices.remove("bonding_masters")
        except:
            pass
    if "bond0" in net_devices:
        try:
            net_devices.remove("bond0")
        except:
            pass
    global pf_devices
    pf_devices = net_devices
    if (len(net_devices) > 0):
        get_status_output("mkdir " + path + file_name + "/ethtool_S")
        #invoke_command(['mkdir', path + file_name + "/ethtool_S"])
    ethtool_command = "/sbin/ethtool"
    res = ""
    st, ethtool_version = get_status_output("timeout 10 " + ethtool_command + " --version")
    if st != 0:
        return "Failed to run the command " + ethtool_command
    #Output - ethtool version 4.8
    version = ethtool_version.split()[2]
    if (float(version) < 4.7):
        ethtool_version = "Warning - " + ethtool_version + ", it is older than 4.7 ! \nIt will not show the 25g generation speeds correctly, cause ethtool 4.6 and below do not support it." 

    res += ethtool_version
    options = ["", "-i", "-g", "-a", "-k", "-c", "-T", "--show-priv-flags", "-n", "-l", "-x"]
    for interface in net_devices:
        res += "\n\n"
        for option in options:
            st, ethtool_interface = get_status_output("timeout 10s " + ethtool_command + " " + option + " " + interface)
            res += "ethtool " + option + " " + interface + "\n"
            if (st == 0):
                res += ethtool_interface
            else:
                res += "Could not run command: ethtool " + option + " " + interface
            res += "\n____________\n\n"

        st, ethtool_interface = get_status_output("timeout 10s " + ethtool_command + " " + " -S " + interface)
        if (st != 0):
            ethtool_interface = "Could not run command: ethtool -S " + interface

        filtered_interface_name = interface.replace(":", "").replace(".", "")
        file = open(path + file_name + "/ethtool_S/ethtool_S_" + filtered_interface_name, 'w')
        file.write(ethtool_interface)
        file.close()
        res += "ethtool -S " + interface + "\n"
        res += "<td><a href=ethtool_S/ethtool_S_" + filtered_interface_name + ">ethtool -S " + interface + "</a></td>"
        res += "\n\n--------------------------------------------------"

    return res

#**********************************************************
#        modinfo Handler

def modinfo_handler():
    modules = ["mlx4_core", "mlx4_ib", "mlx4_en", "mlx5_core", "mlx5_ib", "mlx_compat"]
    modinfo = ''
    for module in modules:
        if modinfo != '':
            modinfo += '\n---------------------------------------------------------------\n\n'
        modinfo += "modinfo " + module + " | grep 'filename\|version:'\n\n"
        st, modinfo_module = get_status_output("timeout 10s modinfo " + module + " | grep 'filename\|version:'")
        if (st != 0):
            modinfo_module = "Could not run: " + '"' + "timeout 10s modinfo " + module + " | grep 'filename\|version:'"
        modinfo += modinfo_module + "\n" 
    return modinfo

#**********************************************************
#        cma_roce_mode/tos Handler

def cma_roce_handler(func):
    st, devices = get_status_output("timeout 10s ibstat | grep \"CA '\"")
    if st != 0:
        return "Failed to retrieve mlx devices"
    if devices == "":
        return "There are no mlx devices"
    res = ""
    first = True
    for device in devices.splitlines():
        _device = device.split("'")[1]
        st, _device_res = get_status_output("timeout 10s cma_roce_" + func + " -d " + _device)
        if not first:
            res += "\n\n---------------\n\n"
        res += _device_res
        first = False
    return res


#**********************************************************
#        mlxdump Handler

def mlxdump_handler():
    if not is_MFT_installed:
        return "MFT is not installed, please install MFT and try again."
    dev_st, all_devices = get_status_output("timeout 10s ls /dev/mst")
    if (dev_st != 0):
        return "There are no devices"
    devices = all_devices.split()
    if (len(devices) < 1):
        return "There are no devices"

    options = ["fsdump"]
    for device in devices:
        if not "mtusb" in device:
            for option in options:
                st, res = get_status_output("timeout 30s mlxdump -d /dev/mst/" + device + " " + option + " > " + path + file_name + "/firmware/mlxdump_" + device.replace(":", "").replace(".", "") + "_" + option.replace("-", ""))
    return "Links"

def add_mlxdump_links():
    file_link = {}
    for file in os.listdir(path+file_name+"/firmware"):
        if file.startswith("mlxdump"):
            file_link[file] = "<td><a href=firmware/" + file + ">" + file + "</a></td>"
    return file_link

#**********************************************************
#        fw_ini_dump Handlers

def fw_ini_dump_handler():
    #02:00.0 Ethernet controller: Mellanox Technologies MT27700 Family [ConnectX-4]
    st, lspci_devices = get_status_output("timeout 10s lspci | grep Mellanox ")
    if st != 0:
        return "NULL_1"
    lspci_devices = lspci_devices.splitlines()
    if (len(lspci_devices) < 1):
        return "NULL_1"

    res = 0
    for device in lspci_devices:
        device = device.split()[0]
        st, res_output = get_status_output("timeout 30s flint -d " + device + " q > " + path + file_name + "/firmware/flint_" + device.replace(":", "").replace(".", "") + "_q")
        if st != 0:
            res += st
        st, res_output = get_status_output("timeout 30s flint -d " + device + " dc > " + path + file_name + "/firmware/flint_" + device.replace(":", "").replace(".", "") + "_dc")
        if st != 0:
            res += st

    if mtusb_flag:
        #/dev/mst/mtusb-1                 - USB to I2C adapter as I2C master
        dev_st, mst_devices = get_status_output("timeout 10s mst status | grep ^/ | grep USB")
        if (dev_st != 0):
            return "Failed to run:  mst status | grep ^/ | grep USB"
        devices = mst_devices.splitlines()
        if (len(devices) < 1):
            return "There are no mst devices"
        for device in devices:
            device = device.split()[0]
            dev_path = path + file_name + "/firmware/flint_" + device.split('/')[3]
            st2, res_output = get_status_output("timeout 120s flint -d " + device + " q > " + dev_path + "_q")
            if st2 != 0:
                res += st2
            st2, res_output = get_status_output("timeout 120s flint -d " + device + " dc > " + dev_path + "_dc")
            if st2 != 0:
                res += st2
    if res == 0:
        return "yes"

    return "NULL_2"

def add_fw_ini_dump_links():
    file_link = []
    for file in os.listdir(path + file_name + "/firmware"):
        if (file.startswith("mstflint") or file.startswith("flint")):
            #filtered_file_name = file.translate(None, ':.')
            filtered_file_name = file.replace(":", "").replace(".", "")
            os.rename(path+file_name+"/firmware/"+file, path+file_name+"/firmware/"+filtered_file_name)
            file_link.append("<td><a href=firmware/" + filtered_file_name + ">" + file + "</a></td>")
    return file_link

#**********************************************************
#            ibdev2pcidev Handlers

def ibdev2pcidev_handler():
    script = "if [ -d /sys/class/infiniband ]; then IBDEVS=$(ls /sys/class/infiniband); for ibdev in $IBDEVS; do cd /sys/class/infiniband/$ibdev/device; pcidev=$(pwd -P | xargs basename); echo $ibdev '==>' $pcidev; done; else echo Unable to get ibdev to pci mapping: /sys/class/infiniband does not exist.; fi"
    st, res = get_status_output(script)
    if (st == 0):
        return res
    return "Could not run: " + '"' + "ibdev2pcidev" + '"'

#**********************************************************
#        itrace Handlers

def itrace_handler():
    if not is_MFT_installed:
        return "MFT is not installed, please install MFT and try again."
    dev_st, all_devices = get_status_output("timeout 10s ls /dev/mst")
    if (dev_st != 0):
        return "There are no devices"
    devices = all_devices.split()
    if (len(devices) < 1):
        return "There are no devices"

    options = ["sx1", "rx0", "rx1", "qpc"]
    itrace = ""
    for device in devices:
        if (itrace != ""):
            itrace += "\n---------------------------------------------------------------\n\n"
        flag = 0
        for option in options:
            if (flag != 0):
                itrace += "\n****************************************\n\n"
            itrace += "itrace -d /dev/mst/" + device + " --noddr " + option + "\n\n"
            itrace_st, itrace_device_option = get_status_output("timeout 30s itrace -d /dev/mst/" + device + " --noddr " + option)
            if (itrace_st != 0):
                itrace_device_option = "Could not run: " + '"' + "itrace -d /dev/mst/" + device + " --noddr " + option + '"'
            itrace += itrace_device_option + "\n"
            flag = 1
    return itrace

#**********************************************************
#        itrace Handlers

def mlxcables_options_handler():
    os.system("timeout 10s mst start > /dev/null 2>&1")
    os.system("timeout 10s mst cable add > /dev/null 2>&1")
    os.system("timeout 10s mst cable add --with_ib > /dev/null 2>&1")
    st, mst_status = get_status_output("timeout 10s mst status")
    if not 'Cables:' in mst_status:
        return 'No cables were found'
    mlxcables = mst_status.split('Cables:')[1]
    options = ["--DDM", "--read_all_regs"]
    res = ''
    for mlxcable in mlxcables.splitlines():
        if len(mlxcable) < 2 or mlxcable.startswith('--'):
            continue
        if res != '':
            res += '\n\n---------------------------------------------------------------\n\n'
        flag = 0
        for option in options:
            if flag != 0:
                res += '\n\n****************************************\n\n'
            res += 'mlxcables -d ' + mlxcable + ' ' + option + '\n\n'
            res_st, res_mlxcable_option = get_status_output('timeout 10s mlxcables -d ' + mlxcable + ' ' + option)
            if res_st != 0:
                res_mlxcable_option = 'Could not run: \"mlxcables -d ' + mlxcable + ' ' + option + '"'
            res += res_mlxcable_option
            flag = 1

    return res


def mlxcables_standard_handler():
    os.system("timeout 10s mst start > /dev/null 2>&1")
    os.system("timeout 10s mst cable add > /dev/null 2>&1")
    os.system("timeout 10s mst cable add --with_ib > /dev/null 2>&1")
    st, res = get_status_output("mlxcables")
    return res

#**********************************************************
#               lspci_xxxvvv Handlers

def lspci_xxxvvv_handler():
    cmd = "timeout 10s lspci | awk '{print $1}'"
    if fw_flag == False:
        cmd = "timeout 10s lspci | grep Mell | awk '{print $1}'"
    st, output = get_status_output(cmd)
    if (st == 0 and output == ""):
        return "There are no Mellanox cards"
   
    interfaces = output.splitlines()
    res = ""
    for i in range(0, len(interfaces)):
        st2, output2 = get_status_output("timeout 10s lspci -s " + interfaces[i].strip() + " -xxxvvv")
        if st2 == 0 and output2 != "":
            res += output2
            if i != len(interfaces)-1:
                res += "\n----------------------------------------\n\n"

    if (st == 0):
        return res
    return "Exception was raised while running command."



#**********************************************************
#        mst command -d <device> Handlers

def mstcommand_d_handler(command):
    if not is_MFT_installed:
        return "MFT is not installed, please install MFT and try again."
    dev_st, all_devices = get_status_output("timeout 10s ls /dev/mst")
    if (dev_st != 0):
        return "There are no devices"
    devices = all_devices.split()
    if (len(devices) < 1):
        return "There are no devices"
    
    suffix = ""
    if command == "mlxconfig":
        suffix = " -e q"
    command_result = ""
    for device in devices:
        if (command_result != ""):
            command_result += "\n\n-------------------------------------------------------------\n\n"
        command_result += " " + command + " -d /dev/mst/" + device + suffix + "\n\n"
        mlx_st, command_result_device = get_status_output("timeout 10s " + command + " -d /dev/mst/" + device + suffix)
        if (mlx_st != 0):
            command_result_device = "Could not run: " + command + " -d /dev/mst/" + device + '"'
        command_result += command_result_device
    return command_result

#**********************************************************
#        mstregdump-func Handlers

def mstregdump_func_handler():
    sleep_period = "2"
    st, res = get_status_output("for interface in `lspci | grep Mellanox | grep \"\.0\" | awk '{print $1}'`; do echo yes; for instance in 1 2 3; do temp='_'; temp=$interface$temp$instance; mstregdump $interface  > " + path + file_name + "/firmware/mstregdump_$temp; sleep " + sleep_period + "; done; done")

    st2 = 0
    res2 = ""
    if mtusb_flag:
        if not is_MFT_installed:
            return "MFT is not installed, please install MFT and try again."
        else:
            st2, res2 = get_status_output("for i2c in `mst status | grep ^/ | grep USB | awk '{print $1}'`; do echo yes; for instance in 1 2 3; do temp='_'; interface=${i2c##*/}; temp=$interface$temp$instance; mstdump $i2c  > " + path + file_name + "/firmware/mstdump_$temp; sleep " + sleep_period + "; done; done")

    if st == 0 and res == "" and st2 == 0 and res2 == "":
        return "NULL_1"
    if st == 0 or (st2 == 0 and mtusb_flag):
        return "yes"
    return "NULL_2"

def add_mstregdump_func_links():
    mstregdump_link = {}
    for file in os.listdir(path + file_name + "/firmware"):
        if (file.startswith("mstregdump") or file.startswith("mstdump")):
            #filtered_file_name = file.translate(None, ':.')
            filtered_file_name = file.replace(":", "").replace(".", "")
            os.rename(path+file_name+"/firmware/"+file, path+file_name+"/firmware/"+filtered_file_name)
            mstregdump_link[file] = "<td><a href=firmware/" + filtered_file_name + ">" + file + "</a></td>"
    return mstregdump_link

#**********************************************************
#        show_irq_affinity_all Handlers

def show_irq_affinity_all_handler():    
    if (os.path.exists("/sys/class/net") == False):
        return "No Net Devices"
    net_devices = "" 
    st, net_devices = get_status_output("timeout 10s ls /sys/class/net")
    if (st != 0):
        return "Could not run: " + '"' + "ls /sys/class/net" + '"'
    net_devices += " mlx4 mlx5"
    net_devices = net_devices.split()

    res = ""
    for interface in net_devices:
        if (interface == "lo" or interface == "bonding_masters"):
            continue
        res += "show_irq_affinity.sh " + interface + "\n"
        st, show_irq_affinity = get_status_output("timeout 10s show_irq_affinity.sh " + interface + " 2>/dev/null")

        if (st == 0 and show_irq_affinity != ""):
            res += show_irq_affinity
        else:
            res += "Interface " + interface + " does not exist"
        res += "\n\n--------------------------------------------------\n\n"

    return res

#**********************************************************
#                ZZ Files Handler

def zz_files_handler(root_dir):
    res = ''
    if os.path.isdir(root_dir):
        for root, dirs, files in os.walk(root_dir):
            for infile in files:
                if res != '':
                    res += '\n\n--------------------------------------------------\n\n'
                res += root_dir + infile + ':\n\n'
                try:
                    with open(root_dir + infile, 'r') as zz_file:
                        content = zz_file.read()
                        if content == "":
                            content = "Empty File"
                        res += content
                except Exception as e:
                    res += 'Could not read file\nError message: ' + str(e)
    if res == '':
        return 1, "Please make sure bonding module is loaded, you can do so by running 'modprob bonding'"
    res += '\n\n'
    return 0, res

#----------------------------------------------------------
#        Server Commands Dictionary Handler

col_count=1

iscsiadm_st, iscsiadm_res = get_status_output("timeout 10s iscsiadm --version")

def add_command_if_exists(command):

    if ( (fw_flag == False) and (command in fw_collection) ):
        return
    if ( (pcie_flag == False) and (command in pcie_collection) ):
        return
    if ( (no_ib_flag == True) and (command in ib_collection) ):
        return
    print_err_flag = 1

    # invoke command reguarly if exists or redirect to the corresponding function
    if (command == "date"):
        result = date_cmd
        status = 0
        print_err_flag = 0
    elif (command == "time"):
        result = date_file
        status = 0
        print_err_flag = 0
    elif (command == "service --status-all"):
        status, result = get_status_output("timeout 10s service --status-all")
        if (status == 0 or status == 124):
            print_err_flag = 0
    elif (command == "python_used_version"):
        result = platform.python_version()
        status = 0
    elif (command == "cma_roce_mode"):
        result = cma_roce_handler("mode")
        status = 0
    elif (command == "cma_roce_tos"):
        result = cma_roce_handler("tos")
        status = 0
    elif (command == "mlxdump"):
        result = mlxdump_handler()
        if result == "Links":
            result = add_mlxdump_links()
            global mlxdump_is_string
            mlxdump_is_string = False
        status = 0
        print_err_flag = 0
    elif (command == "show_pretty_gids"):
        result = show_pretty_gids_handler()
        status = 0
        print_err_flag = 0
    elif (command == "ethtool_all_interfaces"):
        result = ethtool_all_interfaces_handler()
        status = 0
        print_err_flag = 0
    elif (command == "modinfo"):
        result = modinfo_handler()
        status = 0
        print_err_flag = 0
    elif ("fw_ini_dump" in command):
        global fw_ini_dump_is_string
        if not is_MFT_installed:
            result = "MFT is not installed, please install MFT and try again."
        else:
            # NULL_1 - no mlx devices, NULL_2 not all devices were quered, yes - all commands invoked correctly 
            fw_output = fw_ini_dump_handler()
            if fw_output == "NULL_1":
                result = "There are no Mellnaox devices"
            elif fw_output == "NULL_2":
                result = add_fw_ini_dump_links()
                result.insert(0, "Warning - not all fw ini dump commands were successfully finished \n\n")
                fw_ini_dump_is_string = False
            else:
                result = add_fw_ini_dump_links()
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
    elif (command == "mlxcables"):
        result = mlxcables_standard_handler()
        status = 0
        print_err_flag = 0
    elif (command == "mlxcables --DDM/--read_all_regs"):
        result = mlxcables_options_handler()
        status = 0
        print_err_flag = 0
    elif (command == "lspci_xxxvvv"):
        result = lspci_xxxvvv_handler()
        status = 0
        print_err_flag = 0
    elif (command == "mlxmcg -d"):
        result = mstcommand_d_handler('mlxmcg')
        status = 0
        print_err_flag = 0
    elif (command == "mlxconfig_query"):
        result = mstcommand_d_handler('mlxconfig')
        status = 0
        print_err_flag = 0
    elif ("mstregdump-func" in command):
        result = mstregdump_func_handler()
        if (result == "NULL_1"):
            result = "There are no Mellanox cards."
        elif (result == "NULL_2"):
            result = "Exception was raised while running the command"
        elif (result == "yes"):
            result = add_mstregdump_func_links()
            global mstreg_dump_is_string
            mstreg_dump_is_string = False
        status = 0
        print_err_flag = 0
    elif (command == "show_irq_affinity_all"):
        result = show_irq_affinity_all_handler()
        status = 0    
        print_err_flag = 0
    elif (command == "yy_MLX_modules_parameters"):
        st, result = get_status_output("awk '{ print FILENAME " + '"' + "=" + '"' + " $0  }' /sys/module/mlx*/parameters/*")
        if (st == 0):
            status = 0
        else:
            status = 1
            print_err_flag = 1
            result = "Could not run: " + '"' + " awk '{ print FILENAME " + '"' + "=" + '"' + " $0  }' /sys/module/mlx*/parameters/* " + '"'
    elif (command == "yy_IB_modules_parameters"):
        st , result = get_status_output("if [ -d /sys/class/infiniband ]; then awk '{ print FILENAME " + '"' + " = " + '"' + " $0  }' /sys/module/ib*/parameters/*; else echo Unable to get ib modules params : /sys/class/infiniband does not exist.; fi")
        if (st == 0):
            status = 0
        else:
            status = 1
            print_err_flag = 1
            result = "Could not run: " + '"' + "if [ -d /sys/class/infiniband ]; then awk '{ print FILENAME " + '"' + " = " + '"' + " $0  }' /sys/module/ib*/parameters/*; else echo Unable to get ib modules params : /sys/class/infiniband does not exist.; fi" + '"'
    elif (command == "zz_proc_net_bonding_files"):
        status, result = zz_files_handler('/proc/net/bonding/')
        if (status == 0):
            if (is_ib == 0):
                status=0
                print_err_flag=0
            else:
                print_err_flag = 1
                status = 1
        else:
            status = 1
            print_err_flag = 1
    elif (command == "zz_sys_class_net_files"):
        status, result = zz_files_handler('/sys/class/net/')
        if (status == 0):    
            if (is_ib == 0):
                status=0
                print_err_flag = 0
            else:
                print_err_flag = 1
                status = 1
        else:
            status = 1
            print_err_flag = 1
    elif ( "teamdctl" in command ):
        print_err_flag = 0
        result = ""
        #e.g ip link ls type team #19: team0.100: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT qlen 1000
        status, ip_link_output = get_status_output("ip link ls type team")
        if (status != 0):
            print_err_flag = 1
            result = "Could not run: " + '"' + "ip link ls type team" + '"'
        
        team_interfaces = re.findall(r'.*?\:(.*)\: <.*',ip_link_output)
        if team_interfaces:
            for team in team_interfaces:
                run_command = "";
                if (command == "teamdctl_state"):
                    run_command = "teamdctl " + team + " state"
                elif (command == "teamdctl_state_view"):
                    run_command = "teamdctl " + team + " state view"
                elif (command == "teamdctl_config_dump"):
                    run_command = "teamdctl " + team + " config dump "
                elif (command == "teamdctl_config_dump_actual"):
                    run_command = "teamdctl " + team + " config dump actual "
                elif (command == "teamdctl_config_dump_noports"):
                    run_command = "teamdctl " + team + " config dump noports"
                status, teamdctl_result = get_status_output(run_command)
                if (status != 0):
                    teamdctl_result = "Could not run: " + '"' + run_command + '"'
                result += teamdctl_result + '\n\n'
    elif "mst status" in command:
        status, result = get_status_output("timeout 10s " + command)
        if status != 0:
            print_err_flag = 1
            result = "Could not run: " + '"' + command + '"'
    elif "ps -eLo" in command:
        status, result = get_status_output("timeout 10s ps -eLo lstart,%cpu,psr,nlwp,f,uid,pid,ppid,pri,rtprio,ni,vsz,rss,stat,tty,time,wchan,args")
        if status != 0:
            print_err_flag = 1
            result = "Could not run: " + '"' + command + '"'
    else:
        # invoking regular command
        status, result = get_status_output("timeout 10s " + command)
        if (status != 0 and not command.startswith("service")):
            if not (iscsiadm_st == 0 and command.startswith("iscsiadm")):
                result = "Could not run: " + '"' + command + '"'

    # if iscsiadm --version command exists, add all isciadm commands to the available ones
    if (iscsiadm_st == 0 and command.startswith("iscsiadm")):
        status = 0

    # add command to server commands dictionaty only if exists
    if ((status == 0) or (command.startswith("service"))):
        server_commands_dict[command] = result
        available_commands_collection.append(command)
    else:
        if (print_err_flag == 1):
            f = open(path+file_name+"/err_messages/dummy_functions", 'a')
            f.write("The full command is: " + command + "\n")
            f.write(result)
            f.write("\n\n")
            f.close()

#----------------------------------------------------------
#        Fabric Commands Dictionary Handler

def multicast_information_handler():
    if (st_saquery != 0):
        return "saquery command is not found"
    
    st, saquery_g = get_status_output("timeout 10s saquery -g 2>/dev/null")
    if (st != 0):
        return "saquery -g command is not found"
    
    res = "MLIDs list: \n" + saquery_g + "\n\nMLIDs members for each multicast group:"
    
    st, MLIDS = get_status_output("timeout 10s saquery -g | grep -i Mlid | sed 's/\./ /g'|awk '{print $2}' | sort | uniq")
    if (st != 0):
        return "Could not run: " + '"' + "saquery -g | grep -i Mlid | sed 's/\./ /g'|awk '{print $2}' | sort | uniq" + '"'
    MLIDS = MLIDS.split()    
    
    for MLID in MLIDS:
        st, saquery_mlid = get_status_output("timeout 10s saquery -m " + MLID + " --smkey 1 2>/dev/null")
        if (st != 0):
            saquery_mlid = "Could not run: " + '"' + "saquery -m " + MLID + " --smkey 1 2>/dev/null" + '"'
        res += "\nMembers of MLID " + MLID + " group:\n" + saquery_mlid + "\n============================================================"
    res += "\n"
    return res

def perfquery_cards_ports_handler():
    if len(installed_cards_ports) == 0:
       return "No Mellanox cards shown in ibstat"
    res = ''
    for card in installed_cards_ports:
        if len(installed_cards_ports[card]) == 0:
            return "No Mellanox ports shown in ibstat"
        for port in installed_cards_ports[card]:
            st, perfquery = get_status_output("timeout 10s perfquery --Ca " + card + " --Port " + port)
            res += perfquery + "\n"
            first = False
    return res


def ib_find_bad_ports_handler(card, port):
    if is_ib != 0:
        return "No ibnetdiscover"
    
    st, iblinkinfo_bad = get_status_output("timeout 10s iblinkinfo --Ca " + card + " --Port " + port + "| grep Could")
    if st != 0:
        return iblinkinfo_bad
    
    res = "iblinkinfo | grep Could\n"
    if iblinkinfo_bad == "":
        res += "\tNo Bad Ports\n"
    else:
        res += iblinkinfo_bad + "\n"
    return res

def ib_find_disabled_ports_handler(card, port):
    if is_ib != 0:
        return "No ibnetdiscover"
    
    st, iblinkinfo_disabled = get_status_output("timeout 10s iblinkinfo --Ca " + card + " --Port " + port + "| grep Disabled")
    if st != 0:
        return iblinkinfo_disabled
    
    res = "iblinkinfo | grep Disabled\n"
    if iblinkinfo_disabled == "":
        res += "\tNo Disabled Ports\n"
    else:
        res += iblinkinfo_disabled + "\n"
    return res

def calc_IP(MGID):
    st, IP = get_status_output("ip=`echo " + MGID + " | awk ' { mgid=$1; n=split(mgid, a, "+'"'+":"+'"'+"); upper=strtonum("+'"'+"0x"+'"'+" a[n-1]); lower=strtonum("+'"'+"0x"+'"'+" a[n]); addr=lshift(upper,16)+lower; addr=or(addr,0xe0000000); a1=and(addr,0xff); addr=rshift(addr,8); a2=and(addr,0xff); addr=rshift(addr,8); a3=and(addr,0xff); addr=rshift(addr,8); a4=and(addr,0xff); printf("+'"'+"%u.%u.%u.%u"+'"'+", a4, a3, a2, a1); }'`; echo $ip")
    if (st == 0):
        return IP
    return "<N/A>"

def ib_mc_info_show_handler():
    if (st_saquery != 0):
        return "saquery command is not found"
    
    MAX_GROUPS=64
    
    st, saquery = get_status_output("timeout 10s saquery -m --smkey 1 2>/dev/null")
    if (st != 0):
        return "Could not run: " + '"' + "saquery -m --smkey 1 2>/dev/null" + '"'
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
                mlids_ip_dict[Mlid_val] = IP
                mlids_count_dict[Mlid_val] += 1
        elif "MGID" in saquery[index]:
            MGID_val = saquery[index].split('.')[-1]
            try:
                #ff12:401b:ffff::1::ff9c:1b7
                ip_header = MGID_val.split(":")[1]
                if ip_header == "401b":
                    IP = calc_IP(MGID_val)
                else:
                    IP = MGID_val
            except (ValueError, IndexError ) as e:
                IP = "<N/A>"
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

def represents_Int(s, base):
    try:
        int(s, base)
        return True
    except ValueError:
        return False

def represents_Int_base_16(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def ib_switches_FW_scan_handler(ibswitches_st, ibswitches, ibdiagnet_suffix):
    if (ibswitches_st != 0):
        return "Failed to run 'ibswitches' command"

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

    for ibswitch in ibswitches.splitlines():
        lid = "N/A"
        if 'lid ' in ibswitch:
            lid = ibswitch.split('lid ')[1].split()[0]

        guid = "N/A"
        if ': ' in ibswitch:
            guid = ibswitch.split(': ')[1].split()[0]

        device_id = "N/A"
        fw_psid = "N/A"
        fw_version = "N/A"
        fw_build_id = "N/A"
        hw_dev_rev = "N/A"
        if ibdiagnet_is_invoked and not ibdiagnet_error:
            tmp_st, row = get_status_output("awk '/START_NODES_INFO/,/END_NODES_INFO/' " + path + file_name + "/"+ ibdiagnet_suffix + "/ibdiagnet/ibdiagnet2.db_csv | grep ^" + guid )
            splt_row = re.split("[" + re.escape(",\n") + "]", row)
            if ( 1 < len(splt_row) and (represents_Int_base_16(splt_row[1]) == True) ):  
                device_id = str(int(splt_row[1], 16))

            if (12 < len(splt_row) ):
                fw_psid = splt_row[12]

            if (16 < len(splt_row) and (represents_Int_base_16(splt_row[14]) == True) and (represents_Int_base_16(splt_row[15]) == True)
                and (represents_Int_base_16(splt_row[16]) == True) ):
                fw_version = str(int(splt_row[14], 16))+"."+str(int(splt_row[15], 16))+"."+str(int(splt_row[16], 16))

            if (7 < len(splt_row) and (represents_Int_base_16(splt_row[7]) == True) ):
                fw_build_id = str(int(splt_row[7], 16))

            if (2 < len(splt_row) and (represents_Int_base_16(splt_row[2]) == True) ):
                hw_dev_rev = str(int(splt_row[2],16))
        else:
            tmp_st, vendstat_N = get_status_output("timeout 10s vendstat -N " + lid)
            if tmp_st == 0:
                vendstat_N = vendstat_N.splitlines()
                for row in vendstat_N:
                    if row.startswith("hw_dev_rev:"):
                        hw_dev_rev = row.split()[-1]
                        if represents_Int_base_16(hw_dev_rev):
                            hw_dev_rev = str(int(hw_dev_rev, 16))
                    elif row.startswith("hw_dev_id:"):
                        device_id = row.split()[-1]
                        if represents_Int_base_16(device_id):
                            device_id = str(int(device_id, 16))
                    elif row.startswith("fw_version:"):
                        fw_version = row.split()[-1]
                    elif row.startswith("fw_build_id:"):
                        fw_build_id = row.split()[-1]
                        if represents_Int_base_16(fw_build_id):
                            fw_build_id = str(int(fw_build_id, 16))
                    elif row.startswith("fw_psid:"):
                        fw_psid = row.split()[-1]

        res += guid
        res += add_spaces(guid)
        res += lid
        res += add_spaces(lid)
        res += device_id
        res += add_spaces(device_id)
        res += fw_psid
        res += add_spaces(fw_psid)
        res += fw_version
        res += add_spaces(fw_version)
        res += fw_build_id
        res += add_spaces(fw_build_id)
        res += hw_dev_rev
        res += "\n"

    res += "---------------------------------------------------------------------------------------------------------------------------------------\n"
    return res

def ib_topology_viewer_handler(card, port):
    if (is_ib != 0):
        return "No ibnetdiscover"

    suffix = card +"_" + port
    st, GUIDS = get_status_output("timeout 10s cat " + path+file_name + "/ibnetdiscover_p_"+ suffix + " | grep -v -i sfb | grep -e ^SW | awk '{print $4}' | uniq")
    if (st != 0):
        return "Could not run: " + '"' + "cat " + path+file_name + "/ibnetdiscover_p_"+ suffix + " | grep -v -i sfb | grep -e ^SW | awk '{print $4}' | uniq" + '"'
    if (GUIDS == ""):
        return "No switches were found"

    GUIDS = GUIDS.split("\n")
    GUIDS.sort()

    res  = "-----------------------------------\n"
    res += "-  Printing topollogy connection  -\n"
    res += "-----------------------------------\n\n"

    for index in range(0, len(GUIDS)):
        if ( len(GUIDS[index].split()) > 1 ):
            continue

        st, desc = get_status_output("timeout 10s cat " + path+file_name + "/ibnetdiscover_p_"+ suffix + " | grep -v -i sfb | grep -e ^SW | grep " + GUIDS[index] + "..x")

        if (st == 0):
            HCA_ports_count = 0
            switch_ports_count = 0
            desc = desc.split("'")[1]

            st, guid_ports = get_status_output("timeout 10s cat " + path+file_name + "/ibnetdiscover_p_"+ suffix + " | grep -v -i sfb | grep -e ^SW | grep " + GUIDS[index] + "..x | awk '{print $8}'")
            if (st == 0):
                guid_ports = guid_ports.split("\n")
                for guid_port in guid_ports:
                    if (guid_port == "CA"):
                        HCA_ports_count += 1
                    elif (guid_port == "SW"):
                        switch_ports_count += 1
            res += desc.ljust(50, ' ')
            tmp = "(" + GUIDS[index] + ")"
            res += tmp.ljust(30, ' ');
            res += str(HCA_ports_count) + " HCA ports and " + str(switch_ports_count) + " switch ports.\n"
    return res

def sm_master_is_handler(card, port):
    if (st_saquery != 0):
         return "saquery command is not found"
    st, MasterLID = get_status_output("timeout 10s /usr/sbin/sminfo -C " + card +" -P " + port + " | awk '{print $4}'")
    if (st != 0):
        return "Could not retrieve Master LID. Reason: Could not run " + '"' + "/usr/sbin/sminfo -C " + card +" -P " + port + " | awk '{print $4}'" + '"'
    st, all_sms = get_status_output("timeout 10s /usr/sbin/smpquery nodedesc " + MasterLID)
    if (st != 0):
        return "Could not retrieve all SM. Reason: Could not run " + '"' + "/usr/sbin/smpquery nodedesc " + MasterLID + '"'
    res = "IB fabric SM master is: (" + all_sms + ")\nAll SMs in the fabric: "

    st, SMS = get_status_output("timeout 10s saquery -s -C " + card +" -P " + port + " 2>/dev/null |grep base_lid |head -1| sed 's/\./ /g'|awk '{print $2}'")
    if (st != 0):
        return "Could not retrieve all SM. Reason: Could not run " + '"' + "saquery -s -C " + card +" -P " + port + " 2>/dev/null |grep base_lid |head -1| sed 's/\./ /g'|awk '{print $2}'" + '"'
    SMS = set(SMS.split())
    
    for SM in SMS:
        st, smquery_nodedesc = get_status_output("timeout 10s /usr/sbin/smpquery nodedesc " + SM)
        if (st != 0):
            smquery_nodedesc = "Could not run " + '"' + "/usr/sbin/smpquery nodedesc " + SM + '"'
        st, sminfo = get_status_output("timeout 10s /usr/sbin/sminfo -C " + card +" -P " + port + " " + SM)
        if (st != 0):
            sminfo = "Could not run " + '"' + "/usr/sbin/sminfo -C " + card +" -P " + port + " " + SM + '"'
        res += "\n\nSM: " + SM + "\n" + smquery_nodedesc + "\n" + sminfo

    return res

def sm_info_handler(card, port):
    status, result = get_status_output("timeout 10s sminfo -C " + card +" -P " + port)
    if (status != 0):
        result = "Couldn't find command: " + command
    return result

def sm_status_handler(card, port):
    SmActivity_1=0
    NoSM=2 
    res = ""
    
    for lo in range(0,4): 
        get_status_output("timeout 10s sleep 3")
        st, SmActivity = get_status_output("timeout 10s sminfo -C " + card +" -P " + port + " |awk '{ print $10 }'")
        if (st != 0):
            SmActivity = "<N/A>"
        st, c_time = get_status_output("timeout 10s date +%T")
        if (st != 0):
            c_time = "time <N/A>"
        c_time = c_time.strip()
        res += "SM activity on " + c_time + " is " + SmActivity + "\n"
        if (SmActivity != "<N/A>" and represents_Int(SmActivity, 10) == True):
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
        st, res = get_status_output("timeout 10s echo OpenSM installed packages: ; timeout 10s rpm -qa | grep opensm")
        if (st != 0):
            res = "Couldn't find command: timeout 10s echo OpenSM installed packages: ; timeout 10s rpm -qa | grep opensm"
    else:
        st, res = get_status_output("timeout 10s echo OpenSM installed packages: ; timeout 10s dpkg -l | grep opensm")
        if (st != 0):
            res = "Couldn't find command: timeout 10s echo OpenSM installed packages: ; timeout 10s dpkg -l | grep opensm"
    return res

def ibdiagnet_handler(card, port, ibdiagnet_suffix):
    global ibdiagnet_res
    global ibdiagnet_error
    suffix = "_" + card + "_" + port
    if (ibdiagnet_is_invoked == False):
        if (os.path.exists(path + file_name + "/" + ibdiagnet_suffix +"/ibdiagnet") == False):
            os.mkdir(path + file_name + "/" + ibdiagnet_suffix + "/ibdiagnet")
        st, ibdiagnet_res = get_status_output("timeout 10s ibdiagnet -r --virtual --sharp_opt dsc -i "+ card +" -p "+ port +" -o " + path + file_name + "/" + ibdiagnet_suffix + "/ibdiagnet")
        if st != 0:
            ibdiagnet_error = True

def clean_ibnodes(ibnodes, start_string):
    res = ""
    ibnodes = ibnodes.split("\n")
    for ibnode in ibnodes:
        if (ibnode.lower().startswith(start_string) == True):
            res += ibnode + "\n"
    return res

def update_saquery():
    global st_saquery
    st_saquery, SAQUERY = get_status_output("timeout 10s saquery 2>/dev/null")


def add_fabric_command_if_exists(command):
    global fabric_commands_dict
    global available_fabric_commands_collection

    if (command == "Multicast_Information"):
        result = multicast_information_handler()
    elif (command == "ib_mc_info_show"):
        result = ib_mc_info_show_handler()
    elif (command == "perfquery_cards_ports"):
        result = perfquery_cards_ports_handler()
    elif (command == "sm_status"):
        result = sm_status_handler()
    elif (command == "sm_version"):
        result = sm_version_handler()
    else:
        # invoking regular command
        status, result = get_status_output("timeout 10s " + command)
        if (status != 0):
            result = "Couldn't find command: " + command

    fabric_commands_dict[command] = result
    available_fabric_commands_collection.append(command)

def add_fabric_multi_sub_command_if_exists(command):
    global ibdiagnet_is_invoked
    global fabric_commands_dict
    global available_fabric_commands_collection

    result = ""
    index = 0
    #multi subnets commands:
    for card in active_subnets:
        for port_obj in active_subnets[card]:
            index += 1
            port = port_obj["port_num"]
            ibdiagnet_suffix = "ibdiagnet_" + card +"_" + port
            suffix = " for the subnet running though card " + card +" port " + port
            result +=  command + suffix + "\n\n"

            if (command == "ib_find_bad_ports"):
                result += ib_find_bad_ports_handler(card, port)
            elif (command == "sm_status"):
                result += sm_status_handler(card, port)
            elif (command == "sminfo"):
                result += sm_info_handler(card, port)
            elif (command == "ib_find_disabled_ports"):
                result += ib_find_disabled_ports_handler(card, port)
            elif (command == "ib_switches_FW_scan"):
                result += ib_switches_FW_scan_handler(port_obj["ibswitches"]["ibswitches_st"], port_obj["ibswitches"]["ibswitches_output"], ibdiagnet_suffix)
            elif (command == "ib_topology_viewer"):
                result += ib_topology_viewer_handler(card, port)
            elif (command == "sm_master_is"):
                result += sm_master_is_handler(card, port)
            elif (command == "ibdiagnet"):
                if ibdiagnet_flag == False:
                    return
                if (ibdiagnet_is_invoked == False):
                    ibdiagnet_handler(card, port, ibdiagnet_suffix)
                    if index == len(all_sm_on_fabric):
                        ibdiagnet_is_invoked = True
                    result += ibdiagnet_res

            elif command == "ibswitches":
                if port_obj["ibswitches"]["ibswitches_st"] != 0:
                    result += "Couldn't find command: ibswitches"
                elif port_obj["ibswitches"]["ibswitches_output"] == "":
                    result += "There are no ibswitches"
                else:
                    result += port_obj["ibswitches"]["ibswitches_output"]
            else:
                # invoking regular command
                status, command_result = get_status_output("timeout 10s " + command + " -C " + card +" -P " + port)
                if (status != 0):
                    result += "Couldn't find command: " + command  + " -C " + card +" -P " + port
                elif result == "" and command == "ibhosts":
                    result += "There are no ibhosts"
                else:
                    result += command_result
            if index != len(all_sm_on_fabric):
                result += "\n\n##################################################\n\n"

    fabric_commands_dict[command] = result
    available_fabric_commands_collection.append(command)
#----------------------------------------------------------
#               Internal Files Dictionary Handler

def add_internal_file_if_exists(file_full_path):
    # put provided file textual content in result
    status, result = get_status_output("timeout 10s cat " + file_full_path)
    
    # add internal file to files dictionary only if exists
    if (status == 0):
        files_dict[file_full_path] = result
        available_internal_files_collection.append(file_full_path)
    else:
        f = open(path+file_name+"/err_messages/dummy_paths", 'a')
        f.write(result)
        f.write("\n\n")
        f.close()

#----------------------------------------------------------
#        External Files Dictionary Handler

# field_name - the field name that will appear in the html
# fil_name - the name of the file that will be linked to
# command_output - is the content of the fil_name

def add_ext_file_handler(field_name, fil_name, command_output):
    if ( fil_name != "pkglist" and (not "erformance" in fil_name) and (not "sr-iov" in fil_name) ):
        f = open(path+file_name+"/"+fil_name, 'w')
        if sys.version_info[0] == 2:
            f.write(command_output)
        elif sys.version_info[0] == 3:
            f.write(command_output.encode('ascii', 'ignore').decode("utf-8"))
        f.close()

    if not ("mlnx_tune" in field_name):
        external_files_dict[field_name] = "<td><a href=" + fil_name + ">" + field_name + "</a></td>"
        available_external_files_collection.append([field_name, fil_name])

def add_external_file_if_exists(field_name, curr_path):
    command_output = ""
    err_flag = 0
    err_command = "No '" + field_name + "' External File\nReason: Couldn't find command: "
    if (field_name == "kernel config"):
        status, command_output = get_status_output("timeout 10s cat " + curr_path)
        if (status == 0):
            st , uname = get_status_output("timeout 10s uname -r")
            if (st == 0):
                add_ext_file_handler(field_name, "config-" + uname.strip(), command_output)
            else:
                err_flag = 1
                err_command += "uname -r"
        else:
            err_flag = 1
            err_command += "cat " + curr_path
    elif (field_name == "config.gz"):
        unrelevant_st, unrelevant_res = get_status_output("if [ -e config.gz ]; then cp /proc/config.gz " + path + file_name + "/config.gz; fi")
        if (unrelevant_st != 0):
            err_flag = 1
            err_command += "if [ -e /proc/config.gz ]; then cp /proc/config.gz " + path + file_name + "/config.gz; fi"
    elif (field_name == "syslog"):
        status, command_output = get_status_output("timeout 10s cat " + curr_path + "messages")
        if (status == 0):
            add_ext_file_handler(field_name, "messages", command_output)
        else:
            status, command_output = get_status_output("timeout 10s cat " + curr_path + "syslog")
            if (status == 0):
                add_ext_file_handler(field_name, "syslog", command_output)
            else:
                err_flag = 1
                err_command += "Neither " + '"' + "cat " + curr_path + "messages" + '"' + " Nor " + '"' + "cat " + curr_path + "syslog" + '"'
    elif (field_name == "libvma.conf"):
        status, command_output = get_status_output("timeout 10s cat " + curr_path)
        if (status == 0):
            add_ext_file_handler(field_name, field_name, command_output)
        else:
            err_flag = 1
            err_command += "cat " + curr_path
    elif (field_name == "ibnetdiscover"):
        if (is_ib == 0 and no_ib_flag == False):
            status, command_output = get_status_output("timeout 10s " + ib_res)
            if (status == 0):
                add_ext_file_handler("ibnetdiscover", "ibnetdiscover", command_output)
                for card in active_subnets:
                    for port in active_subnets[card]:
                        status, command_output = get_status_output("timeout 10s " + ib_res + " -p -C " + card +" -P " + port["port_num"])
                        suffix =  card +"_" + port["port_num"]
                        if (status == 0):
                            add_ext_file_handler("ibnetdiscover -p " + suffix, "ibnetdiscover_p_" + suffix, command_output)
                        else:
                            err_flag = 1
                            err_command = "No 'ibnetdiscover_p' External File\nReason: Couldn't find command: ibnetdiscover -p" + suffix
            else:
                err_flag = 1
                err_command += ib_res
                err_command += "\n\nNo 'ibnetdiscover_p' External File\nReason: Couldn't find command: " + ib_res
        else:
            err_flag = 1
            if (is_ib != 0 and no_ib_flag == True):
                reason = "which ibnetdiscover, and because --no_ib flag was provided"
                err_command += reason + "\n\nNo 'ibnetdiscover_p' External File\nReason: Couldn't find command: " + reason
            if (is_ib == 0 and no_ib_flag == True):
                err_command = "No '" + field_name + "' External File\nReason: --no_ib flag was provided\n\nNo 'ibnetdiscover_p' External File\nReason: --no_ib flag was provided"
            if (is_ib != 0 and no_ib_flag == False):
                err_command += "which ibnetdiscover"
                err_command += "\n\nNo 'ibnetdiscover_p' External File\nReason: Couldn't find command: which ibnetdiscover"
    elif (field_name == "Installed packages"):
        if (cur_os != "debian"):
            status, unrelevant_res = get_status_output("rpm -qva --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH} %{SIZE}\n' | sort  > "+path+file_name+"/pkglist")
        else:
            status, unrelevant_res = get_status_output("dpkg --list > "+path+file_name+"/pkglist")
        if (status == 0):
            add_ext_file_handler(field_name, "pkglist", "")
        else:
            err_flag = 1
            err_command += "No file " + path+file_name+"/pkglist"
    elif (field_name == "Performance tuning analyze"):
        status, command_output = get_status_output("timeout 10s cat " + html2_path)
        if (status == 0):
            add_ext_file_handler(field_name, "performance-tuning-analyze.html", command_output)
        else:
            err_flag = 1
            err_command += html2_path
    elif (field_name == "SR-IOV"):
        status, command_output = get_status_output("timeout 10s cat " + html3_path)
        if status == 0 :
            add_ext_file_handler(field_name, "sr-iov.html", command_output)
        else:
            err_flag = 1
            err_command += html3_path + "\nSince SR-IOV is not activated"
    elif ("mlnx_tune" in field_name):
        status, command_output = get_status_output("timeout 1m ./mlnx_tune -r")
        if not (("No such file or directory" in command_output) or ((status != 0) and not ("Unsupported" in command_output))):
            add_ext_file_handler(field_name, curr_path, command_output)
        else:
            status, command_output = get_status_output("timeout 1m " + field_name)
            if not (status == 0 or ("Unsupported" in command_output)):
                err_flag = 1
                err_command += field_name + " - tool is not installed, and there is no script mlnx_tune"
                err_command += "\nmlnx_tune tool is available on Mellanox OFED 3.0.0 and above"
            else:
                add_ext_file_handler(field_name, curr_path, command_output)
    else:    
        status, command_output = get_status_output("timeout 10s " + field_name)
        if (status == 0):
            if "dmesg" in field_name:
                add_ext_file_handler(field_name, curr_path, command_output)
            else:
                add_ext_file_handler(field_name, field_name, command_output)
        else:
            err_flag = 1
            err_command += field_name
    
    if (err_flag == 1):
        f = open(path+file_name+"/err_messages/dummy_external_paths", 'a')
        f.write(err_command)
        f.write("\n\n")
        f.close()

#----------------------------------------------------------
#        Other System Files Dictionary Handler

def arrange_numa_nodes():
    # numa_nodes
    if cur_os == "debian":
        os.system("timeout 10s exec 2>/dev/null")
    st, numas = get_status_output("timeout 10s find /sys | grep numa_node | grep -v uevent |sort")
    if st != 0:
        return
    res = ""
    for numa in numas.splitlines():
        with open(numa, 'r') as numa_file:
            res += numa + " " + numa_file.read().strip() + "\n"
    other_system_files_dict['numa_nodes'] = res

def arrange_system_files():
    if (no_ib_flag == False):
        if (cur_os != "debian"):
            st, res = get_status_output("NETDEVICES=$(LIST='' ; set -- `ls /sys/class/net`; while [ $# -ne 0 ];do [[ $1 == lo ]] && shift && continue; LIST+=' '; LIST+=$1 ;shift;done ; echo $LIST); for f in $(find /sys | grep infini |grep -v uevent |sort ) ${NETDEVICES}; do if [[ -f $f ]]; then echo File: $f: $(cat $f); fi; done 2>/dev/null")
        else:
            st, res = get_status_output("exec 2>/dev/null; NETDEVICES=$(LIST='' ; set -- `ls /sys/class/net`; while [ $# -ne 0 ];do [[ $1 == lo ]] && shift && continue; LIST+=' '; LIST+=$1 ;shift;done ; echo $LIST); for f in $(find /sys | grep infini |grep -v uevent |sort ) ${NETDEVICES}; do if ! [[ -d $f ]]; then echo File: $f: $(cat $f); fi; done 2>/dev/null")

        if (st == 0 and res != ""):
            lines = res.splitlines()
            res = ""
            for line in lines:
                if not (line.startswith("File:") and line.endswith(":")):
                    res += "\n" + line
            other_system_files_dict['System Files'] = res

#----------------------------------------------------------

def arrange_server_commands_section():

    if verbose_flag:
        print("\tGenerating server commands section has started")
    # add server commands list
    for cmd in commands_collection:
        if is_command_allowed(cmd):
            if verbose_count == 2:
                print("\t\t" + cmd + " - start")
            add_command_if_exists(cmd)
            if verbose_count == 2:
                print("\t\t" + cmd + " - end")
    if verbose_flag:
        print("\tGenerating server commands section has ended")
        print("\t----------------------------------------------------")

def arrange_fabric_commands_section():

    if verbose_flag:
        print("\tGenerating fabric diagnostic information section has started")
    update_saquery()
    # add fabric commands list if configured as IB
    for cmd in fabric_commands_collection:
        if is_command_allowed(cmd):
            if verbose_count == 2:
                print("\t\t" + cmd + " - start")
            add_fabric_command_if_exists(cmd)
            if verbose_count == 2:
                print ("\t\t" + cmd + " - end")
    if verbose_flag:
        print("\tGenerating fabric diagnostic information for multi-subnets commands")

    # add fabric multi-subnets commands list if configured as IB
    for cmd in fabric_multi_sub_commands_collection:
        if is_command_allowed(cmd):
            if verbose_count == 2:
                print("\t\t" + cmd + " - start")
            add_fabric_multi_sub_command_if_exists(cmd)
            if verbose_count == 2:
                print ("\t\t" + cmd + " - end")
    if verbose_flag:
        print("\tGenerating fabric diagnostic information section has ended")


def arrange_internal_files_section():
    if verbose_flag:
        print("\tGenerating internal files section has started")
    # Internal files with static paths handlers
    for static_path in internal_files_collection:
        if is_command_allowed("file: " + static_path):
            if verbose_count == 2:
                print("\t\t" + static_path + " - start")
            add_internal_file_if_exists(static_path)
            if verbose_count == 2:
                print("\t\t" + static_path + " - end")

    # Internal files with dynamic paths handlers
    if (os.path.exists("/etc/modprobe.d/") == True):
        for file in os.listdir("/etc/modprobe.d/"):
            if (os.path.isfile("/etc/modprobe.d/"+file) == True):
                if is_command_allowed("file: /etc/modprobe.d/" + file):
                    if verbose_count == 2:
                        print("\t\t/etc/modprobe.d/" + file + " - start")
                    add_internal_file_if_exists("/etc/modprobe.d/" + file)
                    if verbose_count == 2:
                        print("\t\t/etc/modprobe.d/" + file + " - end")
    if (os.path.exists("/proc/net/vlan/") == True):
        for file in os.listdir("/proc/net/vlan/"):
            if (os.path.isfile("/proc/net/vlan/"+file) == True):
                if is_command_allowed("file: /proc/net/vlan/" +file):
                    if verbose_count == 2:
                        print("\t\t/proc/net/vlan/" + file + " - start")
                    add_internal_file_if_exists("/proc/net/vlan/" + file)
                    if verbose_count == 2:
                        print("\t\t/proc/net/vlan/" + file + " - end")
    if (os.path.exists("/sys/class/infiniband/") == True):
        for file in os.listdir("/sys/class/infiniband/"):
            if (os.path.isfile("/sys/class/infiniband/"+file) == False):
                if is_command_allowed("file: /sys/class/infiniband/" + file + "/board_id"):
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/board_id - start")
                    add_internal_file_if_exists("/sys/class/infiniband/" + file + "/board_id")
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/board_id - end")
                if is_command_allowed("file: /sys/class/infiniband/" + file + "/fw_ver"):
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/fw_ver - start")
                    add_internal_file_if_exists("/sys/class/infiniband/" + file + "/fw_ver")
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/fw_ver - end")
                if is_command_allowed("file: /sys/class/infiniband/" + file + "/hca_type"):
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/hca_type - start")
                    add_internal_file_if_exists("/sys/class/infiniband/" + file + "/hca_type")
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/hca_type - end")
                if is_command_allowed("file: /sys/class/infiniband/" + file + "/hw_rev"):
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/hw_rev - start")
                    add_internal_file_if_exists("/sys/class/infiniband/" + file + "/hw_rev")
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/hw_rev - end")
                if is_command_allowed("file: /sys/class/infiniband/" + file + "/node_desc"):
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/node_desc - start")
                    add_internal_file_if_exists("/sys/class/infiniband/" + file + "/node_desc")
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/node_desc - end")
                if is_command_allowed("file: /sys/class/infiniband/" + file + "/node_guid"):
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/node_guid - start")
                    add_internal_file_if_exists("/sys/class/infiniband/" + file + "/node_guid")
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/node_guid - end")
                if is_command_allowed("file: /sys/class/infiniband/" + file + "/node_type"):
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/node_type - start")
                    add_internal_file_if_exists("/sys/class/infiniband/" + file + "/node_type")
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/node_type - end")
                if is_command_allowed("file: /sys/class/infiniband/" + file + "/sys_image_guid"):
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/sys_image_guid - start")
                    add_internal_file_if_exists("/sys/class/infiniband/" + file + "/sys_image_guid")
                    if verbose_count == 2:
                        print("\t\t/sys/class/infiniband/" + file + "/sys_image_guid - end")

    if (os.path.exists("/sys/devices/system/node/") == True):
        for file in os.listdir("/sys/devices/system/node/"):
            if (os.path.isfile("/sys/devices/system/node/"+file) == False):
                if is_command_allowed("file: /sys/devices/system/node/" + file + "/cpulist"):
                    if verbose_count == 2:
                        print("\t\t/sys/devices/system/node/" + file + "/cpulist - start")
                    add_internal_file_if_exists("/sys/devices/system/node/"+file+"/cpulist")
                    if verbose_count == 2:
                        print("\t\t/sys/devices/system/node/" + file + "/cpulist - end")

    if (cur_os != "debian" and os.path.exists("/etc/sysconfig/network-scripts/") == True):
        for file in os.listdir("/etc/sysconfig/network-scripts/"):
            if ( (os.path.isfile("/etc/sysconfig/network-scripts/"+file) == True) and (file.startswith("ifcfg")) ):
                if is_command_allowed("file: /etc/sysconfig/network-scripts/" + file):
                    if verbose_count == 2:
                        print("\t\t/etc/sysconfig/network-scripts/" + file + " - start")
                    add_internal_file_if_exists("/etc/sysconfig/network-scripts/" + file)
                    if verbose_count == 2:
                        print("\t\t/etc/sysconfig/network-scripts/" + file + " - end")

    if (os.path.exists("/etc/sysconfig/network/") == True):
        for file in os.listdir("/etc/sysconfig/network/"):
            if ( (os.path.isfile("/etc/sysconfig/network/"+file) == True) and (file.startswith("ifcfg-")) ):
                if is_command_allowed("file: /etc/sysconfig/network/" + file):
                    if verbose_count == 2:
                        print("\t\t/etc/sysconfig/network/" + file + " - start")
                    add_internal_file_if_exists("/etc/sysconfig/network/" + file)
                    if verbose_count == 2:
                        print("\t\t/etc/sysconfig/network/" + file + " - end")

    if (os.path.exists("/etc/") == True):
        for file in os.listdir("/etc/"):
            if ( (os.path.isfile("/etc/"+file) == True) and ("release" in file) ):
                if is_command_allowed("file: /etc/"+file):
                    if verbose_count == 2:
                        print("\t\t/etc/" + file + " - start")
                    add_internal_file_if_exists("/etc/"+file)
                    if verbose_count == 2:
                        print("\t\t/etc/" + file + " - end")

    if (os.path.exists("/etc/infiniband/") == True):
        for file in os.listdir("/etc/infiniband/"):
            if (os.path.isfile("/etc/infiniband/"+file) == True):
                if is_command_allowed("file: /etc/infiniband/"+file):
                    if verbose_count == 2:
                        print("\t\t/etc/infiniband/" + file + " - start")
                    add_internal_file_if_exists("/etc/infiniband/"+file)
                    if verbose_count == 2:
                        print("\t\t/etc/infiniband/" + file + " - end")

    if os.path.exists("/sys/class/net/"):
        for indir in os.listdir("/sys/class/net/"):
            if os.path.isfile("/sys/class/net/" + indir) == False:
                if indir.startswith("ib"):
                    if os.path.isfile("/sys/class/net/" + indir + "/mode"):
                        if is_command_allowed("file: /sys/class/net/" + indir + "/mode"):
                            if verbose_count == 2:
                                print("\t\t/sys/class/net/" + indir + "/mode - start")
                            add_internal_file_if_exists("/sys/class/net/" + indir + "/mode")
                            if verbose_count == 2:
                                print("\t\t/sys/class/net/" + indir + "/mode - end")
                    if os.path.isfile("/sys/class/net/" + indir + "/pkey"):
                        if is_command_allowed("file: /sys/class/net/" + indir + "/pkey"):
                            if verbose_count == 2:
                                print("\t\t/sys/class/net/" + indir + "/pkey - start")
                            add_internal_file_if_exists("/sys/class/net/" + indir + "/pkey")
                            if verbose_count == 2:
                                print("\t\t/sys/class/net/" + indir + "/pkey - end")
                    if os.path.isfile("/sys/class/net/" + indir  + "/queues/rx-0/rps_cpus"):
                        if is_command_allowed("file: /sys/class/net/" + indir + "/queues/rx-0/rps_cpus"):
                            if verbose_count == 2:
                                print("\t\t/sys/class/net/" + indir + "/queues/rx-0/rps_cpus - start")
                            add_internal_file_if_exists("/sys/class/net/" + indir + "/queues/rx-0/rps_cpus")
                            if verbose_count == 2:
                                print("\t\t/sys/class/net/" + indir + "/queues/rx-0/rps_cpus - end")
                options = ["cnp_802p_prio", "0", "1", "2", "3", "4", "5", "6", "7"]
                for option in options:
                    file_full_path = "/sys/class/net/" + indir + "/ecn/roce_np/" + option
                    if os.path.isfile(file_full_path):
                        if is_command_allowed("file: " + file_full_path):
                            if verbose_count == 2:
                                print("\t\t " + file_full_path + " - start")
                            add_internal_file_if_exists(file_full_path)
                            if verbose_count == 2:
                                print("\t\t" + file_full_path + " - end")

    if verbose_flag:
        print("\tGenerating internal files section has ended")
        print("\t----------------------------------------------------")

def arrange_external_files_section():

    if verbose_flag:
        print("\tGenerating external files section has started")
    # add external files if exist to the provided external section e.g. "kernel config"
    for pair in external_files_collection:
        if is_command_allowed("file: " + pair[0]):
            if verbose_count == 2:
                print("\t\t" + pair[0] + " - start")
            add_external_file_if_exists(pair[0], pair[1])
            if verbose_count == 2:
                print("\t\t" + pair[0] + " - end")
    if (no_ib_flag == False):
        for pair in perf_external_files_collection:
            if is_command_allowed("file: " + pair[0]):
                if verbose_count == 2:
                    print("\t\t" + pair[0] + " - start")
                add_external_file_if_exists(pair[0], pair[1])
                if verbose_count == 2:
                    print("\t\t" + pair[0] + " - end")
    # Copying files or dirs to the tgz without appearing in the HTML
    for pair in copy_under_files:
        if not os.path.isdir(pair[1]):
            continue
        if is_command_allowed("file: " + pair[1]):
            if verbose_count == 2:
                print("\t\t" + pair[1] + " - start")
            try:
                shutil.copytree(pair[1], path + file_name + "/" + pair[0])
            except:
                pass
            if verbose_count == 2:
                print("\t\t" + pair[1] + " - end")
    if verbose_flag:
        print("\tGenerating external files section has ended")
        print("\t----------------------------------------------------")

def arrange_other_system_files_section():

    if verbose_flag:
        print("\tGenerating other system files section has started")
    
    if is_command_allowed('file: numa_nodes'):
        if verbose_count == 2:
            print("\t\tnuma_node - start")
        arrange_numa_nodes()
        if verbose_count == 2:
            print("\t\tnuma_node - end")
    if is_command_allowed('file: System Files'):
        if verbose_count == 2:
            print("\t\tother_system_files - start")
        arrange_system_files()
        if verbose_count == 2:
            print("\t\tother_system_files - end")
    if verbose_flag:
        print("\tGenerating other system files section has ended")
        if (no_ib_flag == False):
            print("\t----------------------------------------------------")

def arrange_dicts():
    arrange_server_commands_section()
    arrange_internal_files_section()
    arrange_external_files_section()
    arrange_other_system_files_section()
    if (is_ib == 0 and no_ib_flag == False):
        arrange_fabric_commands_section()

#==========================================================
#        SR-IOV Arranging Dictionaries

def ip_link_show_devices_handler():
    if not sys_class_net_exists:
        return "No Net Devices - The path /sys/class/net does not exist"
    res = ""
    first = True
    for pf_device in pf_devices:
        st, ip_link_device = get_status_output("timeout 10s ip link show dev " + pf_device)
        if not first:
            res += "\n\n------------------------------------------------------------\n\n"
            first = False
        if st == 0:
            res += ip_link_device
        else:
            res += "Could not run: " + '"' + "ip link show dev " + pf_device + '"'
    return res

def lspci_vf_handler():
    st, lspci = get_status_output("timeout 10s lspci -tv -d 15b3:")
    if st != 0:
        return st, "Could not run: lspci -tv -d 15b3:"
    
    lspci = lspci.splitlines()
    if len(lspci) <= 1:
        return 0, "No Virtual Functions"
    
    lspci_vf = ""
    for i in range(1, len(lspci)):
        if "Virtual" in lspci[i]:
            if not "Virtual" in lspci[i-1]:
                lspci_vf += lspci[i-1] + "\n"
            lspci_vf += lspci[i] + "\n"

    if lspci_vf == "":
        return 0, "No Virtual Functions"
    return 0, lspci_vf

def add_sriov_command_if_exists(command):

    print_err_flag = 1
    # invoke command reguarly if exists or redirect to the corresponding function
    if command == "ip_link_show_devices":
        result = ip_link_show_devices_handler()
        print_err_flag = 0
        status = 0
    elif command == "lspci_vf":
        status, result = lspci_vf_handler()
        if status != 0:
            print_err_flag = 1
    else:
        # invoking regular command
        status, result = get_status_output("timeout 10s " + command)
        if status != 0:
            result = "Could not run: " + '"' + command + '"'

    # add command to server commands dictionaty only if exists
    if status == 0:
        sriov_commands_dict[command] = result
        available_sriov_commands_collection.append(command)
    else:
        if print_err_flag == 1:
            f = open(path+file_name+"/err_messages/dummy_sriov_functions", 'a')
            f.write("The full command is: " + command + "\n")
            f.write(result)
            f.write("\n\n")
            f.close()

def add_sriov_internal_file_if_exists(file_full_path):

    # put provided file textual content in result
    status, result = get_status_output("timeout 10s cat " + file_full_path)

    # add internal file to files dictionary only if exists
    if (status == 0):
        sriov_internal_files_dict[file_full_path] = result
        available_sriov_internal_files_collection.append(file_full_path)
    else:
        f = open(path+file_name+"/err_messages/dummy_sriov_paths", 'a')
        f.write(result)
        f.write("\n\n")
        f.close()

#----------------------------------------------------------
#    SR-IOV Commands Dictionary Handler

def arrange_sriov_commands_section():
    if verbose_flag:
        print("\t\tGenerating sr-iov commands section has started")
    # add server commands list
    for cmd in sriov_commands_collection:
        if is_command_allowed(cmd):
            if verbose_count == 2:
                print("\t\t\t" + cmd + " - start")
            add_sriov_command_if_exists(cmd)
            if verbose_count == 2:
                print("\t\t\t" + cmd + " - end")
    if verbose_flag:
        print("\t\tGenerating sr-iov commands section has ended")

#----------------------------------------------------------
#    SR-IOV Internal Files Dictionary Handler

def arrange_sriov_internal_files_section():
    if verbose_flag:
        print("\t\t--------------------------------------------")
        print("\t\tGenerating sr-iov internal files section has started")
    # Internal files with static paths handlers
    for static_path in sriov_internal_files_collection:
        if is_command_allowed("file: " + static_path):
            if verbose_count == 2:
                print("\t\t\t" + static_path + " - start")
            add_sriov_internal_file_if_exists(static_path)
            if verbose_count == 2:
                print("\t\t\t" + static_path + " - end")

    # Internal files with dynamic paths handlers
    if os.path.exists("/sys/class/infiniband/"):
        for indir in os.listdir("/sys/class/infiniband/"):
            if os.path.exists("/sys/class/infiniband/"+ indir + "/device/"):
                for infile in os.listdir("/sys/class/infiniband/"+ indir + "/device/"):
                    if (infile.startswith("sriov") or infile.startswith("mlx")) and os.path.isfile("/sys/class/infiniband/"+ indir + "/device/" + infile):
                        if is_command_allowed("file: /sys/class/infiniband/"+ indir + "/device/" + infile):
                            if verbose_count == 2:
                                print("\t\t\t/sys/class/infiniband/"+ indir + "/device/" + infile + " - start")
                            add_sriov_internal_file_if_exists("/sys/class/infiniband/"+ indir + "/device/" + infile)
                            if verbose_count == 2:
                                print("\t\t\t/sys/class/infiniband/"+ indir + "/device/" + infile + " - end")
            if os.path.exists("/sys/class/infiniband/" + indir + "/iov/"):
                if os.path.exists("/sys/class/infiniband/" + indir + "/iov/ports/"):
                    for indir2 in os.listdir("/sys/class/infiniband/" + indir + "/iov/ports/"):
                        if represents_int(indir2) and int(indir2) >= 0 and int(indir2) <= 127:
                            if os.path.isfile("/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/gids/" + indir2):
                                if is_command_allowed("file: /sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/gids/" + indir2):
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/gids/" + indir2 + " - start")
                                    add_sriov_internal_file_if_exists("/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/gids/" + indir2)
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/gids/" + indir2 + " - end")
                            if os.path.isfile("/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/admin_guids/" + indir2):
                                if is_command_allowed("file: /sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/admin_guids/" + indir2):
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/admin_guids/" + indir2 + " - start")
                                    add_sriov_internal_file_if_exists("/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/admin_guids/" + indir2)
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/admin_guids/" + indir2 + " - end")
                            if int(indir2) <= 126:
                                if os.path.isfile("/sys/class/infiniband/" + indir + "/iov/ports/"  + indir2 + "/pkeys/" + indir2):
                                    if is_command_allowed("file: /sys/class/infiniband/" + indir + "/iov/ports/"  + indir2 + "/pkeys/" + indir2):
                                        if verbose_count == 2:
                                            print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/"  + indir2 + "/pkeys/" + indir2 + " - start")
                                        add_sriov_internal_file_if_exists("/sys/class/infiniband/" + indir + "/iov/ports/"  + indir2 + "/pkeys/" + indir2)
                                        if verbose_count == 2:
                                            print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/"  + indir2 + "/pkeys/" + indir2 + " - end")
                for indir2 in os.listdir("/sys/class/infiniband/" + indir + "/iov/"):
                    if indir2.startswith("0000"):
                        for m in range(1,3):
                            if os.path.isfile("/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/gid_idx/0"):
                                if is_command_allowed("file: /sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/gid_idx/0"):
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/gid_idx/0 - start")
                                    add_sriov_internal_file_if_exists("/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/gid_idx/0")
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/gid_idx/0 - end")
                            for n in range(127):    # 0 <= n <= 126
                                if os.path.isfile("/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/pkey_idx/" + str(n)):
                                    if is_command_allowed("file: /sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/pkey_idx/" + str(n)):
                                        if verbose_count == 2:
                                            print("\t\t\t/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/pkey_idx/" + str(n) + " - start")
                                        add_sriov_internal_file_if_exists("/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/pkey_idx/" + str(n))
                                        if verbose_count == 2:
                                            print("\t\t\t/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/pkey_idx/" + str(n) + " - end")

    if os.path.exists("/sys/bus/pci/drivers/"):
        for indir in os.listdir("/sys/bus/pci/drivers/"):
            if indir.endswith("core"):
                if is_command_allowed("file: /sys/bus/pci/drivers/"+ indir + "/unbind"):
                    if verbose_count == 2:
                        print("\t\t\t/sys/bus/pci/drivers/"+ indir + "/unbind - start")
                    add_sriov_internal_file_if_exists("/sys/bus/pci/drivers/"+ indir + "/unbind")
                    if verbose_count == 2:
                        print("\t\t\t/sys/bus/pci/drivers/"+ indir + "/unbind - end")
                if is_command_allowed("file: /sys/bus/pci/drivers/"+ indir + "/bind"):
                    if verbose_count == 2:
                        print("\t\t\t/sys/bus/pci/drivers/"+ indir + "/bind - start")
                    add_sriov_internal_file_if_exists("/sys/bus/pci/drivers/"+ indir + "/bind")
                    if verbose_count == 2:
                        print("\t\t\t/sys/bus/pci/drivers/"+ indir + "/bind - end")

    if os.path.exists("/etc/sysconfig/network-scripts/"):
        for infile in os.listdir("/etc/sysconfig/network-scripts/"):
            if infile.startswith("ifcfg-"):
                if is_command_allowed("file: /etc/sysconfig/network-scripts/" + infile):
                    if verbose_count == 2:
                        print("\t\t\t/etc/sysconfig/network-scripts/" + infile + " - start")
                    add_sriov_internal_file_if_exists("/etc/sysconfig/network-scripts/" + infile)
                    if verbose_count == 2:
                        print("\t\t\t/etc/sysconfig/network-scripts/" + infile + " - end")

    if os.path.exists("/sys/class/net/"):
        for indir in os.listdir("/sys/class/net/"):
            if os.path.isfile("/sys/class/net/" + indir) == False and (indir.startswith("eth") or indir.startswith("ib")):
                for inSomething in os.listdir("/sys/class/net/" + indir + "/"):
                    if os.path.isfile("/sys/class/net/" + indir + "/" + inSomething) == False:
                        if os.path.isfile("/sys/class/net/" + indir + "/" + inSomething + "/tx_rate"):
                            if is_command_allowed("file: /sys/class/net/" + indir + "/" + inSomething + "/tx_rate"):
                                if verbose_count == 2:
                                    print("\t\t\t/sys/class/net/" + indir + "/" + inSomething + "/tx_rate - start")
                                add_sriov_internal_file_if_exists("/sys/class/net/" + indir + "/" + inSomething + "/tx_rate")
                                if verbose_count == 2:
                                    print("\t\t\t/sys/class/net/" + indir + "/" + inSomething + "/tx_rate - end")
                    elif inSomething.startswith("fdb") or inSomething.startswith("mode") or inSomething.startswith("pkey"):
                        if os.path.isfile("/sys/class/net/" + indir + "/" + inSomething):
                            if is_command_allowed("file: /sys/class/net/" + indir + "/" + inSomething):
                                if verbose_count == 2:
                                    print("\t\t\t/sys/class/net/" + indir + "/" + inSomething + " - start")
                                add_sriov_internal_file_if_exists("/sys/class/net/" + indir + "/" + inSomething)
                                if verbose_count == 2:
                                    print("\t\t\t/sys/class/net/" + indir + "/" + inSomething + " - end")

    if os.path.exists("/sys/bus/pci/devices/"):
        for indir in os.listdir("/sys/bus/pci/devices/"):
            if os.path.isfile("/sys/bus/pci/devices/" + indir) == False:
                if os.path.isfile("/sys/bus/pci/devices/" + indir + "/reset"):
                    if is_command_allowed("file: /sys/bus/pci/devices/" + indir + "/reset"):
                        if verbose_count == 2:
                            print("\t\t\t/sys/bus/pci/devices/" + indir + "/reset - start")
                        add_sriov_internal_file_if_exists("/sys/bus/pci/devices/" + indir + "/reset")
                        if verbose_count == 2:
                            print("\t\t\t/sys/bus/pci/devices/" + indir + "/reset - end")

    if verbose_flag:
        print("\t\tGenerating sr-iov internal files section has ended")


def arrange_sriov_dicts():
    arrange_sriov_commands_section()
    arrange_sriov_internal_files_section()

###########################################################
###############  Out File Name Handlers ###################

def get_json_file_name():
    hst, curr_hostname = get_status_output("hostname")
    #curr_hostname = invoke_command(['hostname']).replace('\n', '-')
    json_file_name = "sysinfo-snapshot-v" + version + "-" + curr_hostname.replace('\n', '-') + date_file
    return json_file_name

file_name = get_json_file_name()

###########################################################
############### Print Handlers ############################

def print_in_process():
    print("sysinfo-snapshot is still in proccess...please wait till completed successfuly")
    print("Gathering the information may take a while, especially in large networks\n")

def print_destination_out_file():
    global csvfile
    if (verbose_flag == False):
        print("------------------------------------------------------------\n")
    print("Running sysinfo-snapshot has ended successfully!")
    print("Temporary destination directory is " + path)
    print("Out file name is " + path + file_name + ".tgz\n")
    if (os.path.exists(path + file_name) == True and os.path.isfile(path + file_name) == False):
        print(path + file_name + ".tgz:")
        for fi in sorted(os.listdir(path + file_name)):
            if (fi == "err_messages"):
                print("err_messages:")
                print("\tdummy_functions \t- contains all not found commands")
                print("\tdummy_paths \t\t- contains all not existing internal files (/paths)")
                print("\tdummy_external_paths \t- contains all not existing external files (/paths)")
            elif (fi == "ethtool_S"):
                print("ethtool_S \t\t\t- contains all files which are generated from invoking ethtool -S <interface>")
            elif (fi == "firmware"):
                print("firmware \t\t\t- contains all firmware files (mst dump files and flint output)")
            elif (fi == "ibdiagnet"):
                print("ibdiagnet \t\t\t- contains all files generated from invoking ibdiagnet")
            elif (fi == "etc_udev_rulesd"):
                print("etc_udev_rulesd \t\t- contains all files under /etc/udev/rules.d")
            elif (fi == "lib_udev_rulesd"):
                print("lib_udev_rulesd \t\t- contains all files under /lib/udev/rules.d")
            else:
                print(fi)


def show_error_message(err_msg):
    print("Error: Unknown option/s: " + err_msg)

###########################################################
############## Main Function's Handlers ###################

# Remove all unwanted side effect files and folders
def remove_unwanted_files():
    # Remove mstflint_lockfiles directory
    get_status_output("rm -rf /tmp/mstflint_lockfiles")
    #invoke_command(['rm', '-rf', "/tmp/mstflint_lockfiles"])
    
    # Remove untared directory out file
    get_status_output("rm -rf " + path + file_name)
    #invoke_command(['rm', '-rf', path+file_name])

    # Remove all unwanted side effect files
    if (os.path.exists(path) == True):
        for file in os.listdir(path):
            if (file.startswith("tmp.") or file.startswith("hsqldb.")):
                get_status_output("rm -rf " + path + file)
                #invoke_command(['rm', '-rf', path+file])

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
        get_status_output("mkdir -p " + path)
        #invoke_command(['mkdir', '-p', path])
        path_is_generated = 1

###########################################################
#        Performance Analyze Handlers

#it is recommended to have irqbalance off
def irqbalance():
    key = "IRQ Affinity"
    st, irqbalance = get_status_output("timeout 10s service irqbalance status")
    if (st == 0):
        if ("running" in irqbalance):
            perf_status_dict[key] = "Warning"
            perf_val_dict[key] = "service irqbalance is running"
        else:
            perf_status_dict[key] = "OK"
            perf_val_dict[key] = "service irqbalance is stopped"
    else:
        perf_val_dict[key] = "command not found: 'service irqbalance status'"

#----------------------------------------------------------

def core_frequency():
    key = "Core Frequency"
    st, cpuinfo = get_status_output("timeout 10s cat /proc/cpuinfo")
    if (st != 0):
        perf_val_dict[key] = "command not found: 'cat /proc/cpuinfo'"
        return
    perf_status_dict[key] = "OK"
    perf_val_dict[key] = "CPU is set to max performance"

    cpuinfo = cpuinfo.splitlines()
    max_freq = 0.0
    cur_freq = 0.0
    for line in cpuinfo:
        if (line.startswith("model name") and ("GHz" in line)):
            try:
                max_freq = float(line.split("GHz")[0].split(' ')[-1])
            except ValueError:
                max_freq = -1.0
        if (line.startswith("cpu MHz")):
            try:
                cur_freq = float(float(line.split(' ')[-1])/1000.0)
            except ValueError:
                cur_freq = -1.0
            if ((max_freq - cur_freq) >= 0.1):
                perf_status_dict[key] = "Warning"
                perf_val_dict[key] = "CPU is not set to max performance >>> CPU frequency is below maximum. Install cpupowerutils and run x86_energy_perf_policy performance."

#----------------------------------------------------------

#If the number of siblings doesn't match the number of cores, HyperThreading is on
#it is recommended to have hyperthreading off
def hyper_threading():
    key = "Hyper Threading"

    st, siblings = get_status_output("timeout 10s cat /proc/cpuinfo | grep " + '"' + "siblings" + '"')
    if (st != 0):
        st, siblings_lines_num = get_status_output("timeout 10s cat /proc/cpuinfo | grep " + '"' + "siblings" + '"' + " | wc -l")
        if (st == 0 and represents_int(siblings_lines_num) and int(siblings_lines_num)==0):
            siblings = ""
        else:
            perf_val_dict[key] = "command not found: cat /proc/cpuinfo | grep " + '"' + "siblings" + '"'
            return

    st, cpu_cores = get_status_output("timeout 10s cat /proc/cpuinfo | grep " + '"' + "cpu cores" + '"')
    if (st != 0):
        st, cpu_cores_lines_num = get_status_output("timeout 10s cat /proc/cpuinfo | grep " + '"' + "cpu cores" + '"' + " | wc -l")
        if (st == 0 and represents_int(cpu_cores_lines_num) and int(cpu_cores_lines_num)==0):
            cpu_cores = ""
        else:
            perf_val_dict[key] = "command not found: cat /proc/cpuinfo | grep " + '"' + "cpu cores" + '"'
            return
   
    siblings = siblings.splitlines()
    sib_count = 0
    for line in siblings:
        if represents_int(line.split(" ")[-1]):
            sib_count += int(line.split(" ")[-1])
    
    cpu_cores = cpu_cores.splitlines()
    cores_count = 0
    for line in cpu_cores:
        if represents_int(line.split(" ")[-1]):
            cores_count += int(line.split(" ")[-1])

    if (sib_count == cores_count):
        perf_status_dict[key] = "OK"
        perf_val_dict[key] = "Inactive"
    else:
        perf_status_dict[key] = "Warning"
        perf_val_dict[key] = "Active"

#----------------------------------------------------------

ip_forwarding_status = {}
ip_forwarding_status["IPv4"] = not_present
ip_forwarding_status["IPv6"] = not_present

ip_forwarding_val = {}
ip_forwarding_val["IPv4"] = not_available
ip_forwarding_val["IPv6"] = not_available

def ipv_forwarding(key, path):
    global ip_forwarding_status
    global ip_forwarding_val

    st, ipv = get_status_output("timeout 10s cat " + path)
    if (st != 0 or ("No such file or directory" in ipv)):
        ip_forwarding_val[key] = "command not found: cat " + path
        return

    if (ipv == ""):
        ip_forwarding_val[key] = "command is empty: cat " + path
    else:
        ip_forwarding_status[key] = present
        if (ipv.strip() == "1"):
            ip_forwarding_val[key] = "Active"
        else:
            ip_forwarding_val[key] = "Inactive"

def ip_forwarding():
    key = "IP Forwarding"
    ipv_forwarding("IPv4", "/proc/sys/net/ipv4/ip_forward")
    ipv_forwarding("IPv6", "/proc/sys/net/ipv6/conf/all/forwarding")
    if (ip_forwarding_status["IPv4"] == not_present or ip_forwarding_status["IPv6"] == not_present):
        perf_status_dict[key] = "Warning"
    else:
        perf_status_dict[key] = "OK"

#----------------------------------------------------------

pci_devices = []
direct = False

def lspci(check_latest):
    global pci_devices
    global direct

    key = "PCI Configurations"
    #lspci -d 15b3: - e.g 81:00.0 Ethernet controller: Mellanox Technologies MT27800 Family [ConnectX-5]
    st, cards_num = get_status_output("timeout 10s lspci -d 15b3: | wc -l")
    if (st != 0 or ("command not found" in cards_num) or represents_int(cards_num) == False):
        perf_status_dict[key]    = "OK"
        perf_val_dict[key]    = " lspci: command not found"
        direct = True
        return
    elif (cards_num == "0"):
        perf_status_dict[key] = "OK"
        perf_val_dict[key] = "There are no Mellanox cards"
        direct = True
        return

    st, mlnx_cards = get_status_output("timeout 10s lspci -d 15b3:")
    if (st != 0 or ("command not found" in mlnx_cards)):
        perf_val_dict[key] = "command not found: lspci -d 15b3:"
        direct = True
        return
    mlnx_cards = mlnx_cards.splitlines()
    i = -1
    for card in mlnx_cards:
        i += 1
        card_pci = card.split()[0]
        pci_devices.append({"status":"OK", "name":card, "current_fw":"", "psid":"", "desired_gen":3.0, "current_gen":3.0, "desired_speed":8.0, "current_speed":8.0, "desired_width":8.0, "current_width":8.0, "desired_payload_size":256.0, "current_payload_size":8.0, "desired_max_read_request":4096.0, "current_max_read_request":4096.0})

        if ( (not "[" in card) or (not "]" in card) ):
            pci_devices[i]["status"] = not_available
            pci_devices[i]["desired_gen"] = not_available
            continue
        card = card.split("[")[1]
        card = card.split("]")[0]
        card = card.lower()

        if (("-ib" in card) or ("pro" in card) or ("x-3" in card) or ("x3" in card) or ("x-4" in card) or ("x4" in card) or ("x-5" in card) or ("x5" in card) or ("connectib" in card)):
            pci_devices[i]["desired_gen"] = 3.0
        else:
            if ("pcie 2.0" in card):
                pci_devices[i]["desired_gen"] = 2.0
                pci_devices[i]["desired_width"] = 8.0
            elif (("x-2" in card) or ("x2" in card)):
                pci_devices[i]["desired_gen"] = 2.0
                pci_devices[i]["desired_width"] = 4.0
            else:
                pci_devices[i]["desired_gen"] = 1.0
                pci_devices[i]["desired_width"] = 4.0
            pci_devices[i]["desired_speed"] = 5.0
            pci_devices[i]["desired_payload_size"] = 256.0
            pci_devices[i]["desired_max_read_request"] = 512.0

        if (("-ib" in card) or ("connectib" in card) or ("x4" in card) or ("x-4" in card) or ("x-5" in card) or ("x5" in card)):
            pci_devices[i]["desired_width"] = 16.0

        st, firmwares_query = get_status_output("mstflint -d " + card_pci + " q | grep  'FW Version\|'^PSID'' ")
        if (st == 0):
            #firmwares_query :-
            #FW Version:            16.18.1000
            #PSID:                  MT_0000000008
            firmwares_query = firmwares_query.splitlines()
            pci_devices[i]["current_fw"] = (firmwares_query[0]).split()[-1]
            pci_devices[i]["psid"] = (firmwares_query[1]).split()[-1]
            if check_latest:
                if is_command_allowed('mlxfwmanager_online-query-psid'):
                    st, check_latest_fw = get_status_output("mlxfwmanager --online-query-psid " + pci_devices[i]["psid"] + " | grep -w FW" )
                    if (st == 0):
                        #     FW             14.20.1010
                        check_latest_fw = check_latest_fw.splitlines()
                        if LooseVersion(check_latest_fw[0].split()[-1] ) > LooseVersion(pci_devices[i]["current_fw"]):
                            pci_devices[i]["status"] = "Warning"
                            pci_devices[i]["current_fw"] = 'Warning the current Firmware- ' + pci_devices[i]["current_fw"] + ', is not latest - ' + check_latest_fw[0].split()[-1]

    st, cards_xxx = get_status_output("timeout 10s lspci -d 15b3: -xxx | grep ^70")
    if (st != 0):
        perf_val_dict[key] = "command not found: lspci -d 15b3: -xxx | grep ^70"
        direct = True
        return
    i = -1
    cards_xxx = cards_xxx.splitlines()
    for card_xxx in cards_xxx:
        i += 1
        if (len(card_xxx.split())<4):
            pci_devices[i]["status"] = not_available
            pci_devices[i]["current_gen"] = not_available
            continue
        card_cur_gen = card_xxx.split()[3]
        if (len(card_cur_gen) > 1):
            try:
                pci_devices[i]["current_gen"] = float(card_cur_gen[1])
            except ValueError:
                pci_devices[i]["current_gen"] = -1.0
        else:
            pci_devices[i]["current_gen"] = -1.0
    st, cards_speed_width = get_status_output("timeout 10s lspci -d 15b3: -vvv | grep -i Speed")
    if (st != 0):
        perf_val_dict[key] = "command not found: lspci -d 15b3: -vvv | grep -i Speed"
        direct = True
        return
    i = -1
    cards_speed_width = cards_speed_width.splitlines()
    for line in cards_speed_width:
        line = line.lower()
        if ("lnksta:" in line):
            i += 1
            try:
                pci_devices[i]["current_speed"] = float((line.split("gt/s")[0]).split()[-1])
            except ValueError:
                pci_devices[i]["current_speed"] = -1.0
            if (len(line.split("width x")) > 1):
                try:
                    pci_devices[i]["current_width"] = float((line.split("width x")[1]).split(",")[0])
                except ValueError:
                    pci_devices[i]["current_width"] = -1.0
            else:
                pci_devices[i]["current_width"] = -1.0
    st, cards_payload_read = get_status_output("timeout 10s lspci -d 15b3: -vvv | grep -i MaxReadReq")
    if (st != 0):
        perf_val_dict[key] = "command not found: lspci -d 15b3: -vvv | grep -i MaxReadReq"
        direct = True
        return
    i = -1
    cards_payload_read = cards_payload_read.splitlines()
    for line in cards_payload_read:
        line = line.lower()
        if "timed out" in line:
            continue
        if "maxreadreq" in line:
            i += 1
            try:
                pci_devices[i]["current_payload_size"] = float((line.split(" bytes,")[0]).split()[-1])
            except ValueError:
                pci_devices[i]["current_payload_size"] = -1.0
            if (len(line.split("maxreadreq ")) > 1):
                try:
                    pci_devices[i]["current_max_read_request"] = float((line.split("maxreadreq ")[1]).split()[0])
                except ValueError:
                    pci_devices[i]["current_max_read_request"] = -1.0
            else:
                pci_devices[i]["current_max_read_request"] = -1.0
    for i in range(0, len(pci_devices)):
        if (pci_devices[i]["status"] == not_available):
            continue
        if (pci_devices[i]["current_gen"] < pci_devices[i]["desired_gen"]):
            pci_devices[i]["status"] = "Warning"
            perf_status_dict[key] = "Warning"
        elif (pci_devices[i]["current_speed"] < pci_devices[i]["desired_speed"]):
            pci_devices[i]["status"] = "Warning"
            perf_status_dict[key] = "Warning"
        elif (pci_devices[i]["current_payload_size"] < pci_devices[i]["desired_payload_size"]):
            pci_devices[i]["status"] = "Warning"
            perf_status_dict[key] = "Warning"
        elif (pci_devices[i]["current_max_read_request"] < pci_devices[i]["desired_max_read_request"]):
            pci_devices[i]["status"] = "Warning"
            perf_status_dict[key] = "Warning"

#----------------------------------------------------------

def amd():
    key = "AMD"
    st, manufacturer = get_status_output("timeout 10s dmidecode -s processor-manufacturer")
    if (st != 0):
        perf_val_dict[key] = "command not found: dmidecode -s processor-manufacturer"
        return

    if "amd" in manufacturer.lower():
        perf_status_dict[key] = "Warning"
        perf_val_dict[key] = "AMD based platform"
    else:
        perf_status_dict[key] = "OK"
        perf_val_dict[key] = "Not AMD based platform"

#----------------------------------------------------------

def memlock():
    key = "Memory Allocation"
    global perf_status_dict
    global perf_val_dict
    st, count = get_status_output("timeout 10s cat /etc/security/limits.conf | grep memlock | wc -l")
    if (st != 0 or ("command not found" in count) or (count == "") or (count == "0")):
        perf_status_dict[key] = not_present
        perf_val_dict[key] = ""
    else:
        st, memlock = get_status_output("timeout 10s cat /etc/security/limits.conf | grep memlock")
        if (st != 0):
            perf_status_dict[key] = not_present
            perf_val_dict[key] = ""
        else:
            perf_status_dict[key] = present
            perf_val_dict[key] = memlock

#----------------------------------------------------------

bandwidth = {}
latency = {}

def bw_and_lat():
    global bandwidth
    global latency
    st, devices = get_status_output("timeout 10s ls /sys/class/infiniband")
    if (st != 0 or ("No such file or directory" in devices)):
        try:
            perf_setting_collection.remove("Bandwidth")
            perf_setting_collection.remove("Latency")
        except:
            pass
        return

    devices = devices.split()
    if len(devices) <= 0:
        return
    st, show_gids = get_status_output("timeout 10s show_gids | sort -k5,6 --numeric-sort")
    if st != 0:
       show_gids = ""
    for device in devices:
        bandwidth[device] = ""
        cmd = "timeout 10s ib_write_bw --report_gbits -d " + device + " >/dev/null & sleep 2; timeout 10s ib_write_bw --report_gbits -d " + device + " localhost"
        st, bandwidth[device] = getstatusoutput(cmd)
        bandwidth[device] = cmd + "\n\n" + bandwidth[device]
        cmd = "timeout 10s ib_write_lat -d " + device + " >/dev/null & sleep 2; timeout 10s ib_write_lat -d " + device + " localhost"
        st, latency[device] = getstatusoutput(cmd)
        latency[device] = cmd + "\n\n" + latency[device]
        if device in show_gids:
            try:
                data = show_gids.split(device)[-1].splitlines()[0].strip().split()
                if len(data)>=5:
                    index = data[1]
                    bandwidth[device] += "\n\n##################################################\n\n"
                    cmd = "timeout 10s ib_write_bw -d " + device + " -x" + index + " >/dev/null & sleep 2; timeout 10s ib_write_bw -d " + device + " -x" + index + " localhost"
                    bandwidth[device] += cmd + "\n\n"
                    st, bandwidth_x = getstatusoutput(cmd)
                    bandwidth[device] += bandwidth_x
                    latency[device] += "\n\n##################################################\n\n"
                    cmd = "timeout 10s ib_write_lat -d " + device + " -x" + index + " >/dev/null & sleep 2; timeout 10s ib_write_lat -d " + device + " -x" + index + " localhost" 
                    latency[device] += cmd + "\n\n"
                    st, latency_x = getstatusoutput(cmd)
                    latency[device] += latency_x
            except:
                pass

#==========================================================

def init_status_dict():
    for key in perf_setting_collection:
        perf_status_dict[key] = not_available
        perf_val_dict[key] = not_available

def perform_checkings():

    if is_command_allowed('hyper_threading'):
        if verbose_count == 2:
            print("\t\t\thyper_threading - start")
        hyper_threading()
        if verbose_count == 2:
            print("\t\t\thyper_threading - end")
    if is_command_allowed('core_frequency'):
        if verbose_count == 2:
            print("\t\t\tcore_frequency - start")
        core_frequency()
        if verbose_count == 2:
            print("\t\t\tcore_frequency - end")
    if is_command_allowed('irqbalance'):
        if verbose_count == 2:
            print("\t\t\tirqbalance - start")
        irqbalance()
        if verbose_count == 2:
            print("\t\t\tirqbalance - end")
    if is_command_allowed('lspci'):
        if verbose_count == 2:
            print("\t\t\tlspci - start")
        lspci(check_fw_flag)
        if verbose_count == 2:
            print("\t\t\tlspci - end")
    if is_command_allowed('amd'):
        if verbose_count == 2:
            print("\t\t\tamd - start")
        amd()
        if verbose_count == 2:
            print("\t\t\tamd - end")
    if is_command_allowed('memlock'):
        if verbose_count == 2:
            print("\t\t\tmemlock - start")
        memlock()
        if verbose_count == 2:
            print("\t\t\tmemlock - end")
    if (is_ib != 0):
        if is_command_allowed('ip_forwarding'):
            if verbose_count == 2:
                print("\t\t\tip_forwarding - start")
            ip_forwarding()
            if verbose_count == 2:
                print("\t\t\tip_forwarding - end")
    elif (no_ib_flag == False and perf_flag == True):
        if is_command_allowed('bw_and_lat'):
            if verbose_count == 2:
                print("\t\t\tbw_and_lat - start")
            bw_and_lat()
            if verbose_count == 2:
                print("\t\t\tbw_and_lat - end")

def generate_perf_table():
    init_status_dict()
    perform_checkings()

###########################################################
###########################################################
#        HTML Handlers

#==========================================================
#    Main Sysinfo-Snapshot HTML #1 Handlers
#==========================================================

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

    # Add firmware and I2C alerts status
    if fw_flag == False:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Firmware commands are NOT included. (-fw or --firmware flags were not provided)</font></p>")
        #if mtusb_flag:
        #    html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: --mtusb flag was provided, it is ineffective since firmware commands are not included</font></p>")
    else:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Firmware commands are included. (One of -fw or --firmware flags was provided)</font></p>")

    if mtusb_flag: 
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: I2C firmware commands are included. (--mtusb flag was provided)</font></p>")
    else:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: I2C firmware commands are NOT included. (--mtusb flag was not provided)</font></p>")

    # Add no_ib and ibdiagnet alerts status
    if no_ib_flag == True:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: IB commands are NOT included, hence e.g. NO fabric commands section (--no_ib flag was provided)</font></p>")
        if ibdiagnet_flag:    
            html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: --ibdiagnet flag was provided, it is ineffective since --no_ib flag was provided</font></p>")
    else:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: IB commands are included. (--no_ib flag was not provided)</font></p>")
        if ibdiagnet_flag:
            if ibdiagnet_error:
                html.write("<p><font color="+'"'+"red"+'"'+" size="+'"'+"3"+'"'+">Error: ibdiagnet command is included. But it ouput may not be displayed correctly for all subnets</font></p>")
            else:
                html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: ibdiagnet command is included. (--ibdiagnet flag was provided)</font></p>")
        else:
            html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: ibdiagnet command is NOT included. (--ibdiagnet flag was not provided)</font></p>")

    # Add no mlnx cards alert if needed
    if (mlnx_cards_status < 0):
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Unable to count Mellanox cards. </font></p>")
    elif (mlnx_cards_status == 0):
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: There are no Mellanox cards. </font></p>")

    if pcie_flag:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: pcie commands are included. (--pcie flag was provided)</font></p>")
    else:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: pcie commands are NOT included. (--pcie flag was not provided)</font></p>")
    html.close()

def html_write_section(html, title, collection, base):
    html.write("<h2>" + title + "</h2>")
    html.write("<table cols="+'"'+"4"+'"'+" width=" + '"' + "100%" + '"' + " border=" + '"' + "0" + '"' + " bgcolor="+'"'+"#E0E0FF"+'"'+">")
    html.write("<tr>")

    rows = len(collection)//4
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
                if (is_ib == 0 and no_ib_flag == False): # IB Fabric
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
            and ( (("fw_ini_dump" in collection[i]) and fw_ini_dump_is_string == False )
            or (("mlxdump" in collection[i]) and mlxdump_is_string == False)
            or (("mstregdump-func" in collection[i]) and mstreg_dump_is_string == False)
            or (collection[i] == "ethtool_all_interfaces") ) ):
            html.write("<p>")
            if (collection[i] == "ethtool_all_interfaces"):
                ethtool_content = dict[collection[i]]
                ethtool_content = ethtool_content.split("\n")
                ethtool_content_final = ""
                for line in ethtool_content:
                    if "<td><a href=" not in line:
                        ethtool_content_final += line.replace('<', "&lt;").replace('>', "&gt;") + "\n"
                    else:
                        ethtool_content_final += line + "\n"
                html.write(ethtool_content_final)
            elif ("fw_ini_dump" in collection[i]):
                for value in server_commands_dict[collection[i]]:
                    html.write(value)
                    html.write("&nbsp;&nbsp;&nbsp;&nbsp;")
            else:
                for key, value in server_commands_dict[collection[i]].items():
                    html.write(value)
                    html.write("&nbsp;&nbsp;&nbsp;&nbsp;")
            html.write("</p>")
        else:
            replaced_command_output = dict[collection[i]].replace('\t', "&nbsp;&nbsp;&nbsp;&nbsp;").replace('<', "&lt;").replace('>', "&gt;").replace('\n', '<br/>')
            # replace all non-ascii charachters with ""
            html.write("<p>" + re.sub(r'[^\x00-\x7F]+',' ', replaced_command_output) + "</p>")
        sec=sec+1

    html.write("</p>")
    return (sec-1)


def build_and_finalize_html():
    html = open(html_path, 'a')

    #=======================SORT COLLECTIONS FOR PRINTING HTML =================

    available_commands_collection.sort()
    if (is_ib == 0 and no_ib_flag == False): # IB Fabric
        available_fabric_commands_collection.sort()
    available_internal_files_collection.sort()

    #=======================BEGIN OF SERVER COMMANDS SECTION ====================
    
    html_write_section(html, "1. Server Commands: ", available_commands_collection, 1000)

    #=======================END OF SERVER COMMANDS SECTION =======================

    #=======================BEGIN OF FABRIC DIGNASTICS SECTION ===================
    
    if (is_ib == 0 and no_ib_flag == False):
        html_write_section(html, "2. Fabric Diagnostic Information: ", available_fabric_commands_collection, 2000)

    #=======================END OF FABRIC DIGNASTICS SECTION =====================

    #=======================BEGIN OF FILES SECTION ===============================

    if (is_ib == 0 and no_ib_flag == False):
        html_write_section(html, "3. Internal Files: ", available_internal_files_collection, 3000)
    else:
        html_write_section(html, "2. Internal Files: ", available_internal_files_collection, 3000)

    #=======================EXTERNAL FILES =======================================
    
    if (is_ib == 0 and no_ib_flag == False):
        html.write("<h2>4. External Files:</h2>")
    else:
        html.write("<h2>3. External Files:</h2>")
    html.write("<table cols="+'"'+"4"+'"'+" width=" + '"' + "100%" + '"' + " border=" + '"' + "0" + '"' + " bgcolor="+'"'+"#E0E0FF"+'"'+">")
    html.write("<tr>")

    rows = len(available_external_files_collection)//6
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
        # pair[1] is external file name
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

    if (is_ib == 0 and no_ib_flag == False): # IB Fabric
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

#==========================================================
#    Performance Tuner HTML Handlers
#==========================================================

html2_path = path + file_name + "/performance-tuning-analyze.html"
html2_flag=0

def initialize_html2(html2_flag):
    if (html2_flag == 1):
        return
    html2_flag = 1
    html2 = open(html2_path, 'a')
    
    html2.write("<html>")
    html2.write("<head><title>" + html2_path + "</title></head>")
    html2.write("<body><pre>")
    html2.write("<a name=" + '"' + "index" + '"' + "></a><h1>Mellanox Technologies</h1>")
    html2.write("<br/>")
    html2.write("<a name=" + '"' + "index" + '"' + "></a><h2>Performance Tuning Analyze for Linux</h2>")
    html2.write("<br/>")
    html2.write("<a name=" + '"' + "index" + '"' + "></a><h2>Version: " + perf_version + "</h2>")
    html2.write("<br/><hr/>")
    
    html2.close()

#----------------------------------------------------------

def html2_write_ipv(html2, key):
    html2.write(key + " Forwarding status: ")
    if (ip_forwarding_status[key] == not_present):
        html2.write("<font color=" +'"'+"red"+'"' + ">Not Present</font>")
    else:
        html2.write("<font color=" +'"'+"green"+'"' + ">" + ip_forwarding_status[key] + "</font>")
    html2.write("<br/>" + key + " Forwarding value: " + ip_forwarding_val[key] + "<br/>")

def html2_write_ip_forwarding(html2):
    html2_write_ipv(html2, "IPv4")
    html2.write("<br/>")
    html2_write_ipv(html2, "IPv6")

#----------------------------------------------------------

def html2_write_lspci(html2):
    html2.write("Setting Value: ")
    for i in range(len(pci_devices)):
        html2.write("<br/><br/>")
        
        #print pci device name
        html2.write("&nbsp;&nbsp;&nbsp;&nbsp;PCI Device Name: " + pci_devices[i]["name"].replace('<', "&lt;").replace('>', "&gt;"))
        html2.write("<br/>")
        
        #print device status:
        if (pci_devices[i]["status"] == "OK"):
            html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Status: <font color=" +'"'+"green"+'"'+">OK</font>")
        else:
            html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Status: <font color=" +'"'+"orange"+'"'+">" + pci_devices[i]["status"] + "</font>")
        html2.write("<br/>")

        #print current hca firmware version
        if (pci_devices[i]["current_fw"] != ""):
            html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Current Firmware Version: " + pci_devices[i]["current_fw"])
            html2.write("<br/>")

        #print hca psid
        if (pci_devices[i]["psid"] != ""):
            html2.write("&nbsp;&nbsp;&nbsp;&nbsp;PSID: " + pci_devices[i]["psid"])
            html2.write("<br/>")

        #print desired gen
        if (pci_devices[i]["desired_gen"] != not_available):
            html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Desired PCIe Generation: " + str(int(pci_devices[i]["desired_gen"])))
            html2.write("<br/>")

        #print current gen
        if (pci_devices[i]["current_gen"] != not_available):
            html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Current PCIe Generation: " + str(int(pci_devices[i]["current_gen"])))
            html2.write("<br/>")

        #print desired speed
        html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Desired Speed: " + str(pci_devices[i]["desired_speed"]))
        html2.write("<br/>")

        #print current speed
        html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Current Speed: " + str(pci_devices[i]["current_speed"]))
        html2.write("<br/>")

        #print desired width
        html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Desired Width: x" + str(pci_devices[i]["desired_width"]))
        html2.write("<br/>")

        #print current width
        html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Current Width: x" + str(pci_devices[i]["current_width"]))
        html2.write("<br/>")

        #print desired payload size
        html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Desired Payload Size: " + str(pci_devices[i]["desired_payload_size"]))
        html2.write("<br/>")

        #print current payload size
        html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Current Payload Size: " + str(pci_devices[i]["current_payload_size"]))
        html2.write("<br/>")

        #print desired max read request
        html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Desired Max Read Request: " + str(pci_devices[i]["desired_max_read_request"]))
        html2.write("<br/>")

        #print current max read request
        html2.write("&nbsp;&nbsp;&nbsp;&nbsp;Current Max Read Request: " + str(pci_devices[i]["current_max_read_request"]))
        html2.write("<br/>")

        if ((i+1) != len(pci_devices)):
            html2.write("<br/>&nbsp;&nbsp;&nbsp;&nbsp;--------------------------------------------------")

#----------------------------------------------------------

def html2_write_bw(html2):
    i = 0
    for device, val in bandwidth.items():
        i += 1
        if (i > 1):
            html2.write("<br/>")
        html2.write(device + "<br/>" + val + "<br/>")
        if (i < len(bandwidth)):
            html2.write("<br/>****************************************<br/>")

def html2_write_lat(html2):
    i = 0
    for device, val in latency.items():
        i += 1
        if (i>1):
            html2.write("<br/>")
        html2.write(device + "<br/>" + val + "<br/>")
        if (i<len(latency)):
            html2.write("<br/>****************************************<br/>")

#----------------------------------------------------------

# body - settings output
def html2_write_paragraph(html2, base, prev_parag_end):
    html2.write("<p>")

    sec=base+1
    for i in range(len(perf_setting_collection)):
        html2.write("<a name=" + '"' + "sec" + str(sec) + '"' + "></a>")

        if ( (i+1) == len(perf_setting_collection) ):
            html_write_prev(html2, sec)
            html_write_index(html2)
            html2.write("<small><a href=" + '"' + "#sec" + str(base+1000+1) + '"' + ">[next>>]</a></small> ")
        elif (i == 0):
            html_write_index(html2)
            html_write_next(html2, sec)
        else:
            html_write_prev_index_next(html2, sec)

        # Add setting title/header
        html2.write("<h2>"+perf_setting_collection[i]+"</h2>")
        # Add setting output/content
        html2.write("<p>")
        if (perf_setting_collection[i] not in setting_without_status):
            if (perf_status_dict[perf_setting_collection[i]] == "Not OK"):
                html2.write("Status: <font color=" +'"'+"red"+'"'+" size="+'"'+"3"+'"'+">" + perf_status_dict[perf_setting_collection[i]] + "</font>")
            elif (perf_status_dict[perf_setting_collection[i]] == "Warning" or perf_status_dict[perf_setting_collection[i]] == not_present):
                html2.write("Status: <font color=" +'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">" + perf_status_dict[perf_setting_collection[i]] + "</font>")
            else:
                html2.write("Status: <font color=" +'"'+"green"+'"'+" size="+'"'+"3"+'"'+">" + perf_status_dict[perf_setting_collection[i]] + "</font>")
            html2.write("<br/>")

        if (perf_setting_collection[i] == "Memory Allocation"):
            html2.write("Setting Value: <br/>" + perf_val_dict[perf_setting_collection[i]].replace('<', "&lt;").replace('>', "&gt;"))
        elif (perf_setting_collection[i] == "IP Forwarding"):
            html2_write_ip_forwarding(html2)
        elif (perf_setting_collection[i] == "Bandwidth"):
            html2_write_bw(html2)
        elif (perf_setting_collection[i] == "Latency"):
            html2_write_lat(html2)
        elif ((perf_setting_collection[i] != "PCI Configurations") or (direct == True)):
            html2.write("Setting Value: " + perf_val_dict[perf_setting_collection[i]].replace('<', "&lt;").replace('>', "&gt;"))
        else:
            html2_write_lspci(html2)
        
        html2.write("</p>")
        sec=sec+1
    
    html2.write("<small><a href=" + '"' + "#sec" + str(sec-1) + '"' + ">[&lt;&lt;prev]</a></small> ")
    html_write_index(html2)
    html2.write("</p>")

#----------------------------------------------------------

def build_and_finalize_html2():
    html2 = open(html2_path, 'a')
    
    #=======================SORT COLLECTIONS FOR PRINTING HTML =================

    perf_setting_collection.sort()
    if (is_ib == 0):
        for key in eth_setting_collection:
            try:
                perf_setting_collection.remove(key)
            except:
                pass
    if (is_ib != 0 or no_ib_flag == True):
        for key in ib_setting_collection:
            try:
                perf_setting_collection.remove(key)
            except:
                pass

    #=======================BEGIN OF SETTINGS SECTION ==========================

    html_write_section(html2, "1. Settings Menu: ", perf_setting_collection, 1000)
    
    #=======================END OF SETTINGS SECTION ============================

    #=======================BEGIN OF EXTERNAL FILES SECTION ====================

    if (no_ib_flag == False and os.path.exists(path+file_name+"/mlnx_tune_r") == True):
        html2.write("<h2>2. External Files:</h2>")
        html2.write("<table cols="+'"'+"4"+'"'+" width=" + '"' + "100%" + '"' + " border=" + '"' + "0" + '"' + " bgcolor="+'"'+"#E0E0FF"+'"'+">")
        html2.write("<tr>")

        rows = len(perf_external_files_collection)//6
        mod_val = len(perf_external_files_collection) % 6

        c=0
        r=0
        base=2000

        html2.write("<!-- rows: " + str(rows) + " Perf External Files: " + str(len(perf_external_files_collection)) + " -->")

        for pair in perf_external_files_collection:
            if (c < mod_val):
                fno = r + c*(rows+1)
            else:
                fno = r + c*rows
            
            # pair[0] is field name
            # pair[1] is external file name
            html2.write("<td width=" + '"' + "16%" +'"' + "><a href=" + pair[1] + ">" + pair[0] + "</a></td>")
            c = c+1
            if ( (c % 6) == 0):
                html2.write("</tr><tr>")
                r = r+1
                c=0

        html2.write("</tr></table>")

    #=======================END OF EXTERNAL FILES SECTION =================================

    html2_write_paragraph(html2, 1000, 0)

    html2.write("</body></pre>")
    html2.write("</html>")

    html2.close()

#==========================================================
#        SR-IOV HTML Handlers
#==========================================================

html3_path = path + file_name + "/sr-iov.html"
html3_flag=0

def initialize_html3(html3_flag):
    if (html3_flag == 1):
        return
    html3_flag = 1
    html3 = open(html3_path, 'a')

    html3.write("<html>")
    html3.write("<head><title>" + html3_path + "</title></head>")
    html3.write("<body><pre>")
    html3.write("<a name=" + '"' + "index" + '"' + "></a><h1>Mellanox Technologies</h1>")
    html3.write("<br/>")
    html3.write("<a name=" + '"' + "index" + '"' + "></a><h2>Single Root IO Virtualization (SR-IOV)</h2>")
    html3.write("<br/>")
    html3.write("<a name=" + '"' + "index" + '"' + "></a><h2>Version: " + sriov_version + "</h2>")
    html3.write("<br/><hr/>")

    html3.close()

#----------------------------------------------------------

def build_and_finalize_html3():
    html3 = open(html3_path, 'a')

    #=======================PRINT PROPER MESSAGE - NO SRIOV ====================

    if len(available_sriov_commands_collection) == 0 and len(available_sriov_internal_files_collection) == 0:
        html3.write("There are neither available SR-IOV commands nor available SR-IOV related internal files")
        html3.write("</body></pre>")
        html3.write("</html>")
        html3.close()
        return 

    #=======================SORT COLLECTIONS FOR PRINTING HTML =================

    available_sriov_commands_collection.sort()
    available_sriov_internal_files_collection.sort()

    #=======================BEGIN OF SR-IOV COMMANDS SECTION ===================

    if_section_num = "1. "
    if_index = 1000
    if len(available_sriov_commands_collection) > 0:
        html_write_section(html3, "1. SR-IOV Commands: ", available_sriov_commands_collection, 1000)
        if_section_num = "2. "
        if_index = 2000

    #=======================END OF SERVER COMMANDS SECTION =====================
    #=======================BEGIN OF SR-IOV INTERNAL FILES SECTION =============

    if len(available_sriov_internal_files_collection) > 0:
        html_write_section(html3, if_section_num + "SR-IOV Related Internal Files: ", available_sriov_internal_files_collection, if_index)

    #=======================END OF SR-IOV INTERNAL FILES SECTION ===============

    #=======================Paragraph 1 - Server Commands ======================

    parag_1_end = 0
    parag_start = 1000
    if len(available_sriov_commands_collection) > 0:
        parag_1_end = html_write_paragraph(html3, 1000, available_sriov_commands_collection, sriov_commands_dict, 0)
        parag_start = 2000

    #===========================================================================
    #=======================Paragraph 2 - Fabric Commands ======================

    if len(available_sriov_internal_files_collection) > 0:
        parag_2_end = html_write_paragraph(html3, parag_start, available_sriov_internal_files_collection, sriov_internal_files_dict, parag_1_end)

    #===========================================================================

    html3.write("</body></pre>")
    html3.write("</html>")

    html3.close()

###########################################################

def confirm_mlnx_cards():
    global mlnx_cards_status
    global sriov_exists
    st, mlnx_cards = get_status_output("timeout 10s lspci -d 15b3:")
    if (st != 0 or ("command not found" in mlnx_cards)):
        st, mlnx_cards = get_status_output("timeout 10s ls /sys/class/infiniband")
        if (st == 0 and ("No such file or directory" not in mlnx_cards)):
            mlnx_cards = mlnx_cards.split()
            mlnx_cards_status = len(mlnx_cards)
            for mlnx_card in mlnx_cards:
                if mlnx_card.endswith("_1"):
                    sriov_exists = True
                    return
    else:
        mlnx_cards = mlnx_cards.splitlines()
        if len(mlnx_cards) > 0 and represents_Int(mlnx_cards[-1].split(":")[0], 16):
            mlnx_cards_status = 1
            for mlnx_card in mlnx_cards:
                if mlnx_card.split()[0].endswith(".1"):
                    sriov_exists = True
                    return

# Create empty log files
def create_empty_log_files():
    f = open(path+file_name+"/err_messages/dummy_functions", 'a')
    f.close()

    f = open(path+file_name+"/err_messages/dummy_paths", 'a')
    f.close()

    f = open(path+file_name+"/err_messages/dummy_external_paths", 'a')
    f.close()

# Load module if needed and save old mst status
def load_modules():
    global driver_required_loading
    global is_MFT_installed
    st, mst_start = get_status_output('mst start')
    if st != 0:
        print ('MFT is not installed, it is prefered to install MFT and try again.')
        is_MFT_installed = False
        return
    is_MFT_installed = True
    if 'already' in mst_start:
        driver_required_loading = False
    else:
        driver_required_loading = True


# Create the output tar
def generate_output():

    global ibdiagnet_error

    validate_not_file()
    print_in_process()
    confirm_mlnx_cards()
    
    # Create output directories
    ensure_out_dir_existence()
    get_status_output("mkdir " + path + file_name)

    #invoke_command(['mkdir', path + file_name])
    get_status_output("mkdir " + path + file_name + "/tmp")
    #invoke_command(['mkdir', path + file_name + "/tmp"])
    get_status_output("mkdir " + path + file_name + "/err_messages")
    #invoke_command(['mkdir', path + file_name + "/err_messages"])
    #if fw_flag:
    get_status_output("mkdir " + path + file_name + "/firmware")
    #invoke_command(['mkdir', path + file_name + "/firmware"])

    # Create empty log files
    create_empty_log_files()

    if verbose_flag:
        print("------------------------------------------------------------\n")
        print("Loading modules via 'mst start'. (will be reverted to initial state at end of run)\n")
    load_modules()
    if verbose_flag and not generate_config_flag:
        print("Generating sysinfo-snapshot HTML page has started")
    initialize_html(html_flag)

    # Generate performance tuning analyze html
    if verbose_flag and not generate_config_flag:
        print("\tGenerating performance-tuning-analyze HTML page has started")
    initialize_html2(html2_flag)
    if verbose_flag:
        print("\t\tGenerating performance settings menu has started")
    generate_perf_table()
    if verbose_flag:
        print("\t\tGenerating performance settings menu has ended")
    if verbose_flag and not generate_config_flag:
        print("\tGenerating performance-tuning-analyze HTML page has ended")
        print("\t----------------------------------------------------")

    if sriov_exists:
        # Generating sriov html
        if verbose_flag and not generate_config_flag:
            print("\tGenerating sr-iov HTML page has started")
        initialize_html3(html3_flag)
        arrange_sriov_dicts()
        if verbose_flag and not generate_config_flag:
            print("\tGenerating sr-iov HTML page has ended")

    if verbose_flag:
        print("\tDiscovering installed IB cards, ports and subnets has started")
    if (is_ib == 0 and no_ib_flag == False):
        get_installed_cards_ports()
        # Create output directories for ibdiagnet files for multisubnets
        for card in active_subnets:
            for port_obj in active_subnets[card]:
                port = port_obj["port_num"]
                ibdiagnet_suffix = "ibdiagnet_" + card + "_" + port
                if ibdiagnet_flag:
                    st, mkdir_output = get_status_output("mkdir " + path + file_name  + "/" + ibdiagnet_suffix)
                    if st != 0:
                        ibdiagnet_error = True
    if verbose_flag:
        print("\tDiscovering installed IB cards, ports and subnets has ended")

    # operation is done here
    arrange_dicts()
    # Major operations for creating the .json file
    if (verbose_flag == True and json_flag == True and not generate_config_flag):
        print("\t----------------------------------------------------")
        print("\tGenerating JSON file has started")
    if (json_flag == True and json_found == True):
        json_content = json.dumps(l1_dict, sort_keys=True)
        with open(path + file_name + "/" + file_name + ".json", 'w') as json_file:
            json_file.write(json_content)
        #print >> json_file, json_content
        #json_file = open(path + file_name + "/" + file_name + ".json", 'w')
        #print >> json_file, json_content
        #json_file.close()
    elif (json_flag == True and not generate_config_flag):
        if verbose_flag:
            print("\t'json' module is not found in python, please install the module or remove the flag --json and try again.")
        else:
            print("'json' module is not found in python, please install the module or remove the flag --json and try again.\n")
    if (verbose_flag == True and json_flag == True and not generate_config_flag):
        print("\tGenerating JSON file has ended")

    if sriov_exists:
        build_and_finalize_html3()
    build_and_finalize_html2()
    build_and_finalize_html()

    if verbose_flag and not generate_config_flag:
        print("Generating sysinfo-snapshot HTML page has ended\n")

    # Remove helping directories before creating tar
    get_status_output("rm -rf " + path + file_name + "/tmp")
    #invoke_command(['rm', '-rf', path + file_name + "/tmp"])

    if verbose_flag:
        print("\nReverting modules loading state to the initial state")
    if driver_required_loading:
        if verbose_flag:
            print("The modules were not loaded, hence, stopping them via 'mst stop'\n")
        os.system('timeout 10s mst stop > /dev/null 2>&1')
    else:
        if verbose_flag:
            print("The modules were loaded, hence, starting them via 'mst start'\n")
        os.system('timeout 10s mst start > /dev/null 2>&1')

    # Print generated config file message
    if generate_config_flag:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerows(config_dict.items())
        csvfile.close()
        print("\t----------------------------------------------------\n")
        print("Generating a new configuration file has ended successfully")
        print("Temporary destination directory is /tmp/\n")
        remove_unwanted_files()
        return

    if verbose_flag and not generate_config_flag:
        print("Creating tgz file has started")
    # Create result tar file
    tar = tarfile.open(path + file_name + ".tgz", "w:gz")
    tar.add(path + file_name, arcname = file_name)
    tar.close()
    if verbose_flag and not generate_config_flag:
        print("Creating tgz file has ended\n")
        print("------------------------------------------------------------\n")

    # Print Destination
    print_destination_out_file()

    # Remove all unwanted files
    remove_unwanted_files()

def confirm_valid_options(index):
    if (index > 0 and (sys.argv[index-1] == '-d' or sys.argv[index-1] == "--dir")):
        print("Invalid options")
        parser.print_help()
        sys.exit(1)

def update_flags(args):
    global fw_flag
    global no_ib_flag
    global json_flag
    global verbose_flag
    global verbose_count
    global ibdiagnet_flag
    global mtusb_flag
    global perf_flag
    global pcie_flag
    global check_fw_flag
    global generate_config_flag
    global config_file_flag
    global isFile
    isFile = False

    if (args.dir):
        path = args.dir
        if (len(path) > 0):
            if (not path.endswith("/")):
                path = path + "/"
            if (os.path.isfile(path[:-1]) == True):
                isFile = True
    if (args.perf):
        perf_flag = True
    if (args.firmware):
        fw_flag = True
    if (args.ibdiagnet):
        ibdiagnet = True
    if (args.no_ib):
        no_ib_flag = True
    if (args.json):
        json_flag = True
    if (args.pcie):
        pcie_flag = True
    if (args.config):
        config_file_flag = True
        config_path = args.config
        try:
            with open(config_path, 'r') as csvfile:
                reader = csv.reader(csvfile)
                config_dict = {k:v for k, v in reader}
            #e.g config_dict{COMMAND_CSV_HEADER: INVOKED_CSV_HEADER }
        except:
            print('Unable to read the configuration file. Please make sure that config file(config.csv) is in the same directory\n')
            parser.print_help()
            sys.exit(1)
    if (args.generate_config):
        generate_config_flag = True
        config_path = args.config
        try:
            csvfile = open(config_path, 'w+')
            fieldnames = [COMMAND_CSV_HEADER, INVOKED_CSV_HEADER]
            config_file = csv.DictWriter(csvfile, fieldnames=fieldnames)
            config_file.writeheader()
            config_dict = {}
        except:
            print('Unable to create a default configuration file .\n')
            parser.print_help()
            sys.exit(1)
    if (args.check_fw):
        check_fw_flag = True
    if (args.verbose):
        verbose_flag = True
        if args.verbose >= 2 :
            verbose_count = 2
        else:
            verbose_count = 1

    if (args.mtusb):
        mtusb_flag = True
        # Change Name: mstregdump-func --> mstregdump-func / i2c-mstdump-func
        try:
            commands_collection.remove('mstregdump-func')
        except:
            pass
        commands_collection.extend(['mstregdump-func / i2c-mstdump-func'])
        try:
            fw_collection.remove('mstregdump-func')
        except:
            pass
        fw_collection.extend(['mstregdump-func / i2c-mstdump-func'])
        # Change Name: fw_ini_dump --> fw_ini_dump / i2c_fw_ini_dump
        try:
            commands_collection.remove('fw_ini_dump')
        except:
            pass
        commands_collection.extend(['fw_ini_dump / i2c_fw_ini_dump'])
        try:
            fw_collection.remove('fw_ini_dump')
        except:
            pass
        fw_collection.extend(['fw_ini_dump / i2c_fw_ini_dump'])

def execute(args):
    global len_argv
    global csvfile
    global config_file
    global config_dict
    update_flags(args)
    generate_output()

def confirm_root():
    st, user = get_status_output('timeout 10s /usr/bin/whoami')
    if (st != 0):
        print('Unable to distinguish user')
        sys.exit(1)
    if (user.strip() != 'root'):
        print('Running as a none root user\nPlease switch to root user (super user) and run again.\n')
        parser.print_help()
        sys.exit(1)

def main():
    global parser
    parser = argparse.ArgumentParser(prog='Sysinfo-snapshot', usage=' %(prog)s version: ' + version + ' [options]'
                                                                    + "\n\tThe sysinfo-snapshot command gathers system information and places it into a tar file."
                                                                    + "\n\tIt is required to run this script as super user (root).")
    parser.add_argument("-d", "--dir", nargs="?", const="/tmp/",default="/tmp/", help="set destination directory (default is /tmp/).")
    parser.add_argument("-v", "--version", help="show the tool's version information and exit.", action='store_true')
    parser.add_argument("-p", "--perf",  help="include more performance commands/functions, e.g. ib_write_bw and ib_write_lat.", action='store_true')
    parser.add_argument("-fw", "--firmware", help="add firmware commands/functions to the output.", action='store_true')
    parser.add_argument("--mtusb", help="add I2C mstdump files to the output.", action='store_true')
    parser.add_argument("--ibdiagnet", help="add ibdiagnet command to the output.", action='store_true')
    parser.add_argument("--no_ib", help="do not add server IB commands to the output.", action='store_true')
    parser.add_argument("--json", help="add json file to the output.", action='store_true')
    parser.add_argument("--pcie", help="add pcie commands/functions to the output.", action='store_true')
    parser.add_argument("--config", nargs="?", const=DEFAULT_CONFIG_PATH, help="set the customized configuration file path, to choose which commands are approved to run.\n"
                                                                                + "In case a path is not provided, the default file(config.csv) path is for the same directory.")
    parser.add_argument("--generate_config", nargs="?", const=DEFAULT_CONFIG_PATH, help="set the file path of the generated configuration file, by default all commands are approved to be invoked.\n"
                                                                                        + "In case a path is not provided, the default file(config.csv) path is for the same directory.")
    parser.add_argument("--check_fw", help="check if the current adapter firmware is the latest version released, output in performance html file [Internet access is required]", action='store_true')
    parser.add_argument("--verbose", help="first verbosity level, available if option is provided only once, lists sections in process.second verbosity level, available if option is provided twice, lists sections and commands in process.", action='count')
    args = parser.parse_args()

    if (args.version):
        print('sysinfo-snapshot version: ' + version)
    else:
        confirm_root()
        execute(args)


if __name__ == '__main__':
    main()