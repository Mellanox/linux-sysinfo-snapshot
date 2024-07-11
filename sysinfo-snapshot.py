#!/usr/bin/python3
# -*- python -*-
#
# Author:    Nizar Swidan  nizars@mellanox.com -- Created: 2015
# Modified:  Anan Fakheraldin  ananf@mellanox.com -- Modified: 2018
#            Jeries Haddad     jeriesh@mellanox.com -- Modified: 2019
__author__ = 'nizars'

import warnings
import subprocess
import sys
import re
import os
import collections
import time
import signal
import shutil
import platform
import csv
from optparse import OptionParser
from distutils.version import LooseVersion
from itertools import chain
import hashlib
import datetime
import inspect
import threading
import shutil


try:
    import json
    json_found = True
except ImportError:
    json_found = False

warnings.filterwarnings('ignore')

COMMAND_CSV_HEADER = 'Command'
INVOKED_CSV_HEADER = 'Approved'
FLAG_RELATED_HEADER = "related flag"
DEFAULT_CONFIG_PATH = './config.csv'
DEFAULT_PATH = '/tmp/'

######################################################################################################
#                                  no_log_status_output
# get_status_output but without logging to the command log
# Only used in few instances where logging is not mandatory

def standarize_str(tmp):
    ''' if python version major is 3, then tmp is unicode (utf-8) byte string
        and need to be converted to regular string
    '''
    if sys.version_info[0] == 2:
        return tmp.strip()
    elif sys.version_info[0] == 3:
        return tmp.decode("utf-8", 'ignore').strip()
    else:
        return tmp.strip()

def no_log_status_output(command, timeout='10s'):
    command = 'timeout '+ timeout + ' ' + command
    try:
        p = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1024*1024)
        stdout, stderr = p.communicate()
        return p.returncode, standarize_str(stdout)
    except:
        error = "\nError while reading output from command - " + command + "\n"
        return 1, error


######################################################################################################
#                                     GLOBAL GENERAL VARIABLES

version = "3.7.8"
sys_argv = sys.argv
len_argv = len(sys.argv)
driver_required_loading = False
is_MST_installed = False
is_MFT_installed = False
are_inband_cables_loaded = False # If in-band cables were loaded before user runs snapshot
mst_devices_exist = False
all_sm_on_fabric = []
is_command_string = False
#active_subnets --> device_name
#               --> port
active_subnets = {}
#installed_cards_ports --> device_name
#                       --> port
installed_cards_ports = {}
pf_devices = []
asap_devices = []
mtusb_devices = []
vf_pf_devices = []
config_dict = {}
local_mst_devices = []
json_flag = False
verbose_flag = False
verbose_count = 0
mlnx_cards_status = -1
ethtool_command = ""
path_is_generated = 0
path = "/tmp/"
config_path = ""
parser = ""
section_count=1
ibdiagnet_res = ""
file_name = ""
ibdiagnet_is_invoked = False
st_saquery = 1
sys_class_net_exists = False
blueos_flag = False
missing_critical_info = False # True --> Sysinfo-snapshot is missing some critical debugging information
non_root = False
nvsm_dump_flag = False
CANCELED_STATUS = 4
######################################################################################################
#                Initialize Environment Variables
is_ib, ib_res = no_log_status_output("which ibnetdiscover 2>/dev/null")
date_file = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
sta, date_cmd = no_log_status_output("date")
st_infiniband_devices, infiniband_devices = no_log_status_output('ls /sys/class/infiniband')



######################################################################################################
#                SR-IOV Global Variables

sriov_version = "1.0.0"
sriov_exists = False
sriov_commands_collection = ["bridge fdb show dev p3p1", "ip link", "ip_link_show_devices", "lspci_vf"]
available_sriov_commands_collection = []
sriov_internal_files_collection = ["/etc/infiniband/openib.conf.rpmsave", "/etc/modprobe.d/mlnx.conf"]
available_sriov_internal_files_collection = []
sriov_commands_dict = {}
sriov_internal_files_dict = {}

######################################################################################################
#        Performance Tunning Analyze Global Variables

perf_version = "1.0.1"
perf_setting_collection = ["IRQ Affinity", "Core Frequency", "Hyper Threading", "IP Forwarding", "AMD", "Memory Allocation", "PCI Configurations", "Perf Samples", "Bandwidth", "Latency"]
eth_setting_collection = ["IP Forwarding"]
ib_setting_collection = ["Bandwidth", "Latency", "Perf Samples"]
setting_without_status = ["IP Forwarding", "Bandwidth", "Latency", "Perf Samples"]
not_available = "N/A"
not_present = "Not Present"
present = "Present"
perf_status_dict = {}
perf_val_dict = {}
perf_external_files_collection = [["mlnx_tune -r -i ", "mlnx_tune_r"]]
perf_samples = {}
bandwidth = {}
latency = {}

######################################################################################################
#                                            FLAGS

# ibdiagnet_flag = False, means --ibdiagnet was not provided
# ibdiagnet_flag = True, means --ibdiagnet was provided
ibdiagnet_flag = False
# ibdiagnet_ext_flag = True, means use replacment ibdiagent command
ibdiagnet_ext_flag = False
ibdiagnet_error = False
openstack_flag = False
asap_flag = False
asap_tc_flag = False
rdma_debug_flag = False
gpu_flag = False
# no_fw_flag = True, means not to add fw_collection commands to the out file
# no_fw_flag = False, means to add fw_collection commands to the out file
# no_fw_flag can be converted to True by running the tool with --no_fw flag
no_fw_flag = False
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
# generate_config_flag = False, means not to generate a new config file
# generate_config_flag = True, means to  generate a new config file
# this should be invoked with before any release with --ibdiagnet -fw -p --pcie --check_fw
generate_config_flag = False
# config_file_flag = False, means not to use default configuration all commands should be invoked
# config_file_flag = True, means to add any check to adapter firmware if latest
config_file_flag= False
#no_ib_flag = False, means to add ib commands to the out file
#no_ib_flag = True, means not to add ib commands to the out file
#no_ib_flag can be converted to True by running the tool with --no_ib
pcie_debug_flag = False
#pcie_debug_flag = False, means to run the tool normally and not PCIE_Debug run
#pcie_debug_flag = True, means to run the tool only for collecting PCIE_Debug info
no_ib_flag = False
keep_info_flag = False
trace_flag = False
interfaces_flag = False
#--with_inband_flag = False, means not to add in-band cable information
#--with_inband = True, means to add in-band cable information
#--with_inband can be converted to True by running the tool with --with_inband flag
with_inband_flag = False
# fsdump_flag = False, means not to add fsdump from firmware
# fsdump_flag = True, means to  add fsdump from firmware
# fsdump_flag can be converted to True by running the tool with --fsdump_flag
# If check_fw flag is true it runs online check for the latest fw for this psid
fsdump_flag = False
no_fw_regdumps_flag = False
no_mstconfig_flag = False
no_cables_flag = False
all_var_log_flag = False
if "--no_ib" in sys.argv:
    no_ib_flag = True
#perf_flag = False, means not to include more performance commands/function like ib_write_bw and ib_write_lat
#no_ib_flag = True, means include more performance commands/functions to the out file
#perf_flag can be converted to True by running the tool with -p|--perf
perf_flag = False
#ufm_flag = False, means not to include ufm logs to the out file
#ufm_flag = True, means to include ufm logs to the out file
#ufm_flag can be converted to True by running the tool with --ufm
ufm_flag = False

######################################################################################################
#                                 GLOBAL LISTS

fw_collection = ["fwtrace", "mlxmcg -d", "mlxdump", "mst_commands_query_output"]
pcie_collection = ["lspci -vvvxxxxx",]
ufm_collection = ["ufm_logs"]
fsdump_collection = ["mlxdump"]
asap_collection = ["asap_parameters"]
asap_tc_collection = ["asap_tc_information"]
rdma_debug_collection = ["rdma_tool"]
gpu_command_collection = ["nvidia-smi topo -m","nvidia-smi","lspci -tv |grep 'NVIDIA' -A7","nvidia-smi -q -d clock","nvidia-smi --format=csv --query-supported-clocks=gr,mem","ib_write_bw -h | grep -i cuda","modinfo nv_peer_mem"\
,"/usr/local/cuda/extras/demo_suite/deviceQuery","/etc/init.d/nv_peer_mem status"\
,"bandwidthTest","hwloc-ls"]
PCIE_debugging_collection =  ["dmidecode", "performance_lspci", "lscpu", "mlxlink / mstlink","mst_commands_query_output","dmesg" ]
ib_collection = []
commands_collection = ["ip -s -s link show", "ip -s -s addr show", "ovs-vsctl --version", "ovs-vsctl show", "ovs-dpctl show", "brctl --version", "brctl show", "mlxmcg -d", "arp -an", "free", "blkid -c /dev/null | sort", "date", "time", \
                        "df -lh", "mlnx_ethtool_version", "ethtool_version", "ethtool_all_interfaces", "fdisk -l", "hostname", "ibdev2netdev", "ibdev2pcidev", "ibv_devinfo -v", "ifconfig -a", \
                        "initctl list", "ip m s", "ip n s", "iscsiadm --version", "iscsiadm -m host", "iscsiadm -m iface", "iscsiadm -m node", "iscsiadm -m session", "lscpu", "lsmod",  "lspci -tv", \
                        "mount", "mst_commands_query_output", "asap_parameters", "asap_tc_information","rdma_tool",  "netstat -i", "netstat -nlp", "netstat -nr", "netstat -s", "numactl --hardware", "ofed_info", "ofed_info -s", "ompi_info",  "ip route show table all", "service --status-all", \
                        "service cpuspeed status", "service iptables status", "service irqbalance status", "show_irq_affinity_all",  "tgtadm --mode target --op show", "tgtadm --version", "tuned-adm active", "ulimit -a", "uname", \
                        "yy_MLX_modules_parameters", "sysclass_IB_modules_parameters", "proc_net_bonding_files","Mellanox_Nvidia_pci_buses" ,"sys_class_net_files", "teamdctl_state", "teamdctl_state_view", "teamdctl_config_dump", "teamdctl_config_dump_actual", "teamdctl_config_dump_noports", \
                        "mlxconfig_query", "mst status", "mst status -v", "mlxcables", "ip -6 addr show", "ip -6 route show", "modinfo", "show_pretty_gids", "flint -v",  "mstflint -v","dkms status",\
                        "mlxdump", "gcc --version", "python_used_version", "cma_roce_mode", "cma_roce_tos", "service firewalld status", "mlxlink / mstlink", "mget_temp_query", "mlnx_qos_handler", "devlink_handler", "se_linux_status", \
                        "ufm_logs", "virsh version","virsh list --all", "virsh vcpupin", "sys_class_infiniband_ib_paameters", "sys_class_net_ecn_ib","roce counters","route -n","numastat -n","NetworkManager --print-config","networkManager_system_connections","USER","mlxreg -d --reg_name ROCE_ACCL --get"\
                        ,"congestion_control_parameters","ecn_configuration","lsblk", "journalctl -u mlnx_snap","flint -d xx q","virtnet query --all","journalctl -u virtio-net-controller","/etc/mlnx_snap","snap_rpc.py emulation_functions_list","snap_rpc.py controller_list"\
                        ,"nvidia-smi topo -m", "nvidia-smi", "lspci -tv |grep 'NVIDIA' -A7", "nvidia-smi -q -d clock", "nvidia-smi --format=csv --query-supported-clocks=gr,mem", "ib_write_bw -h | grep -i cuda", "modinfo nv_peer_mem",\
                        "bandwidthTest"\
                        , "/etc/init.d/nv_peer_mem status","cuda_deviceQuery","ibstatus","ibstat","ucx_info -v", "dpkg -l net-tools | cat", "mdadm -D /dev/md*","hwloc-ls -v","systemctl list-units","nvsm dump health","lspci -nnPP -d 15b3:","lspci -nnPP -d ::0302"\
                        ,"lldptool -ti eth$i","lldptool -tin eth$i","lldptool -t -i eth$i -V APP -c","lldptool -t -i eth$i -V PFC","ip route show","ip -6 -s -s addr show"]
available_commands_collection = [[],[]]
available_PCIE_debugging_collection_dict = {}
fabric_commands_collection = [ "ib_mc_info_show", "sm_version", "Multicast_Information", "perfquery_cards_ports"]
fabric_multi_sub_commands_collection = ["ibdiagnet", "ib_find_bad_ports", "ib_find_disabled_ports", "ib_topology_viewer", "ibhosts", "ibswitches", "sminfo", "sm_status", "sm_master_is", "ib_switches_FW_scan"]
available_fabric_commands_collection = []
internal_files_collection = ["/sys/devices/system/clocksource/clocksource0/current_clocksource", "/sys/fs/cgroup/net_prio/net_prio.ifpriomap", "/etc/opensm/partitions.conf","/etc/opensm/opensm.conf", "/etc/default/mlnx_snap","/etc/modprobe.d/vxlan.conf", "/etc/security/limits.conf", "/boot/grub/grub.cfg","/boot/grub2/grub.cfg","/boot/grub/grub.conf","/boot/grub2/grub.conf", "/boot/grub/menu.lst","/boot/grub2/menu.lst","/etc/default/grub", "/etc/host.conf", "/etc/hosts", "/etc/hosts.allow", "/etc/hosts.deny", "/etc/issue", "/etc/modprobe.conf","/etc/udev/udev.conf" ,"/etc/ntp.conf", "/etc/resolv.conf", "/etc/sysctl.conf", "/etc/tuned.conf","/etc/dhcp/dhclient.conf","/etc/yum.conf","/etc/bluefield_version", "/proc/cmdline", "/proc/cpuinfo", "/proc/devices", "/proc/diskstats", "/proc/dma", "/proc/meminfo", "/proc/modules", "/proc/mounts", "/proc/net/dev_mcast", "/proc/net/igmp", "/proc/partitions", "/proc/stat", "/proc/sys/net/ipv4/igmp_max_memberships", "/proc/sys/net/ipv4/igmp_max_msf","/proc/uptime", "/proc/version", "/etc/rdma/rdma.conf","/etc/systemd/system/mlnx_interface_mgr@.service","/etc/systemd/system/sysinit.target.wants/openibd.service", "/proc/net/softnet_stat", "/proc/buddyinfo", "/proc/slabinfo", "/proc/pagetypeinfo","/etc/iproute2/rt_tables"]
available_internal_files_collection = []
# [field_name, file_name to cat]
external_files_collection = [["kernel config", "/boot/config-$(uname -r)"],["mlxcables --DDM/--dump","cables/mlxcables_options_output"] ,["config.gz", "/proc/config.gz"],["zoneinfo","/proc/zoneinfo"],[ "interrupts","/proc/interrupts"],["lstopo-no-graphics","lstopo-no-graphics"] ,["lstopo-no-graphics -v -c","lstopo-no-graphics -v -c"],["lspci","lspci"],["lshw","lshw"],["lspci -vvvxxxxx","lspci -vvvxxxxx"],["ps -eLo","ps -eLo"],["ucx_info -c", "ucx_info -c"],["ucx_info -f","ucx_info -f"],["sysctl -a","sysctl -a"], ["netstat -anp","netstat -anp"] ,["dmesg -T", "dmesg"], ["biosdecode", "biosdecode"], ["dmidecode", "dmidecode"], ["libvma.conf", "/etc/libvma.conf"], ["ibnetdiscover", ""], ["Installed packages", ""], ["Performance tuning analyze", ""], ["SR_IOV", ""],["other_system_files",""],["numa_node",""],["trace","/sys/kernel/debug/tracing/trace"],["lspci -nnvvvxxxx","lspci_nnvvvxxx"],["journalctl -k -o short-monotonic","journal"],["lspci -vv", "lspci_vv"]]
available_external_files_collection = []
copy_under_files = [["etc_udev_rulesd", "/etc/udev/rules.d/"], ["lib_udev_rulesd", "/lib/udev/rules.d/"]]
copy_openstack_dirs  = [["conf_nova", "/var/lib/config-data/puppet-generated/nova_libvirt"], ["conf_nuetron", "/var/lib/config-data/puppet-generated/neutron/"]]
copy_openstack_files  = [["logs_nova", "/var/log/containers/nova/nova-compute.log"], ["logs_neutron", "/var/log/containers/neutron/openvswitch-agent.log"]]
critical_failed_commands = [] # Critical commands that failed
running_warnings = []
#command not found 
command_exists_dict = {}
#commands that are part of higher chain commands ,used when generating config file
sub_chain_commands = ["file: var/log/syslog", "file: var/log/messages", "file: var/log/boot.log", "mlnx_tune -i " , "ib_write_bw_test", "latency", "perf_samples", "mlxfwmanager --online-query-psid", "file: /sys/class/infiniband/*/iov", "file: /sys/class/infiniband/*/device/"]
critical_collection = PCIE_debugging_collection # List of all critical commands
critical_collection.append("general_fw_command_output")
critical_collection.append("mstcommand_d_handler")
critical_collection.append("load_modules")
supported_os_collection = ["redhat", "suse", "debian"]

###########################################################
#        Get Status Ouptut
# (replacement old the depreciated call st, res = get_status_output("..")

#*****************************************************************************************************
#                               log_command_status
# A function to log every command invoked on the host: command, passed/filed, time taken
# A critical command is a command which is used for PCIE debugging. Found in PCIE_debugging_collection

def log_command_status(parent, command, status, res, time_taken, invoke_time):
    global missing_critical_info
    log_file = "/tmp/status-log-" + file_name
    with open(log_file, 'a') as log:
        status_message = "PASSED, time taken: {}".format(time_taken)
        if status != 0:
            failed_reason = "NOT FOUND" if "not found" in res.lower() or "no such file or directory" in res.lower() or "not invoked" in res.lower() else "FAILED"
            status_message = "{}, time taken: {}".format(failed_reason, time_taken)
            if parent in critical_collection:
                missing_critical_info = True
                critical_failed_commands.append("{} ---- {}".format(command, failed_reason))
        log.write("{}:{} ---- {}\n".format(invoke_time, command, status_message))

#*****************************************************************************************************
#                               arrange_command_status_log
# A function to arrange the command log
# If one of the critical commads failed --> display failed critical commands in the first section of the file + a proper warning
# display running warnings

def arrange_command_status_log():
    temp_log_path = "/tmp/status-log-" + file_name
    with open(temp_log_path, 'r') as temp_log:
        log_content = temp_log.read()

    with open(path + file_name + "/status-log-" + file_name, 'w') as log:
        #write invoked command 
        log.write("invoked command:\n")
        log.write(' '.join(sys.argv))
        log.write('\n')
        if missing_critical_info:
            log.write("\n\nWarning! The sysinfo-snapshot output failed to collect all essential information from the server.\n")
            log.write("\nFailed critical debugging commands:\n")
            for failed_command in critical_failed_commands:
                log.write(failed_command + "\n")
        if running_warnings:
            log.write("\n\n------------------------------------------------------------------------------------------------------------------\n")
            log.write("\nRunning warnings:\n")
            for warning in running_warnings:
                log.write(warning + "\n")
        log.write("\n\n------------------------------------------------------------------------------------------------------------------\n")
        log.write("\nFull log:\n")
        log.write(log_content)
        
    # After moving status log inside the TGZ file, remove it from /tmp
    try:
        os.remove(temp_log_path)
    except BaseException as e:
        with open(temp_log_path ,'a') as temp_log:
            temp_log.write("\nError in removing status log from /tmp. Full path is: " + temp_log_path + "\n" + str(e))
    

#*****************************************************************************************************
#                                         log
# A decorater that helps figure out the timing each command took, parent function, input / output of the invoked command

def log(f):
    def wrap(*args):
        time1 = time.time()
        invoke_time = datetime.datetime.now()
        ret = f(*args)
        time2 = time.time()
        st = ret[0]
        res = ret[1]
        time_taken = '{0:.3f}'.format((time2-time1))
        invoked_command = args[0]
        parent = inspect.stack()[1][3] # parent function who called the command
        log_command_status(parent, invoked_command, st,res ,time_taken, invoke_time)
        return ret
    return wrap

def is_command_exists(command):
    if sys.version_info[0] ==2:
        from distutils.spawn import find_executable
        if find_executable(command):
            return True
        else:
            return False  
    elif sys.version_info[0] ==3:
        import shutil 
        if shutil.which(command) is not None:
            return True
        else:
            return False
 
@log
def get_status_output(command, timeout='10'):
    command_with_timeout = "timeout " + timeout + "s " + command
    try:
        if " cat " in command_with_timeout:
            filePath = command_with_timeout.split(" cat ")[1]
            filePath = filePath.split("|")[0].strip()
            if os.path.exists(filePath) and  (not os.access(filePath, os.R_OK)):
                return 1, "Cant read file "  + filePath + " due to missing permissions"
            elif not os.path.exists(filePath):
                return 1, "Cant read file "  + filePath + " due to file does not exists" 
        else:
            base_command = command.split()[0]
            if base_command in command_exists_dict:
                if not command_exists_dict[base_command]:
                    return CANCELED_STATUS , "Command not invoked " + command + " due to " + base_command + " does not exists"
            else:
                is_exists = is_command_exists(base_command)
                command_exists_dict[base_command] = is_exists
                if not is_exists:
                    return CANCELED_STATUS , "Command not invoked " + command + " due to " + base_command + " does not exists"
        p = subprocess.Popen([command_with_timeout], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1024*1024)
        stdout = ""
        stderr = ""
        stdout, stderr = p.communicate()
        return p.returncode, standarize_str(stdout)
    except Exception as e:
        print(e,"err")
        error = "\nError while reading output from command - " + command_with_timeout + "\n"
        return 1, error


# Ditto but preserving the exit status.
# Returns a pair (sts, output)
#
@log
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
    if(not keep_info_flag):
        if (path_is_generated == 1):
            no_log_status_output("rm -rf " + path)
            #invoke_command(['rm', '-rf', path])
        else:
            # Remove tar out file
            no_log_status_output("rm -rf " + path + file_name + ".tgz")
            #invoke_command(['rm', '-rf', path+file_name+".tgz"])
        remove_unwanted_files()
        if driver_required_loading:
            os.system('mst stop > /dev/null 2>&1')
        print("\nRunning sysinfo-snapshot was halted!\nNo out directories/files.\nNo changes in modules loading states.")
        os._exit(0)
    else:
        if sriov_exists:
            build_and_finalize_html3()
        build_and_finalize_html2()
        build_and_finalize_html()
        create_tar_file()
        remove_unwanted_files()
        if driver_required_loading:
            os.system('mst stop > /dev/null 2>&1')
        print("\nRunning sysinfo-snapshot was halted!\n ")
        print("Temporary destination directory is " + path)
        print("Out file name is " + path + file_name + ".tgz\n")
        os._exit(0)
signal.signal(signal.SIGTSTP, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

##########################################################
#        OS General Variables & Confirmation

#rpm --eval %{_vendor}
#Ubuntu prints debian
#Redhat and CentOS prints redhat

os_st, cur_os = no_log_status_output("rpm --eval %{_vendor}")
def decide():
    global cur_os

    print("Hence running sysinfo-snapshot may throw an exception or produce an unexpected output.")
    print("Continue running sysinfo-snapshot (y/n)? ")
    decision_ch = sys.stdin.read(1).lower()
    if (decision_ch == 'y'):
        cur_os = "redhat"
    else:
        if (decision_ch != 'n'):
            print("Invalid char")
        print("Halting sysinfo-snapshot")
        sys.exit(0)

if (os_st == 0 and cur_os != "%{_vendor}"):
    if (cur_os not in supported_os_collection):
        print("Operating system with vendor " + cur_os + " is not tested in this Linux sysinfo snapshot.")
        decide()
else:
    os_st, o_systems = no_log_status_output("cat /etc/*release*")
    if (os_st != 0):
        os_st, o_systems = no_log_status_output("cat /etc/issue")
        if (os_st != 0):
            os_st, o_systems = no_log_status_output("lsb_release -a")
            if (os_st != 0):
                print("Unable to distinguish operating system.")
                decide()
    o_systems = o_systems.lower()
    o_systems = o_systems.replace('(',' ')
    o_systems = o_systems.replace(')',' ')
    o_systems = re.split(r'( +|")', o_systems)
    if ( ("red" in o_systems and "hat" in o_systems) or ("redhat" in o_systems) or ("centos" in o_systems) or ("fedora" in o_systems) or ("scientific" in o_systems) or ("yocto" in o_systems) or ("blueos" in o_systems) ):
        cur_os = "redhat"
        if ("yocto" in o_systems) or ("blueos" in o_systems):
            blueos_flag = True
    elif ("suse" in o_systems):
        cur_os = "suse"
    elif ( ("ubuntu" in o_systems) or ("debian" in o_systems) or ("uos" in o_systems)):
        cur_os = "debian"
    else:
        print("Unable to distinguish operating system.")
        decide()

# Runs ibswitches for a given card and port and returns it output and run status
def get_ibswitches_output(card, port):
    ibswitches_st, ibswitches = get_status_output("/usr/sbin/ibswitches -C " + card +" -P " + port)
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

    st, ibstat = get_status_output("ibstat | grep " + '"' + "CA '\|Port " + '"' + " | grep -v GUID")
    if st != 0:
        if st == CANCELED_STATUS:
            return ibstat
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
                            st, ibnetdiscover_output = get_status_output("/usr/sbin/ibnetdiscover -C " + card_name + " -P " + port_num + "")
                            if st != 0:
                                continue
                            ibnetdiscover_output_hashed = hashlib.sha256(ibnetdiscover_output.encode('utf-8')).hexdigest()
                            if ibnetdiscover_output_hashed not in all_sm_on_fabric:
                                all_sm_on_fabric.append(ibnetdiscover_output_hashed)
                                if card_name not in active_subnets:
                                    active_subnets[card_name] = []
                                obj = {}
                                obj["port_num"] = port_num
                                ibswitches_st, ibswitches = get_ibswitches_output(card_name, port_num)
                                obj["ibswitches"] = {}
                                obj["ibswitches"]["ibswitches_st"] = ibswitches_st
                                obj["ibswitches"]["ibswitches_output"] = ibswitches
                                active_subnets[card_name].append(obj)

if os.path.exists("/sys/class/net"):
    sys_class_net_exists = True


# ---------------------------------------
#                CLASSES
# ---------------------------------------

class mlnx_device:
    def __init__(self, parent_device, sys_img_guid, board_id, fw_ver, hca_type, hw_rev, node_type):
        self.parent_device = parent_device
        self.sys_img_guid = sys_img_guid
        self.board_id = board_id
        self.fw_ver = fw_ver
        self.hca_type = hca_type
        self.hw_rev = hw_rev
        self.node_type = node_type
        self.node_guids = {}

    def get_parent_device(self):
        return self.parent_device

    def set_parent_device(self, parent_device):
        self.parent_device = parent_device

    def get_sys_img_guid(self):
        return self.sys_img_guid

    def set_sys_img_guid(self, sys_img_guid):
        self.sys_img_guid = sys_img_guid

    def get_board_id(self):
        return self.board_id

    def set_board_id(self, board_id):
        self.board_id = board_id

    def get_fw_ver(self):
        return self.fw_ver

    def set_fw_ver(self, fw_ver):
        self.fw_ver = fw_ver

    def get_hca_type(self):
        return self.hca_type

    def set_hca_type(self, hca_type):
        self.hca_type = hca_type

    def get_hw_rev(self):
        return self.hw_rev

    def set_hw_rev(self, hw_rev):
        self.hw_rev = hw_rev

    def get_node_type(self):
        return self.node_type

    def set_node_type(self, node_type):
        self.node_type = node_type

    # Append a node description to the node descriptions list
    def add_node_desc(self, node_desc, node_guid):
        if not (node_guid in self.node_guids.keys()):
            self.node_guids[node_guid] = [] # Initialize list as value
            self.node_guids[node_guid].append(node_desc)
        else:
            self.node_guids[node_guid].append(node_desc)

    def get_mlnx_device_info(self):
        res = ""
        res += "Virtual / physical ports info for: " + self.parent_device + ":\n\n"
        res += "System Image GUID: " + "/sys/class/infiniband/" + self.parent_device + "/sys_image_guid = " + self.sys_img_guid + "\n"
        res += "Board ID: " + "/sys/class/infiniband/" + self.parent_device + "/board_id = " + self.board_id + "\n"
        res += "Firmware Version: " + "/sys/class/infiniband/" + self.parent_device + "/fw_ver = " + self.fw_ver + "\n"
        res += "HCA Type: " + "/sys/class/infiniband/" + self.parent_device + "/hca_type = " + self.hca_type + "\n"
        res += "HW Rev: " + "/sys/class/infiniband/" + self.parent_device + "/hw_rev = " + self.hw_rev + "\n"
        res += "Node Type: " + "/sys/class/infiniband/" + self.parent_device + "/node_type = " + self.node_type + "\n"
        for node_guid in self.node_guids:
            res += "\nNumber of related nodes with Node GUID = " + node_guid + " is: "+ str(len(self.node_guids[node_guid])) +", with the following Node Descriptions: \n"
            for node_desc in self.node_guids[node_guid]:
                res += "  " + node_desc + "\n"
        return res

#return true if command should be invoked. and added to dict in case we are generating new file
def is_command_allowed(config_key,related_flag=""):
    global config_dict
    if generate_config_flag:
        if not config_key in config_dict:
            approved = "yes"
            if related_flag:
                related_flags = related_flag.split("/")
                for flag in related_flags:
                    if not "no" in flag.lower()  :
                        flag = flag.strip()
                        approved = "no"

            config_dict[config_key] = {"approved":approved,"related flag":related_flag}
        return False

    if config_key in config_dict:
        if config_file_flag and config_dict[config_key]["approved"].lower() != 'yes':
            return False
        else:
            return True
    else:
        if config_file_flag :
            print("Warning: following command not collected it's missing in config file :\n" + config_key + ' \n Please make sure that you are using sysinfo-snapshot version (' + version + ') to generate config file (config.csv)  \n')
            running_warnings.append("following command not collected it's missing in config file :\n" + config_key + "\n")
    return True

is_bluefield_involved = False
is_run_from_bluefield_host = False
def update_net_devices():
    global pf_devices
    global asap_devices
    global mtusb_devices
    global vf_pf_devices
    global all_net_devices
    global local_mst_devices
    global mst_devices_exist
    global is_bluefield_involved
    global is_run_from_bluefield_host

    errors = []

    if os.path.isdir('/dev/mst'):
        current_mst_devices = os.listdir("/dev/mst")
        if interfaces_flag:
            current_mst_devices = specific_cable_devices
        for device in current_mst_devices:
            if (not (device.startswith("CA") or device.startswith("SW")) and "cable" in device): # Make sure we get info only for local cables
                local_mst_devices.append(device)
    if not sys_class_net_exists:
        errors.append("No Net Devices - The path /sys/class/net does not exist")

    st, network_devices = get_status_output("ls /sys/class/net")
    if (st != 0):
        errors.append("Failed to run the command ls /sys/class/net")
        #e.g: all_net_devices = ['eno2', 'eno3', 'eno4', 'eno5', 'enp0s29u1u1u5', 'enp139s0f1', 'ib0', 'ib1', 'ib2', 'lo']
    else: all_net_devices = network_devices.splitlines()
    if(interfaces_flag):
        specific_all_net_devices = []
        for device in specific_net_devices:
            if device in all_net_devices:
                specific_all_net_devices.append(device)
            else :
                print(device + " not found in net devices , please make sure you intered correct device\n ")
        all_net_devices = specific_all_net_devices
    # e.g 81:00.0 Infiniband controller: Mellanox Technologies MT27800 Family [ConnectX-5]
    st, lspci_devices = get_status_output("lspci | grep Mellanox")
    if (st != 0):
        errors.append("Failed to run the command lspci | grep Mellanox")
    if "bluefield" in lspci_devices.lower():
        is_bluefield_involved = True
        st1, result = get_status_output('dmidecode -t 1')
        if st1 == 0 and "bluefield" in result.lower():
            is_run_from_bluefield_host = True
    pci_devices = lspci_devices.splitlines()
    mellanox_net_devices = [] # Only Mellanox net_devices
    st, all_interfaces = get_status_output("ls -la /sys/class/net")
    if (st != 0):
        errors.append("Failed to run the command ls -la /sys/class/net")

    # e.g /dev/mst/mtusb-1                 - USB to I2C adapter as I2C master
    if mtusb_flag:
        st, mst_status = get_status_output("mst status")
        mtusbs = re.findall(r'(.*?)- USB', mst_status)
        for mtusb_device in mtusbs:
            mtusb_devices.append(mtusb_device.strip()) # Clean the string
        if interfaces_flag:
            mtusb_dev = []
            for dev in mtusb_devices:
                if dev in specific_mst_devices:
                    mtusb_dev.append(dev)
            mtusb_devices = mtusb_dev
    for lspci_device in pci_devices:
        device = lspci_device.split()[0]
        if  "function" in lspci_device.lower():
             if not device in vf_pf_devices:
                vf_pf_devices.append(device)
        # e.g lrwxrwxrwx  1 root root 0 Oct 26 15:51 ens11f0 -> ../../devices/pci0000:80/0000:80:03.0/0000:81:00.0/net/ens11f0
        match = re.findall(device + '\/net\/([\w.-]+)',all_interfaces)
        if match:
            for interface in match:
                mellanox_net_devices.append(interface)

    # e.g lrwxrwxrwx  1 root root 0 Oct 26 15:51 ens11f0 -> ../../devices/pci0000:80/0000:80:03.0/0000:81:00.0/net/ens11f0
    match = re.findall('virtual\/net\/([\w.-]+)',all_interfaces)
    if match:
        for interface in match:
            mellanox_net_devices.append(interface)
    asap_devices = mellanox_net_devices
    if "lo" in mellanox_net_devices:
        try:
            mellanox_net_devices.remove("lo")
            asap_devices.remove("lo")
        except:
            pass
    if "bonding_masters" in mellanox_net_devices:
        try:
            mellanox_net_devices.remove("bonding_masters")
            asap_devices.remove("bonding_masters")
        except:
            pass
    if "bond0" in mellanox_net_devices:
        try:
            mellanox_net_devices.remove("bond0")
        except:
            pass
    pf_devices = mellanox_net_devices
    if(interfaces_flag):
        specific_mellanox_net_devices = []
        specific_asap_devices = []
        for device in specific_net_devices:
            if device in mellanox_net_devices:
                specific_mellanox_net_devices.append(device)
            if device in asap_devices:
                specific_asap_devices.append(device)
        pf_devices = specific_mellanox_net_devices
        asap_devices = specific_asap_devices
    if errors:
        f = open(path + file_name + "/err_messages/dummy_functions", 'a')
        f.write("Could not get network devices from the following commands: ")
        f.write("\n")
        for error in errors:
            f.write(error)
            f.write("\n\n")
        f.close()


###########################################################
#    JSON Handlers And Global Variables

# define and initialize dictionaries hierarchy
server_commands_dict = {}
fabric_commands_dict = {}
files_dict = {}
external_files_dict = {}

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
#        ethtool_version Handlers

def ethtool_version_handler():
    global ethtool_command

    ethtool_command = "/usr/sbin/ethtool"
    st, ethtool_version = get_status_output(ethtool_command + " --version")
    if st != 0:
        ethtool_command_2 = "/sbin/ethtool"
        st, ethtool_version = get_status_output(ethtool_command_2 + " --version")
        if st != 0:
            return st, "Failed to run the command " + ethtool_command + " or " + ethtool_command_2
        ethtool_command = ethtool_command_2
    return 0, ethtool_version

#**********************************************************
#        ethtool_all_interfaces Handlers

def ethtool_all_interfaces_handler():
    if not all_net_devices:
        return "No interfaces were found"
    mellanox_net_devices = all_net_devices
    if (len(mellanox_net_devices) > 0):
        get_status_output("mkdir " + path + file_name + "/ethtool_S")
        #invoke_command(['mkdir', path + file_name + "/ethtool_S"])

    st, ethtool_version = ethtool_version_handler()
    if st != 0:
        return "Failed to run the command " + ethtool_command
    res = ""

    #Output - ethtool version 4.8
    version = ethtool_version.split()[2]
    if (LooseVersion(version) < LooseVersion('4.7')):
        ethtool_version = "Warning - " + ethtool_version + ", it is older than 4.7 ! \nIt will not show the 25g generation speeds correctly, cause ethtool 4.6 and below do not support it." 
    res += ethtool_version
    options = ["", "-i", "-g", "-a", "-k", "-c", "-T","-u","-m","--show-priv-flags", "--show-fec","--show-tunnels","-n", "-l", "-x"]
    for interface in mellanox_net_devices:
        res += "\n\n"
        for option in options:
            st, ethtool_interface = get_status_output(ethtool_command + " " + option + " " + interface)
            res += "ethtool " + option + " " + interface + "\n"
            if (st == 0):
                res += ethtool_interface
            else:
                if st != CANCELED_STATUS:
                    res += "Could not run command: ethtool " + option + " " + interface
            res += "\n____________\n\n"
    res += ethtool_S_output(mellanox_net_devices)
    return res

#**********************************************************
#       Split ethtool -S output from all ethtool outputs section
def ethtool_S_output(mellanox_net_devices):
    res = "ethtool -S output:"
    for interface in mellanox_net_devices:
        res += "\n\n"
        st, ethtool_interface = get_status_output(ethtool_command + " " + " -S " + interface)
        if (st != 0 and st != CANCELED_STATUS ):
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
        st, modinfo_module = get_status_output("modinfo " + module + " | grep 'filename\|version:'")
        if (st != 0 and st != CANCELED_STATUS):
            modinfo_module = "Could not run: " + '"' + " modinfo " + module + " | grep 'filename\|version:'"
        modinfo += modinfo_module + "\n"
    return modinfo


#**********************************************************
#        devlink handler

def devlink_handler():
    dev_st, devlink_health = get_status_output("devlink health show")
    if (dev_st != 0):
        return "There are no devices"
    dev_st, devlink_health_j = get_status_output("devlink health show -j")
    if (dev_st != 0):
        return "There are no devices"

    if (os.path.exists(path + file_name + "/devlink") == False):
        os.mkdir(path + file_name + "/devlink")

    devlink_health_json = json.loads(devlink_health_j)['health']
    pci_devices = devlink_health_json.keys()
    if (len(pci_devices) < 1):
        return "There are no devices"
    result = "\n" + devlink_health + "\n"
    result += "\n--------------------------------------------------\n"

    options = ["diagnose", "dump show"]
    if interfaces_flag:
        pci_dev = []
        for device in pci_devices:
            if device.split("/")[-1] in specific_pci_devices:
                pci_dev.append(device)
        pci_devices = pci_dev
    for device in pci_devices:
        for i, reporter in enumerate(devlink_health_json[device]):
            filtered_device_name = device.replace(":", "").replace(".", "").replace("/", "")
            if 'name' in reporter.keys():
                reporter_key = 'name'
            elif 'reporter' in reporter.keys():
                reporter_key = 'reporter'
            else:
                result += '\nError in parsing ' + device + 'information from: "devlink health show -j"\n'
                continue
            if reporter[reporter_key] == "fw_fatal" and 'last_dump_time' in devlink_health_json[device][i].keys():
                command = "devlink health dump show %s reporter %s " % (device, reporter[reporter_key])
                dump_output_result = command + "\n\n"
                dump_output_st, dump_output = get_status_output(command)
                if (dump_output_st != 0):
                    dump_output_result += "Error while reading output from command - " + command + "\n"
                dump_output = dump_output.split()
                space = dump_output[1]
                snapshot_id = dump_output[3]
                #devlink health dump show pci/0000:06:00.0/cr-space snapshot 1
                dump_output_st, dump_output = get_status_output("devlink region dump " + device + "/" + space + " snapshot " + snapshot_id)
                if (dump_output_st != 0):
                    dump_output_result += "Error while reading output from command - " + command + "\n"
                dump_output_result += dump_output
                devlink_file_name = filtered_device_name + "_" + option.replace(" ", "_") + "_" + reporter[reporter_key] + ".txt"
                full_file_name = "devlink/devlink_" + devlink_file_name
                file = open(path + file_name + "/" + full_file_name, 'w+')
                file.write(dump_output_result)
                file.close()
                result += "<td><a href=" + full_file_name + "> " + devlink_file_name + "</a></td>"
                result += "\n--------------------------------------------------\n"
            else:
                for option in options:
                    if 'last_dump_time' in devlink_health_json[device][i].keys() or (not option == "dump show"):
                        command = "devlink health %s %s reporter %s " % ( option, device, reporter[reporter_key])
                        dump_output_result = command + "\n\n"
                        dump_output_st, dump_output = get_status_output(command)
                        if (dump_output_st != 0):
                            dump_output_result += "Error while reading output from command - " + command + "\n"
                        dump_output_result += dump_output
                        devlink_file_name = filtered_device_name + "_" + option.replace(" ", "_") + "_" + reporter[reporter_key] + ".txt"
                        full_file_name = "devlink/devlink_" + devlink_file_name
                        file = open(path + file_name + "/" + full_file_name, 'w+')
                        file.write(dump_output_result)
                        file.close()
                        #dump_output_result += "<td><a href=" + full_file_name + "> " file_name + "</a></td>"
                        result += "<td><a href=" + full_file_name + "> " + devlink_file_name + "</a></td>"
                        result += "\n--------------------------------------------------\n"
    return result

#**********************************************************

#**********************************************************
#        mlnx_qos handler

def mlnx_qos_handler():
    if not pf_devices:
        return "No interfaces were found"
    st,res = getstatusoutput("mlnx_qos --version")
    if(st != 0 and "command not found" in res):
        return "mlnx_qos command not found"
    mellanox_net_devices = pf_devices
    res = ""
    options = ["-i"]
    for interface in mellanox_net_devices:
        res += "\n\n"
        for option in options:
            st, mlnx_qos_interface = get_status_output("mlnx_qos " + option + " " + interface)
            res += "mlnx_qos " + option + " " + interface + "\n"
            if (st == 0):
                res += mlnx_qos_interface
            else:
                if st == CANCELED_STATUS:
                   res += mlnx_qos_interface
                res += "Could not run command: mlnx_qos " + option + " " + interface
            res += "\n____________\n\n"
    return res

#**********************************************************
#  lldptool

def lldptool_handler(command):
    st,res = get_status_output("lldpad")
    if ("command not found" in res):
        return 1,res
    else:
        status,result = get_status_output(command)
        return status,result

#**********************************************************
#        cma_roce_mode/tos Handler

def cma_roce_handler(func):
    st, devices = get_status_output("ibstat | grep \"CA '\"")
    if st != 0:
        return "Failed to retrieve mlx devices"
    if devices == "":
        return "There are no mlx devices"
    res = ""
    first = True
    mlx_devices = [device.split("'")[1] for device in devices.splitlines()]
    if interfaces_flag:
        mlx_devices_specific = []
        for device in specific_rdma_mlnx_devices:
            if device in mlx_devices:
                mlx_devices_specific.append(device)
        mlx_devices = mlx_devices_specific
    for _device in mlx_devices:
        st, _device_res = get_status_output("cma_roce_" + func + " -d " + _device)
        if not first:
            res += "\n\n---------------\n\n"
        res += "cma_roce_" + func + " -d " + _device + "\n\n"
        res += _device_res
        first = False
    return res

#**********************************************************
#        mlxdump Handler Helper Function
def is_mft_installed():
    mft_installed = True
    mft_message = "MFT is installed"
    if not is_MFT_installed:
        mft_installed = False
        if non_root:
            mft_message =  "Running as a non-root user - You must be root to use mst tool"
        else:
            mft_message =  "MFT is not installed, please install MFT and try again."
    return mft_installed, mft_message

#**********************************************************
#        mlxdump Handler
def mlxdump_handler():
    mft_installed, mft_message = is_mft_installed()
    if not mft_installed:
        return mft_message
    if (len(pci_devices) < 1):
        return "There are no devices"
    options = ["fsdump"]
    temp = '_run_'
    for pci_device in pci_devices:
        device = pci_device["device"]
        if device in vf_pf_devices:
            continue
        if not "mtusb" in device:
            for option in options:
                gvmi_number = device.split('.')[1].strip()
                gvmi = "_gvmi_" + gvmi_number
                output = device + "_" + option.replace("-", "") + gvmi
                filtered_file_name = output.replace(":", "").replace(".", "").replace("/", "_")
                st, res = get_status_output("mlxdump -d " + device + " " + option + " --gvmi " + gvmi_number + " > " + path + file_name + "/firmware/mlxdump_" + filtered_file_name)
    return "Links"

def add_mlxdump_links():
    file_link = {}
    for file in os.listdir(path+file_name+"/firmware"):
        if file.startswith("mlxdump"):
            file_link[file] = "<td><a href=firmware/" + file + ">" + file + "</a></td>"
    return file_link

#**********************************************************
#        ASAP Handlers

def asap_handler():
    result = []
    is_all_failed = True
    try:
        with open(path + file_name + "/asap/ovs_dpctl_dump_flows", "w+") as outF:
            outF.write("ovs-dpctl dump-flows -m\n")
            st, res = get_status_output("ovs-dpctl dump-flows -m >> " + path + file_name + "/asap/ovs_dpctl_dump_flows", '300')
            if st != 0:
                if st == CANCELED_STATUS:
                    outF.write(res)
                outF.write("Could not run: ovs-dpctl dump-flows -m")
            else:
                is_all_failed = False
        result.append("<td><a href=asap/ovs_dpctl_dump_flows> ovs_dpctl_dump_flows </a></td>")
    except:
        err = "Could not open the file: " + file_name + "/asap/ovs_dpctl_dump_flows."
        running_warnings.append(err)
    try:
        with open(path + file_name + "/asap/tc_qdisc_show", "w+") as outF:
            outF.write("tc qdisc show\n")
            st, res = get_status_output("tc qdisc show >> " + path + file_name + "/asap/tc_qdisc_show", '300')
            if st != 0:
                if st == CANCELED_STATUS:
                    outF.write(res)
                outF.write("Could not run: ovs-dpctl tc qdisc show")
            else:
                is_all_failed = False
        result.append("<td><a href=asap/tc_qdisc_show> tc_qdisc_show </a></td>")
    except:
        err = "Could not open the file: " + file_name + "/asap/tc_qdisc_show."
        running_warnings.append(err)

    try:
        with open(path + file_name + "/asap/ovs-vsctl_get_Open_vSwitch", "w+") as outF:
            outF.write("ovs-vsctl get Open_vSwitch . other_config\n")
            st, res = get_status_output("ovs-vsctl get Open_vSwitch . other_config >> " + path + file_name + "/asap/ovs-vsctl_get_Open_vSwitch", '300')
            if st != 0:
                if st ==CANCELED_STATUS:
                    outF.write(res)
                outF.write("Could not run: ovs-vsctl get Open_vSwitch . other_config")
            else:
                is_all_failed = False
        result.append("<td><a href=asap/ovs-vsctl_get_Open_vSwitch> ovs-vsctl get Open_vSwitch </a></td>")
    except:
        err = "Could not open the file: " + file_name + "/asap/ovs-vsctl_get_Open_vSwitch."
        running_warnings.append(err)


    st, output = get_status_output("ovs-vsctl show | grep Bridge | awk '{$1=$1};1' | cut -d' ' -f 2", '300')
    if  st!= 0:
        try:
            with open(path + file_name + "/asap/ovs_dpctl_dump_flows_bridges", "a+") as outF:
                outF.write(str(output))
        except:
            err = "Could not open the file: " + file_name + "/asap/ovs_dpctl_dump_flows_bridges."
            running_warnings.append(err)
    else:
        for row in output.split('\n'):
            if 'b' in row:
                cmd = "ovs-ofctl dump-flows " + row
                try:
                    with open(path + file_name + "/asap/ovs_dpctl_dump_flows_bridges", "a+") as outF:
                        outF.write(cmd)
                        st, res = get_status_output(cmd  + " >> " + path + file_name + "/asap/ovs_dpctl_dump_flows_bridges", '300')
                        if st != 0:
                            if st == CANCELED_STATUS:
                                outF.write(res)
                            outF.write("Could not run: ovs-dpctl dump-flows")
                        else:
                            is_all_failed = False
                except:
                    err = "Could not open the file: " + file_name + "/asap/ovs_dpctl_dump_flows_bridges."
                    running_warnings.append(err)
    result.append("<td><a href=asap/ovs_dpctl_dump_flows_bridges> ovs_dpctl_dump_flows_bridges </a></td>")
    if is_all_failed :
        err = "--asap flag was provided but all asap commands failed."
        running_warnings.append(err)
        return 1,err
    else:
        return 0,result

def asap_tc_handler():
    if not asap_devices:
        running_warnings.append("--asap_tc flag was provided but there's no interfaces found.")
        return 1, "No interfaces were found"
    result = []
    is_all_failed = True
    for interface in asap_devices:
        cmd =  "tc -s filter show dev " + interface + " ingress "
        try:
            with open(path + file_name + "/asap_tc/ovs_tc_filter_" + interface, "a+") as outF:
                outF.write(cmd)
                st, res = get_status_output(cmd + " >> " + path + file_name + "/asap_tc/ovs_tc_filter_" + interface, '300')
                if st != 0:
                    if st == CANCELED_STATUS:
                        outF.write(res)
                    outF.write("Could not run: " + cmd)
                else:
                    is_all_failed = False
            result.append("<td><a href=asap_tc/ovs_tc_filter_" + interface + "> ovs_tc_filter_" + interface + " </a></td>")
        except:
            err = "Could not open the file: " + file_name + "/asap/ovs_tc_filter_."
            running_warnings.append(err)
    if is_all_failed :
        err = "--asap_tc flag was provided but all asap tc filter commands failed. "
        running_warnings.append(err)
        return 1,err
    else:
        return 0,result

#**********************************************************
#            rdma tool Handler

def rdma_tool_handler():
    if os.path.exists("/opt/mellanox/iproute2/sbin/rdma") == False :
        err = "--rdma_debug flag was provided but /opt/mellanox/iproute2/sbin/rdma does not exsist. "
        running_warnings.append(err)
        print(err)
        return 1 , err
    result = []
    is_all_failed = True
    options = ["resource show","resource show cm_id","resource show qp","res show cq"]
    for option in options:
        with open(path + file_name + "/rdma_tool/" + option, "a+") as outF:
            outF.write("/opt/mellanox/iproute2/sbin/rdma " + option + "\n")
            st, res = get_status_output("/opt/mellanox/iproute2/sbin/rdma " + option)
            if st == 0:
                outF.write(res)
                is_all_failed = False
            else:
                outF.write("Could not run: /opt/mellanox/iproute2/sbin/rdma " + option)
        result.append("<td><a href='rdma_tool/" + option + "'> /opt/mellanox/iproute2/sbin/rdma " + option + " </a></td>")
    if is_all_failed :
        err = "--rdma_debug flag was provided but all rdma tool commands failed. "
        running_warnings.append(err)
        print(err)
        return 1,err
    else:
        return 0,result


#**********************************************************
#            ibdev2pcidev Handlers

def ibdev2pcidev_handler():
    st = st_infiniband_devices
    devices = infiniband_devices
    if st != 0:
        return "Unable to get ibdev to pci mapping: /sys/class/infiniband does not exist."
    final_mapping = ""
    for device in devices.splitlines():
        #Example output:  /sys/class/infiniband/mlx5_3/device -> ../../../0000:8b:00.1
        cmd = "ls -la /sys/class/infiniband/"+ device.strip() + "/device"
        st2, device_mapping = get_status_output(cmd)
        if st2 != 0:
            final_mapping += "Could not get pci mapping for device"+ device.strip() + "\n"
        else:
            #Example: mlx5_0 is mapped to /sys/class/infiniband/mlx5_0/device -> ../../../0000:86:00.0
            device_mapping_split = device_mapping.split("/")
            device_pci_mapping = device_mapping_split[-1] #Now it will be mlx5_0 --> 0000:86:00.0 (The last part only)
            port_mapping = device + " ==> " + device_pci_mapping
            final_mapping += port_mapping
            cmd = "ls /sys/class/infiniband/"+ device.strip() + "/device" + "/infiniband_verbs/"
            st2, uverbs_mapping = get_status_output(cmd)
            if st2 == 0:
           	    final_mapping += " ==> " + uverbs_mapping
            final_mapping += "\n"
    return final_mapping

#**********************************************************
#        fwtrace Handlers
def fwtrace_handler():
    mft_installed, mft_message = is_mft_installed()
    if not mft_installed:
        return mft_message
    if (len(pci_devices) < 1):
        return "There are no devices"

    options = ["-i all --tracer_mode FIFO"]
    fwtrace = ""
    for pci_device in pci_devices:
        device = pci_device["device"]
        if device.split('.')[1].strip() != "0":
            continue
        if device in vf_pf_devices:
            continue
        if "cable" in device:
            continue
        if (fwtrace != ""):
            fwtrace += "\n---------------------------------------------------------------\n\n"
        flag = 0
        for option in options:
            if (flag != 0):
                fwtrace += "\n****************************************\n\n"
            fwtrace += "fwtrace -d " + device + " " + option + "\n\n"
            fwtrace_st, fwtrace_device_option = get_status_output("fwtrace -d " + device + " " + option, '2m')
            if (fwtrace_st != 0 and fwtrace_st !=  CANCELED_STATUS):
                fwtrace_device_option = "Could not run: fwtrace -d " + device + " " + option
            fwtrace += fwtrace_device_option + "\n"
            flag = 1
    return fwtrace

def mlxcables_options_handler():
    global with_inband_flag
    global mst_devices_exist
    global local_mst_devices

    mlxcables = []
    mlxcables_out = []
    res = ''

    if mst_devices_exist:
        current_mst_devices = os.listdir("/dev/mst")
        if interfaces_flag:
            current_mst_devices = specific_cable_devices
        if with_inband_flag: # with in-band cables
            for device in current_mst_devices:
                if 'cable' in device:
                    mlxcables.append(device)
        else: # without in-band cables
            mlxcables = local_mst_devices
    else:
        return 1, 'Error running mlxcables - no MST devices were found!'
    if not mlxcables:
        res += "No cables found"
    options = ["--DDM", "--dump"]
    for mlxcable in mlxcables:
        if res != '':
            res += '\n\n---------------------------------------------------------------\n\n'
        flag = 0
        for option in options:
            if flag != 0:
                res += '\n\n****************************************\n\n'
            res += 'mlxcables -d ' + mlxcable + ' ' + option + '\n\n'
            res_st, res_mlxcable_option = get_status_output('mlxcables -d ' + mlxcable + ' ' + option)
            if res_st != 0 and res_st != CANCELED_STATUS:
                res_mlxcable_option = 'Could not run: \"mlxcables -d ' + mlxcable + ' ' + option + '"'
            res += res_mlxcable_option
            flag = 1
    if os.path.isdir(path + file_name + "/cables"):
        try:
            with open(path + file_name + "/cables/mlxcables_options_output","w+") as f:
                f.write(res)
        except:
            res_mlxcable_option = "Could not open the file: " + file_name + "/cables/mlxcables_options_output"
            res += res_mlxcable_option
    else:
        return 1, "Error generating mlxcables output - unable to make directory: /cables"
    return 0, res

def mlxcables_standard_handler():
    global are_inband_cables_loaded
    global with_inband_flag

    mlxcables_res = ""
    mlxcables_out = []

    if not mst_devices_exist:
        return 1, 'Error running mlxcables - no MST devices were found!'
    if not os.path.isdir(path + file_name + "/cables"):
        return 1, 'Error generating mlxcables output - unable to make directory: /cables'
    else:
        f = open( path + file_name + "/cables/mlxcables_output","w+")

    if with_inband_flag: # If in-band cable info is requested, we have to load in-band cables anyways
        mlxcables_res = ""
        if interfaces_flag:
            if not specific_cable_devices:
                mlxcables_res += "No cables found"
            for device in specific_cable_devices: 
                st, res = get_status_output("mlxcables -d " + device)
                mlxcables_res += "\n"
                mlxcables_res += res
        else :
            st, mlxcables_res = get_status_output("mlxcables")
        f.write(mlxcables_res)
        f.close()
        mlxcables_out.append("<td><a href=\"cables/mlxcables_output\">mlxcables_output</a></td>")
        return 0, mlxcables_out
    else: # Not to include in-band cables info
        if are_inband_cables_loaded:
            current_mst_devices = os.listdir("/dev/mst")
            if interfaces_flag:
                if not specific_cable_devices:
                    mlxcables_res += "No cables found"
                current_mst_devices = specific_cable_devices
            for device in current_mst_devices: # Run mlxcables only on local cables even if in-band cables are loaded
                if (not (device.startswith("CA") or device.startswith("SW")) and "cable" in device):
                    st, res = get_status_output("mlxcables -d " + device)
                    mlxcables_res += "\n"
                    mlxcables_res += res
            f.write(mlxcables_res) # To put output in /cables, but still display it in HTML file because --no_inband was NOT given
            f.close()
            return 0, mlxcables_res
        else:
            mlxcables_res = ""
            if interfaces_flag:
                if not specific_cable_devices:
                    mlxcables_res += "No cables found"
                for device in specific_cable_devices: 
                    st, res = get_status_output("mlxcables -d " + device)
                    mlxcables_res += "\n"
                    mlxcables_res += res
            else :
                st, mlxcables_res = get_status_output("mlxcables")# To put output in /cables, but still display it in HTML file because --no_inband was NOT given
            f.write(mlxcables_res)
            f.close()
            return 0, mlxcables_res

def lspci_vv_handler():
    mlnx_pci = [] # A list containing  PCI addresses of Mellanox devices
    result = "Mellanox Pci devices tree \n" # Final result
    st,res = get_status_output("lspci -Dnnd 15b3:")
    if st == 0  and res :
        lines = res.splitlines()
        for line in lines:
            device = line.split()[0]
            path = os.readlink("/sys/bus/pci/devices/" + device)
            pci = path.split('/')
            for part in pci:
                part = part.split(":",1)
                if len(part) > 1:
                    part = part[1]
                    # Define the case-insensitive regular expression pattern to match  "xx:xx.x"
                    pattern = r'^[0-9a-zA-Z]{2}:[0-9a-zA-Z]{2}\.?[0-9a-zA-Z]*$'
                    # Use re.match() to check if the input string matches the pattern
                    match = re.match(pattern, part)
                    if bool(match) and not part in mlnx_pci :
                        mlnx_pci.append(part)
            result += path + "\n"
    result += "\n\n"
    result += 'lspci -vv -s <Query device that is connected to Mellanox device according to the lspci tree>' + '\n\n'
    if not mlnx_pci:
        result += 'No devices found'
    for pci_address in mlnx_pci:
        st, lspci_vv = get_status_output('lspci -vv -s ' + pci_address)
        if not st == 0:
            result += 'Error invoking lspci -vv -s ' + pci_address + '\n'
        else:
            result += 'lspci -vv -s ' + pci_address +'\n'
            result += lspci_vv + '\n' + '\n'
    return(result)

#**********************************************************
#        Helper for mstcommand_d_handler - handles commands with given number of runs
def command_with_number_of_runs(number_of_runs, device, command, suffix, pcie_debug, pci_device=False):
    no_log_status_output("mkdir " + path + file_name + "/amber_info")
    command_result =""
    for i in range(0, number_of_runs):
        suffix_list = []
        if "--amber_collect" in suffix :
            suffix_list = [" --amber_collect "  + path + file_name +"/amber_info/amber_collect_port" + str(i+1) + "_" + str(device) + ".csv"]
            if pci_device:
                suffix_list.append(" --amber_collect "  + path + file_name +"/amber_info/amber_collect_pcie" + str(i+1) + "_" + str(device) + ".csv --port_type PCIE")
        else:
            suffix_list.append(suffix)
        for suff in suffix_list:
            command_result += "\n#" + str(i+1) + " " + command + " -d " + device + suff + "\n\n"
            mlx_st, command_result_device = get_status_output(command + " -d " + device + suff, "30")
            if pcie_debug:
                output = command + "_" + device + "_run_" + str(i + 1)
                filtered_file_name = output.replace(":", "").replace(".", "")
                save_mlxlink_output_to_file(filtered_file_name,command_result_device)
            command_result_device = command_result_device.replace("[31m","").replace("[32m","").replace("[33m","").replace("[0m","")
            if (mlx_st != 0):
                command_result_device = "Errors detected while running: " + command + " -d " + device + suffix + '"\n' + command_result_device
                command_result += command_result_device
                break
            command_result += command_result_device
    return command_result

#**********************************************************
#        mst command -d <device> Handlers
def mstcommand_d_handler(command,pcie_debug = False):
    mft_installed, mft_message = is_mft_installed()
    if (command == 'mlxlink / mstlink'):
        if mft_installed:
            st, mlxlink_test = get_status_output('man mlxlink') # If MFT is installed but it is an old version that does NOT include Mlxlink
            if st == 0:
                command = 'mlxlink'
            elif is_MST_installed:
                st, mstlink_test = get_status_output('man mstlink')
                if st == 0:
                    command = 'mstlink'
                else:
                    return "could not run mstlink"
            else:
                return "could not run mlxlink / mstlink"
        else:
            if is_MST_installed: # If MFT is not installed, but MST is installed
                st, mstlink_test = get_status_output('man mstlink')
                if st == 0:
                    command = 'mstlink'
                else:
                    return "could not run mstlink"
            else:
                return "MFT and MST are not installed - could not run mlxlink / mstlink"
    else:
        if not mft_installed:
            return mft_message
    if (len(pci_devices) < 1):
        return "There are no devices"
    suffix_list = []
    if command == "mlxconfig":
        suffix_list.append(" -e q")
    elif command == "mlxlink" or command == "mstlink":
        suffix_list = [" -m", " -e", " -c", " --show_fec", " --port_type PCIE -c -e"," --rx_fec_histogram --show_histogram"," --cable --ddm"," --cable --dump","--amber_collect"]
    else:
        suffix_list.append(" ")

    if pcie_debug : # run only port_type PCIE for pcie_debug
        suffix_list = [" --port_type PCIE -c -e"]

    command_result = ""
    mst_status_rs, mst_status_output = get_status_output("mst status -v")
    # PCIe ports
    for pci_device in pci_devices:
        device = pci_device["device"]
        if mft_installed:
            if device  not in mst_status_output:
                continue
        elif is_MST_installed:
            if device in vf_pf_devices:
                continue
        if "cable" in device:
            continue
        if command == "mlxmcg" and not ("ConnectX-3" in pci_device["name"] or "ConnectX-3 Pro" in  pci_device["name"] ):
            continue
        for suffix in suffix_list:
            number_of_runs = 1
            if (command_result != ""):
                command_result += "\n\n-------------------------------------------------------------\n\n"
            if "--port_type PCIE -c -e" in suffix or "--amber_collect" in suffix :
                number_of_runs = 3
            # PCIe ports
            command_result+=command_with_number_of_runs(number_of_runs,device,command, suffix, pcie_debug, True)
    if not command_result:
        command_result = "No devices found for " + command
    return command_result

def save_mlxlink_output_to_file(filtered_file_name,result):
    try:
        file_path = path + file_name + "/firmware/" + filtered_file_name
        f = open(file_path, "w+")
        f.write(result)
        f.close()
    except:
        print("Error in creating new file in the system : " + file_path)

def general_fw_command_output(command, card, timeout = '80'):
    commands_dict = {}
    fwflint_error = "Couldn't run mstflint / flint. Please make sure MST or MFT are installed."
    fwdump_error = "Couldn't run mstregdump / mstdump. Please make sure MST or MFT are installed."
    fwconfig_error = "Couldn't run mstconfig / mlxconfig. Please make sure MST or MFT are installed."
    mlxdump_error = "Couldn't run mlxdump. Please make sure MFT is installed."
    mlxdump_notsupported_error = "Device not supported, couldn't run mlxdump " + card + " pcie_uc --all"
    command_error = "Could not run firmware command: " + command
    tool_error = "N/A"

    # Initialize lists as dictonary values
    # First index of each list will be the MST command
    # Second index of each list will be the MFT command
    # Invoke MST command as a priority, if it fails invoke MFT command
    # Return 0 --> Command succeeded, 1 --> Failed

    commands_dict['fwdump'] = ["mstdump " + card, "mstregdump " + card]
    commands_dict['fwconfig'] = ["mstconfig -d " + card + " -e  q", "mlxconfig -d " + card + " -e  q"]
    commands_dict['fwflint'] = ["mstflint -d " + card, "flint -d " + card]
    commands_dict['mlxdump'] = ["mlxdump -d " + card + " pcie_uc --all"]
    if command == 'fwflint_q' or command == 'fwflint_dc':
        if (not is_MFT_installed and not is_MST_installed):
            return(1, fwflint_error, tool_error)
        if command == 'fwflint_q':
            flint_flags = ' q full'
        else:
            flint_flags = ' dc'
        st, fw_query = get_status_output(commands_dict["fwflint"][0] + flint_flags, timeout)
        if st == 0:
           return(0, fw_query, 'mst')
        else:
            st, fw_query = get_status_output(commands_dict["fwflint"][1] + flint_flags, timeout)
            if st == 0:
                return(0, fw_query, 'mft')
            else:
                return(1, command_error, tool_error)
    elif command == 'fwdump':
        if (not is_MFT_installed and not is_MST_installed):
            return(1, fwdump_error, tool_error)
        if(not no_fw_regdumps_flag):
            st, fw_query = get_status_output(commands_dict['fwdump'][0], timeout)
            if st == 0:
                return(0, fw_query, 'mft')
            else:
                st, fw_query = get_status_output(commands_dict['fwdump'][1], timeout)
                if st == 0:
                    return(0, fw_query, 'mst')
                else:
                    return(1, command_error, tool_error)
        else:
            return(1, "no_fw_regdumps_flag is used, the fw regdump commands are not executed.", tool_error)
    elif command == 'fwconfig':
        if (not is_MFT_installed and not is_MST_installed):
            return(1, fwconfig_error, tool_error)
        if(not no_mstconfig_flag):
            st, fw_query = get_status_output(commands_dict['fwconfig'][0], timeout)
            if st == 0:
                return(0, fw_query, 'mst')
            else:
                st, fw_query = get_status_output(commands_dict['fwconfig'][1], timeout)
                if st == 0:
                    return(0, fw_query, 'mft')
                return(1, command_error, tool_error)
        else:
            return(1, "no_mstconfig_flag is used, the mstconfig commands are not executed.", tool_error)   
    elif command =='mlxdump':
        if (not is_MFT_installed ):
            return(1, mlxdump_error, tool_error)
        st, fw_query = get_status_output(commands_dict['mlxdump'][0], timeout)
        if st == 0:
            return(0, fw_query, 'mft')
        elif 'not supported' in fw_query:
            return(1, mlxdump_notsupported_error, tool_error)
        return(1, command_error, tool_error)
    else:
        return (1, command_error, tool_error)

def general_fw_commands_handler(command, card, filtered_file_name, timeout = '80'):
    if command == 'fwdump':
        st, res, tool_used = general_fw_command_output(command, card, timeout)
        if tool_used == 'mst':
            try:
                f = open(path + file_name + "/firmware/mstregdump_" + filtered_file_name, "w+")
                f.write(res + "\n")
                f.close()
                return ("firmware/mstregdump_" + filtered_file_name, "mst", 0)
            except:
                with open(path+file_name+"/err_messages/dummy_functions", 'a') as f:
                    f.write("The full command is: mstregdump " + card + "\n")
                    f.write("Error in creating new file in the system")
                    f.write("\n\n")
                    return("Error in creating new file in the system", "Error in creating new file in the system", 1)
        
        elif tool_used =='mft':
            try:
                f = open(path + file_name + "/firmware/mstdump_" + filtered_file_name, "w+")
                f.write(res + "\n")
                f.close()
                return ("firmware/mstdump_" + filtered_file_name, "mft", 0)
            except:
                with open(path+file_name+"/err_messages/dummy_functions", 'a') as f:
                    f.write("The full command is: mstdump " + card + "\n")
                    f.write("Error in creating new file in the system")
                    f.write("\n\n")
                    return("Error in creating new file in the system", "Error in creating new file in the system", 1)
        else:
            try:
                f = open(path + file_name + "/firmware/mstdump_" + filtered_file_name, "w+")
                f.write("Could not run mstregdump AND mstdump commands!")
                f.close()
                return ("firmware/mstdump_" + filtered_file_name, "mft", 0)
            except:
                with open(path+file_name+"/err_messages/dummy_functions", 'a') as f:
                    f.write("The full command is: mstregdump " + card + "\n")
                    f.write("Error in creating new file in the system")
                    f.write("\n\n")
                    return("Error in creating new file in the system", "Error in creating new file in the system", 1)
    elif command == 'fwconfig':
        st, res, tool_used = general_fw_command_output(command, card, timeout)
        if tool_used == 'mst':
            try:
                f = open(path + file_name + "/firmware/mstconfig_" + filtered_file_name, "w+")
                f.write("mstconfig -d " + card + " -e  q" + "\n")
                f.write(res + "\n")
                f.close()
                return ("firmware/mstconfig_" + filtered_file_name, "mst", 0)
            except:
                with open(path+file_name+"/err_messages/dummy_functions", 'a') as f:
                    f.write("The full command is: mstconfig -d " + card + " -e  q" + "\n")
                    f.write("Error in creating new file in the system")
                    f.write("\n\n")
                    return("Error in creating new file in the system", "Error in creating new file in the system", 1)
        elif tool_used =='mft':
            try:
                f = open(path + file_name + "/firmware/mlxconfig_" + filtered_file_name, "w+")
                f.write("mlxconfig -d " + card + " -e  q" + "\n")
                f.write(res + "\n")
                f.close()
                return ("firmware/mlxconfig_" + filtered_file_name, "mft", 0)
            except:
                with open(path+file_name+"/err_messages/dummy_functions", 'a') as f:
                    f.write("The full command is: mlxconfig -d " + card + " -e  q" + "\n")
                    f.write("Error in creating new file in the system")
                    f.write("\n\n")
                    return("Error in creating new file in the system", "Error in creating new file in the system", 1)
        else:
            try:
                f = open(path + file_name + "/firmware/mlxconfig_" + filtered_file_name, "w+")
                f.write("Could not run mstconfig AND mlx commands!")
                f.close()
                return ("firmware/mlxconfig_" + filtered_file_name, "mft", 0)
            except:
                with open(path+file_name+"/err_messages/dummy_functions", 'a') as f:
                    f.write("The full command is: mstconfig -d " + card + " -e  q" + "\n")
                    f.write("Error in creating new file in the system")
                    f.write("\n\n")
                    return("Error in creating new file in the system", "Error in creating new file in the system", 1)
    elif command == 'fwflint_q' or command == 'fwflint_dc':
        if command == 'fwflint_q':
            flint_flags = ' q'
            filtered_file_name = filtered_file_name + '_q'
        else:
            flint_flags = ' dc'
            filtered_file_name = filtered_file_name + '_dc'
        st, res, tool_used = general_fw_command_output(command, card, timeout)
        if tool_used == 'mst':
            try:
                f = open(path + file_name + "/firmware/mstflint_" + filtered_file_name, "w+")
                f.write("mstflint -d " + card + flint_flags + "\n")
                f.write(res + "\n")
                f.close()
                return ("firmware/mstflint_" + filtered_file_name, "mst", 0)
            except:
                with open(path+file_name+"/err_messages/dummy_functions", 'a') as f:
                    f.write("The full command is: mstflint -d " + card + flint_flags + "\n")
                    f.write("Error in creating new file in the system")
                    f.write("\n\n")
                    return("Error in creating new file in the system", "Error in creating new file in the system", 1)
        elif tool_used == 'mft':
            try:
                f = open(path + file_name + "/firmware/flint_" + filtered_file_name, "w+")
                f.write("flint -d " + card + flint_flags + "\n")
                f.write(res + "\n")
                f.close()
                return ("firmware/flint_" + filtered_file_name, "mft", 0)
            except:
                with open(path+file_name+"/err_messages/dummy_functions", 'a') as f:
                    f.write("The full command is: flint -d " + card + flint_flags + "\n")
                    f.write("Error in creating new file in the system")
                    f.write("\n\n")
                    return("Error in creating new file in the system", "Error in creating new file in the system", 1)
        else:
            try:
                f = open(path + file_name + "/firmware/mstflint_flint_" + filtered_file_name, "w+")
                f.write("Could not run mstflint -d " + card + flint_flags + "and flint -d " + card + flint_flags  + '\n')
                f.close()
                return ("firmware/flint_" + filtered_file_name, "mft", 0)
            except:
                with open(path+file_name+"/err_messages/dummy_functions", 'a') as f:
                    f.write("The full command is: mstflint -d " + card + flint_flags +  "\n")
                    f.write("Error in creating new file in the system")
                    f.write("\n\n")
                    return("Error in creating new file in the system", "Error in creating new file in the system", 1)
    elif (command == 'mlxdump'):
        st, res, tool_used = general_fw_command_output(command, card, timeout)
        try:
            f = open(path + file_name + "/firmware/mlxdump_" + filtered_file_name +"_pcie_uc", "w+")
            f.write(" mlxdump -d " + card + " pcie_uc" + "\n")
            f.write(res + "\n")
            f.close()
            return ("firmware/mlxdump_" + filtered_file_name +"_pcie_uc", "mft", 0)
        except:
            with open(path+file_name+"/err_messages/dummy_functions", 'a') as f:
                f.write("The full command is: mlxdump -d " + card + " pcie_uc" + "\n")
                f.write("Error in creating new file in the system")
                f.write("\n\n")
                return("Error in creating new file in the system", "Error in creating new file in the system", 1)

def generate_mst_config(card,ports ,sleep_period, mstregdump_out, mst_status_output):
    for port in ports:
        if is_MFT_installed:
            if card + "." + port not in mst_status_output:
                return
        elif is_MST_installed:
            if card + "." + port in vf_pf_devices:
                return
        output = card + "." + port
        filtered_file_name = output.replace(":", "").replace(".", "").replace("/","")
        output_file, tool_used, is_error = general_fw_commands_handler('fwconfig', card + "." + port, filtered_file_name)
        if is_error == 0:
            if tool_used == 'mst':
                mstregdump_out.append("<td><a href=\""+ output_file +"\">mstconfig_" + output + "</a></td><br />")
            else:
                mstregdump_out.append("<td><a href=\""+ output_file +"\">mlxconfig_" + output + "</a></td><br />")
            time.sleep(sleep_period)

def generate_card_logs(card, sleep_period, mstregdump_out, mst_status_output):
    if is_MFT_installed:
        if card not in mst_status_output:
            return
    elif is_MST_installed:
        if card in vf_pf_devices:
            return
    output = card
    filtered_file_name = output.replace(":", "").replace(".", "").replace("/","")
    output_file, tool_used, is_error = general_fw_commands_handler('fwflint_q', card, filtered_file_name)
    if is_error == 0:
        if tool_used == 'mst':
            mstregdump_out.append("<td><a href=\""+ output_file +"\">mstflint_" + output + "_q</a></td><br />")
        else:
            mstregdump_out.append("<td><a href=\""+ output_file +"\">flint_" + output + "_q</a></td><br />")
        time.sleep(sleep_period)

    output = card
    filtered_file_name = output.replace(":", "").replace(".", "").replace("/","")
    output_file, tool_used, is_error = general_fw_commands_handler('fwflint_dc', card, filtered_file_name)
    if is_error == 0:
        if tool_used == 'mst':
            mstregdump_out.append("<td><a href=\""+ output_file +"\">mstflint_" + output + "_dc</a></td><br />")
        else:
            mstregdump_out.append("<td><a href=\""+ output_file +"\">flint_" + output + "_dc</a></td><br />")
        time.sleep(sleep_period)

    output = card
    filtered_file_name = output.replace(":", "").replace(".", "").replace("/","")
    output_file, tool_used, is_error = general_fw_commands_handler('mlxdump', card, filtered_file_name)
    if is_error == 0:
        mstregdump_out.append("<td><a href=\""+ output_file +"\">mlxdump_" + output + "_pcie_uc</a></td><br />")
        time.sleep(sleep_period)

def generate_mst_dumps(card, ports,sleep_period, mstregdump_out, mst_status_output,temp):
    for port in ports:
        if is_MFT_installed:
            if card + "." + port not in mst_status_output: 
                return
        elif is_MST_installed:
            if card + "." + port in vf_pf_devices:
                return
        for i in range(0, 3):
            output = card + "." + port + temp + str(i + 1)
            filtered_file_name = output.replace(":", "").replace(".", "").replace("/","")
            output_file, tool_used, is_error = general_fw_commands_handler('fwdump', card + "." + port, filtered_file_name)
            if is_error == 0:
                if tool_used == 'mst':
                    mstregdump_out.append("<td><a href=\""+ output_file +"\">mstregdump_" + output + "</a></td><br />")
                else:
                    mstregdump_out.append("<td><a href=\""+ output_file +"\">mstdump_" + output + "</a></td><br />")
                time.sleep(sleep_period)
#**********************************************************
#        mst_commands_query_output Handlers
def mst_func_handler():
    all_devices = []
    mstregdump_out = []
    sleep_period = 2
    threads_dumps = []
    threads_config = []

    if (len(pci_devices) < 1):
        mstregdump_out.append("There are no Mellanox cards.\n")
        return 2, mstregdump_out
    for pci_device in pci_devices:
        all_devices.append(pci_device["device"])
    if mtusb_flag:
        if len(mtusb_devices) < 1:
            mstregdump_out.append("There are no MTUSB devices.\n")
        else:
            all_devices += mtusb_devices
    mst_status_rs, mst_status_output = get_status_output("mst status -v")
    temp = '_run_'

    cards_port_dict = {}
    for device in all_devices:
        card, port = device.split(".")
        if not card in cards_port_dict:
            cards_port_dict[card] = []
        cards_port_dict[card].append(port)

    for card in cards_port_dict:
        t_dumps = threading.Thread(target = generate_mst_dumps, args = [card ,cards_port_dict[card], sleep_period, mstregdump_out, mst_status_output,temp])
        t_dumps.start()
        threads_dumps.append(t_dumps)
    for thread in threads_dumps:
        thread.join()
    for card in cards_port_dict:
        t_dumps = threading.Thread(target = generate_mst_config, args = [card ,cards_port_dict[card], sleep_period, mstregdump_out, mst_status_output])
        t_dumps.start()
        threads_config.append(t_dumps)
    for thread in threads_config:
        thread.join()
    for card in all_devices:
        generate_card_logs(card, sleep_period, mstregdump_out, mst_status_output)

    if mstregdump_out == []:
        mstregdump_out.append("There was no mst query output from this devices\n")
        return 2, mstregdump_out

    return 0, mstregdump_out

#**********************************************************
#        mlnx_snap_handler

def mlnx_snap_handler():
    if (os.path.exists("/etc/mlnx_snap") == False):
        return 1,"/etc/mlnx_snap does not exist"
    mlnx_snap_files = os.listdir("/etc/mlnx_snap")
    if not mlnx_snap_files:
        return 1,"No files in /etc/mlnx_snap"
    no_log_status_output("mkdir " + path + file_name + "/mlnx_snap")
    res = []
    for file in mlnx_snap_files:
        st, content = get_status_output("cp /etc/mlnx_snap/" + file + " " + path + file_name + "/mlnx_snap/" + file)
        res.append("<td><a href=mlnx_snap/" + file + "> /etc/mlnx_snap/" + file + "</a></td>")
    return 0,res

#**********************************************************
#        rshim_log_handler

def rshim_log_handler():
    res = ""
    st = 0
    if is_run_from_bluefield_host:
        st,res = get_status_output('bfrshlog')
    else :
        if os.path.exists('/dev/rshim0/misc'):
            st1,res1 = get_status_output('echo "DISPLAY_LEVEL 2 \n" > /dev/rshim0/misc') 
            if(st1 == 0):
                st,res = get_status_output('cat /dev/rshim0/misc') 
        else:
            res = "/dev/rshim0/misc file does not exist"
    return st,res

#**********************************************************
#        show_irq_affinity_all Handlers

def show_irq_affinity_all_handler():
    if (os.path.exists("/sys/class/net") == False):
        return 1,"No Net Devices"
    net_devices = ""
    st, net_devices = get_status_output("ls /sys/class/net")
    if (st != 0):
        return 1,"Could not run: " + '"' + "ls /sys/class/net" + '"'
    no_log_status_output("mkdir " + path + file_name + "/show_irq_affinity_all")
    net_devices += " mlx4 mlx5"
    net_devices = net_devices.split()
    if(interfaces_flag):
        net_devices = all_net_devices
    res = []
    for interface in net_devices:
        if (interface == "lo" or interface == "bonding_masters"):
            continue
        try:
            with open(path + file_name + "/show_irq_affinity_all/" + interface, "w+") as outF:
                outF.write("show_irq_affinity.sh " + interface + "\n")
                st, show_irq_affinity = get_status_output("show_irq_affinity.sh " + interface + " 2>/dev/null")

                if (st == 0 and show_irq_affinity != ""):
                    outF.write(show_irq_affinity)
                else:
                    outF.write("Interface " + interface + " does not exist")
            res.append("<td><a href=show_irq_affinity_all/" + interface + "> show_irq_affinity.sh " + interface + "</a></td>")
        except:
            outF.write("Could not open the file: " + file_name + "/show_irq_affinity_all/" + interface)
    return 0,res

#**********************************************************
#            /etc/NetworkManager/system-connections/ handler

def network_manager_system_connections_handler():
    status,out = no_log_status_output("systemctl status NetworkManager")
    if (status!=0 and not "active (running)" in out):
        return 1,"NetworkManager is not running"
    if (os.path.exists("/etc/NetworkManager/system-connections/") == False):
        return 1,"No sytem connections"
    system_connections = os.listdir("/etc/NetworkManager/system-connections/")
    if not system_connections:
        return 1,"No sytem connections"
    no_log_status_output("mkdir " + path + file_name + "/networkManager_system_connections")
    res = []
    for connection in system_connections:
        try:
            with open(path + file_name + "/networkManager_system_connections/" + connection, "w+") as outF:
                st, content = get_status_output("cat /etc/NetworkManager/system-connections/" + connection )
                if(st == 0 and content != ""):
                    outF.write(content)
                else:
                    outF.write("system connection " + connection + " does not exist")
            res.append("<td><a href=networkManager_system_connections/" + connection + "> /etc/NetworkManager/system-connections/" + connection + "</a></td>")
        except:
            outF.write("Could not open the file: " + file_name + "/networkManager_system_connections/" + connection)

    return 0,res



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

#**********************************************************
#            yy IB Modules Parameters Handler

def yy_ib_modules_parameters_handler():
    main_path = "/sys/module/"
    yy_ib_modules = ""
    if os.path.isdir("/sys/class/infiniband"):
        for folder in os.listdir(main_path):
            if(folder.startswith("ib_")):
                folder_path = ""
                folder_path += main_path
                folder_path += folder
                folder_path += "/parameters"
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        str_result = ""
                        file_path = os.path.join(folder_path, file)
                        str_result += file_path
                        str_result += " = "
                        f = open(file_path, 'r')
                        str_result += f.read()
                        yy_ib_modules += str_result.strip() + "\n"
                        f.close()
        return 0, yy_ib_modules
    else: return 1, "Could not run the command, /sys/class/infiniband does not exist."

#*****************************************************************************************************
#                               add_txt_command_output
# A function to add command output as txt file
def add_txt_command_output(command, output):
    forbidden_chars = re.compile('([\/:*?"<||-])')
    clean_file_name = forbidden_chars.sub(r'', command).replace("\\", "") # clean the file name
    clean_file_name = clean_file_name.replace(" ", "_")
    clean_file_name = clean_file_name.replace("__", "_")
    full_path = path + file_name + "/commands_txt_output/" + clean_file_name + ".txt"
    command_file = open(full_path, 'w')
    try:
        command_file.write("Invoked Command: " + command + "\n")
        command_file.write(output)
    except UnicodeEncodeError:
        command_file.write("Invoked Command: " + command.encode('utf-8').decode(sys.stdout.encoding) + "\n")
        command_file.write(output.encode('utf-8'))
    command_file.close()

# *******************************************************************
#            Function to (safely)get the content of a file
def get_file_content(file_dir):
    st, content = get_status_output("cat " + file_dir)
    if st != 0:
        return "N/A"
    else:
        return content

# *******************************************************************
#            Function to clean string prior to using it as a file name
def filter_file_name(file_name):
    forbidden_chars = re.compile('([\/:*?"<||-])')
    filtered_file_name = forbidden_chars.sub(r'', file_name).replace("\\", "")
    return filtered_file_name

# *******************************************************************
#            /sys/class/infiniband handler
def sys_class_infiniband_handler():
    sys_img_dict = {}

    if not os.path.isdir('/sys/class/infiniband'):
        return 1, 'Could not run the command, /sys/class/infiniband does not exist.'

    st = st_infiniband_devices
    ib_devices = infiniband_devices
    ib_devices_lines = ib_devices.splitlines()
    if interfaces_flag:
        ib_devices_lines = specific_rdma_mlnx_devices
    for device in ib_devices_lines:
        sys_img_guid = get_file_content("/sys/class/infiniband/"+ device +"/sys_image_guid")

        if not (sys_img_guid in sys_img_dict.keys()):
            parent_device = device
            board_id = get_file_content('/sys/class/infiniband/'+ device +'/board_id')
            fw_ver = get_file_content('/sys/class/infiniband/'+ device +'/fw_ver')
            hca_type = get_file_content('/sys/class/infiniband/'+ device +'/hca_type')
            hw_rev = get_file_content('/sys/class/infiniband/'+ device +'/hw_rev')
            node_type = get_file_content('/sys/class/infiniband/'+ device +'/node_type')
            node_desc = get_file_content('/sys/class/infiniband/'+ device +'/node_desc')
            sys_img_dict[sys_img_guid] = mlnx_device(parent_device, sys_img_guid, board_id, fw_ver, hca_type, hw_rev, node_type) # Initialize mlnx_device object

        node_guid = get_file_content('/sys/class/infiniband/'+ device + '/node_guid')
        node_desc = get_file_content('/sys/class/infiniband/'+ device + '/node_desc')
        node_desc_output = 'Node Description: /sys/class/infiniband/'+ device +'/node_desc = ' + node_desc + '\n'
        sys_img_dict[sys_img_guid].add_node_desc(node_desc_output, node_guid)
    res = ""
    for key in sys_img_dict:
        mlnx_device_info = sys_img_dict[key].get_mlnx_device_info()
        res += mlnx_device_info
        res += '\n\n' + '----------------------------------------------------------------\n'
    return 0, res

# *******************************************************************
#            /sys/class/net handler
def sys_class_net_handler():
    res = ""
    options = ["cnp_802p_prio", "0", "1", "2", "3", "4", "5", "6", "7"]
    ib_path_options = ["/mode", "/pkey", "/queues/rx-0/rps_cpus"]

    if os.path.exists("/sys/class/net/"):
        for indir in all_net_devices:
            if os.path.isfile("/sys/class/net/" + indir) == False:
                if indir.startswith("ib"):
                    for option in ib_path_options:
                        current_path = "/sys/class/net/" + indir + option
                        if os.path.isfile(current_path):
                            res += current_path
                            res += " = " + get_file_content(current_path) + "\n"
                for option in options:
                    current_path = "/sys/class/net/" + indir + "/ecn/roce_np/" + option
                    if os.path.isfile(current_path):
                        res += current_path
                        res += " = " + get_file_content(current_path) + "\n"
    else:
        return 1, 'Could not run the command, /sys/class/net does not exist.'
    if res == "":
        return 1, "/sys/class/net No interfaces found"
    else:
        return 0, res
# *******************************************************************
#            Ecn configuration
def ecn_configuration_handler():
    res = []
    if os.path.exists("/sys/class/net"):
        for indir in all_net_devices:
            if( os.path.exists("/sys/class/net/" + indir + "/ecn")):
                # fillter indir cause this is the part in the path of the ECN output
                # the file_name is the "sysinfo-snapshot-v" + version + "-"
                filtered_indir =  filter_file_name(indir)
                if(not os.path.exists(path + file_name + "/ecn/")):
                    no_log_status_output("mkdir " + path + file_name + "/ecn" )
                if(not os.path.exists(path + file_name + "/ecn/config")):
                    no_log_status_output("mkdir " + path + file_name + "/ecn/config" )
                for root, dirs, files in os.walk("/sys/class/net/" + indir + "/ecn"):
                    try:
                        with open(path + file_name + "/ecn/config/" + filtered_indir, "a+") as outF:
                            for file in files:
                                outF.write( os.path.join(root,file) + "= ")
                                outF.write(get_file_content( os.path.join(root,file))+ "\n\n")
                    except:
                        outF.write("Could not open the file: " + file_name + "/ecn/config/" + filtered_indir)
                res.append("<td><a href='ecn/config/" + filtered_indir + "'> " + filtered_indir + " </a></td>")
    else:
        return 1, "/sys/class/net does not exist"
    if res:
        return 0, res
    else:
        return 1, "sys/class/net//ecn No interfaces found"

# *******************************************************************
#            Congestion control parameters
def congestion_control_parameters_handler():
    res = []
    if os.path.exists("/sys/kernel/debug/mlx5"):
        pci_dev = os.listdir("/sys/kernel/debug/mlx5/")
        if interfaces_flag:
            specific_pci_kernal = []
            for device in specific_pci_devices:
                if device in pci_dev:
                    specific_pci_kernal.append(device)
            pci_dev = specific_pci_kernal
        for indir in pci_dev:
            if( os.path.exists("/sys/kernel/debug/mlx5/" + indir + "/cc_params")):
                if(not os.path.exists(path + file_name + "/ecn/")):
                    no_log_status_output("mkdir " + path + file_name + "/ecn" )
                if(not os.path.exists(path + file_name + "/ecn/debug")):
                    no_log_status_output("mkdir " + path + file_name + "/ecn/debug" )
                for root, dirs, files in os.walk("/sys/kernel/debug/mlx5/" + indir + "/cc_params"):
                    filename = indir.replace(":","_")
                    try:
                        with open(path + file_name + "/ecn/debug/" + filename, "a+") as outF:
                            for file in files:
                                outF.write( os.path.join(root,file) + "= ")
                                outF.write(get_file_content( os.path.join(root,file))+ "\n\n")
                    except:
                        outF.write("Could not open the file: " + file_name + "/ecn/debug/" + filename)

                res.append("<td><a href='ecn/debug/" + filename + "'> " + indir + " </a></td>")
    else:
        return 1, "/sys/kernel/debug/mlx5 does not exist"
    if res:
        return 0, res
    else:
        return 1, "/sys/kernel/debug/mlx5 No pci found"

# *******************************************************************
#            nvsm dump health handler
def nvsm_dump_health_handler():
    res = ""
    res +=  "nvsm dump health \n\n"
    # the result of the command is a tar archive maybe have to use tar commad annd append the archive contant as href
    st,result = get_status_output("nvsm dump health -tfp " + path + file_name, "6m")
    if st != 0:
        if st == CANCELED_STATUS:
            return 1, result
        res += "Could not run the command - nvsm dump health\n\n" + result
    else:
        res += "Produced a health report as .tar archive in the given path " + path
    res += "---------------------------------------------------------\n\n"
    return st, res

# *******************************************************************
#            pci_bus handler

def pci_bus_handler():
    res = ""
    st,result = get_status_output("lspci -Dnnd ::0302")
    if st == 0  and result :
        lines = result.splitlines()
        res = "Nvidia pci buses \n"
        for line in lines:
            device = line.split()[0]
            path = os.readlink("/sys/bus/pci/devices/" + device)
            res += path + "\n"
        res += " RP   |  UP      iDP     iUP     DP   |  UP      iDP     iUP     DP   |  UP      DP   |  EP \n"
        res += "  CPU  |           CDFP Switch         |          Switch Board         | GPU Baseboard |  GPU \n"
    st,result = get_status_output("lspci -Dnnd 15b3:")
    if st == 0  and result :
        lines = result.splitlines()
        res += "Mellanox pci buses \n"
        for line in lines:
            device = line.split()[0]
            path = os.readlink("/sys/bus/pci/devices/" + device)
            res += path + "\n"
        res += "  RP   |  UP      iDP     iUP     DP   |  UP      iDP     iUP     DP   |  EP \n"
        res += "  CPU  |           CDFP Switch         |          Switch Board         |  NIC \n"
    return 0,res

# *******************************************************************
#            mlxreg <mst_device> handler
def mlxreg_handler():
    res = ""
    if mst_devices_exist:
        mst_devices = os.listdir("/dev/mst")
        if interfaces_flag:
            mst_devices = specific_mst_devices
        for device in mst_devices:
            if not "cable" in device:
                res +=  "mlxreg -d /dev/mst/" + device +" --reg_name ROCE_ACCL --get \n\n"
                st,result = get_status_output("mlxreg -d /dev/mst/" + device +" --reg_name ROCE_ACCL --get")
                if st == 0:
                    res += result + "\n\n"
                else:
                    if st == CANCELED_STATUS:
                        return 1, result
                    res += "Could not run the command,mlxreg -d /dev/mst/" + device +" --reg_name ROCE_ACCL --get\n\n"
                res += "---------------------------------------------------------\n\n"
        if not res:
            return 1 , "No devices found"
        return 0, res
    else:
        return 1, "No MST devices"


#**********************************************************
#             SE Linux Stats / Config Handler

def  se_linux_status_handler():
    st, se_linux_status = get_status_output("getenforce")
    if (st != 0):
        if st == CANCELED_STATUS:
            return 1, se_linux_status
        return 1, "Could not run: 'getenforce' command - SELinux is not installed in the system"
    else:
        return 0, "SELinux configuration: " + se_linux_status

#**********************************************************
#             virsh list --all Handler

def virsh_list_all_handler():
    st, virsh_list_all = get_status_output("virsh list --all")
    if st != 0:
        if st == CANCELED_STATUS:
            return 1, virsh_list_all
        return 1 , "Could not run 'virsh' command"
    if 'error' in virsh_list_all:
        return 2, virsh_list_all
    return 0, virsh_list_all

#**********************************************************
#             virsh vcpupin <kvm> Handler (On all running KVMs)

def virsh_vcpupin_handler():
    kvms_list = []
    output = ""
    index = 5

    st, virsh_list_all = get_status_output("virsh list --all")
    if st != 0:
        if st == CANCELED_STATUS:
             return 1,virsh_list_all
        return 1, "Could not run 'virsh' command"
    if not 'running' in virsh_list_all:
        return 2, "Could not run 'virsh vcpupin' command - There are no running KVMs"

    st, virsh_running = get_status_output("virsh list --state-running")

    if st != 0:
        return 3, "Could not run virsh list --state-running"

    kvms_list = re.findall(r' \d\s+(.*?)\s+running', virsh_running)

    for kvm in kvms_list:
        st, res = get_status_output("virsh vcpupin " + kvm)
        output += "virsh vcpupin " + kvm
        output += "\n"
        output += res
        output += "\n\n"
    return 0, output

#**********************************************************
#             roce_counters_handler

def roce_counters_handler():
    final_output = ""
    roce_hw_counters = ""
    roce_counters = ""

    st = st_infiniband_devices
    ib_devices = infiniband_devices
   
    if st != 0:
        return 1, "Couldn't get RoCE Counters - /sys/class/infiniband does not exist."
    ib_devices = ib_devices.splitlines()
    if(interfaces_flag):
        ib_devices = specific_rdma_mlnx_devices
    for ib_device in ib_devices:
        st, ib_device_hw_counter_files = get_status_output("ls /sys/class/infiniband/"+ ib_device +"/hw_counters")
        if st == 0:
            ib_device_hw_counter_files = ib_device_hw_counter_files.splitlines()
            for ib_device_hw_counter_file in ib_device_hw_counter_files:
                file_content = get_file_content("/sys/class/infiniband/"+ ib_device  +"/hw_counters/"+ ib_device_hw_counter_file +"")
                roce_hw_counters += "/sys/class/infiniband/"+ ib_device +"/hw_counters/"+ ib_device_hw_counter_file +"" + ': ' + file_content + '\n'
        st, ports = get_status_output("ls /sys/class/infiniband/"+ ib_device +"/ports")
        if st != 0:
            return 1, "Couldn't get RoCE Counters - /sys/class/infiniband/"+ ib_device +"/ports does not exist."
        ports = ports.splitlines()
        for port in ports:
            st, hw_counter_files = get_status_output("ls /sys/class/infiniband/"+ ib_device +"/ports/"+ port +"/hw_counters")
            if st != 0:
                roce_hw_counters += "RoCE HW Counters for "+ ib_device +" port: "+ port + " do not exist.\n"
            else:
                hw_counter_files = hw_counter_files.splitlines()
                for hw_counter_file in hw_counter_files:
                    file_content = get_file_content("/sys/class/infiniband/"+ ib_device +"/ports/"+ port +"/hw_counters/"+ hw_counter_file +"")
                    roce_hw_counters += "/sys/class/infiniband/"+ ib_device +"/ports/"+ port +"/hw_counters/"+ hw_counter_file +"" + ': ' + file_content + '\n'
            st, counters_files = get_status_output("ls /sys/class/infiniband/"+ ib_device +"/ports/"+ port +"/counters")
            if st != 0:
                roce_counters += "RoCE Counters for "+ ib_device +" port: "+ port + " do not exist.\n"
            counters_files = counters_files.splitlines()
            for counters_file in counters_files:
                file_content = get_file_content("/sys/class/infiniband/"+ ib_device +"/ports/"+ port +"/counters/"+ counters_file +"")
                roce_counters += "/sys/class/infiniband/"+ ib_device +"/ports/"+ port +"/counters/"+ counters_file +"" + ': ' + file_content + '\n'
    final_output += "HW Counters: \n\n" + roce_hw_counters + "\n\n\nCounters: \n\n" + roce_counters
    return 0, final_output

#----------------------------------------------------------
#        Server Commands Dictionary Handler

col_count=1

iscsiadm_st, iscsiadm_res = no_log_status_output("iscsiadm --version")

def add_command_if_exists(command):
    global with_inband_flag
    command_is_string = True

    if ( (no_fw_flag == True) and (command in fw_collection) ):
        return
    if ( (pcie_flag == False) and (command in pcie_collection) ):
        return
    if ( (ufm_flag == False) and (command in ufm_collection) ):
        return
    if ( (asap_flag == False) and (command in asap_collection) ):
        return
    if ( (asap_tc_flag == False) and (command in asap_tc_collection) ):
        return
    if ( (rdma_debug_flag == False) and (command in rdma_debug_collection) ):
        return
    if( (gpu_flag == False) and (command in gpu_command_collection) ):
        return
    if ( (fsdump_flag == False) and (command in fsdump_collection) ):
        return
    if ( (no_ib_flag == True) and (command in ib_collection) ):
        return
    print_err_flag = 1
    #status = 0
    # invoke command reguarly if exists or redirect to the corresponding function
    if (command == "date"):
        result = date_cmd
        status = 0
        print_err_flag = 0
    elif (command == "ufm_logs"):
        ufm_snapshot_path = "/opt/ufm/scripts/vsysinfo"
        if(os.path.isfile(ufm_snapshot_path)):
            status, result = get_status_output(ufm_snapshot_path + " -S all -e A -O " + path + file_name + "/ufm_logs")
            if (status == 0):
                print_err_flag = 0
        else:
            status = 1
            result = "--ufm flag provided but /opt/ufm/scripts/vsysinfo path not exist"
            running_warnings.append(result)
            print_err_flag = 1
    elif (command == "se_linux_status"):
        status, result = se_linux_status_handler()
        if(status == 0):
            print_err_flag  = 0
        else:
            status = 1
            print_err_flag = 1
    elif (command == "virsh list --all"):
        status, result = virsh_list_all_handler()
        if status == 0:
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
    elif (command == "virsh vcpupin"):
        status, result = virsh_vcpupin_handler()
        if status == 0:
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
    elif (command == "roce counters"):
        status, result = roce_counters_handler()
        if status == 0:
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
    elif (command == "time"):
        result = date_file
        status = 0
        print_err_flag = 0
    elif (command == "service --status-all"):
        if blueos_flag:
            return
        status, result = get_status_output("service --status-all")
        if (status == 0 or status == 124):
            print_err_flag = 0
    elif (command == "python_used_version"):
        result = platform.python_version()
        status = 0
        print_err_flag = 0
    elif (command == "cma_roce_mode"):
        result = cma_roce_handler("mode")
        status = 0
        print_err_flag = 0
    elif (command == "mlnx_qos_handler"):
        result = mlnx_qos_handler()
        status = 0
        print_err_flag = 0
    elif ("lldptool" in command):
        status,result = lldptool_handler(command)
        print_err_flag = 0
        if(status != 0):
            print_err_flag = 1
    elif (command == "cma_roce_tos"):
        result = cma_roce_handler("tos")
        status = 0
        print_err_flag = 0
    elif (command == "mlxdump"):
        result = mlxdump_handler()
        if result == "Links":
            result = add_mlxdump_links()
            command_is_string = False
        status = 0
        print_err_flag = 0
    elif (command == "asap_parameters"):
        status , result = asap_handler()
        if(status == 0):
            command_is_string = False
            print_err_flag = 0
        else:
            print_err_flag = 0
            if(result != 0 ):
                print_err_flag = 1
    elif (command == "asap_tc_information"):
        status, result = asap_tc_handler()
        if (status == 0) :
            command_is_string = False
            print_err_flag = 0
        else:
            print_err_flag = 0
            if(result != 0 ):
                print_err_flag = 1
    elif (command == "rdma_tool"):
        status, result = rdma_tool_handler()
        if (status == 0) :
            command_is_string = False
            print_err_flag = 0
        else:
            print_err_flag = 0
            if(result != 0 ):
                print_err_flag = 1
    elif (command == "devlink_handler"):
        result = devlink_handler()
        status = 0
        print_err_flag = 0
        command_is_string = False
    elif (command == "show_pretty_gids"):
        result = show_pretty_gids_handler()
        status = 0
        print_err_flag = 0
    elif (command == "ethtool_version"):
        st, result = ethtool_version_handler()
        status = 0
        print_err_flag = 0
    elif (command == "ethtool_all_interfaces"):
        result = ethtool_all_interfaces_handler()
        status = 0
        print_err_flag = 0
        command_is_string = False
    elif (command == "modinfo"):
        result = modinfo_handler()
        status = 0
        print_err_flag = 0
    elif (command == "ibdev2pcidev"):
        result = ibdev2pcidev_handler()
        status = 0
        print_err_flag = 0
    elif (command == "fwtrace"):
        result = fwtrace_handler()
        status = 0
        print_err_flag = 0
    elif (command == "mlxcables"):
        if not no_cables_flag:
            st, result = mlxcables_standard_handler()
            if st == 0 and with_inband_flag:
                command_is_string = False
            if st != 0:
                status = 1
                print_err_flag = 1
            else:
                status = 0
                print_err_flag = 0
        else:
            result = "no_cables_flag used , mlxcables commands are not executed"
            status = 0
            print_err_flag = 0
    elif (command == "mlxmcg -d"):
        result = ""
        if not no_cables_flag:
            result = mstcommand_d_handler('mlxmcg')
        else:
            result = "no_cables_flag used , mlxmcg commands are not executed"
        status = 0
        print_err_flag = 0
    elif (command ==  "mlxlink / mstlink"):
        result = ""
        if not no_cables_flag:
            result = mstcommand_d_handler('mlxlink / mstlink')
            # add_output_to_pcie_debug_dict("mlxlink_mstlink", result)
        else:
            result = "no_cables_flag used , mlxlink / mstlink commands are not executed"
        status = 0
        print_err_flag = 0
    elif (command == "mget_temp_query"):
        result = ""
        if not no_cables_flag:
            result = mstcommand_d_handler('mget_temp')
        else:
            result = "no_cables_flag used , mget_temp commands are not executed"
        status = 0
        print_err_flag = 0
    elif ("mst_commands_query_output" in command):
        status, result = mst_func_handler()
        command_is_string = False
        status = 0
        print_err_flag = 0
    elif(command == "ulimit -a"):
        status, result = getstatusoutput("ulimit -a")
        if status != 0:
            print_err_flag = 1
    elif (command == "show_irq_affinity_all"):
        status, result = show_irq_affinity_all_handler()
        if(status == 0):
            print_err_flag = 0
            command_is_string = False
        else:
            print_err_flag = 1
    elif ( command == "/etc/mlnx_snap"):
        status, result = mlnx_snap_handler()
        if(status == 0):
            print_err_flag = 0
            command_is_string = False
        else:
            print_err_flag = 1
    elif (command == 'rshim_log'):
        status, result = rshim_log_handler()
        if(status != 0):
            print_err_flag = 1
    elif (command == "networkManager_system_connections"):
        status, result = network_manager_system_connections_handler()
        if(status == 0):
            print_err_flag = 0
            command_is_string = False
        else:
            print_err_flag = 1
    elif "ecn_configuration" == command:
        status, result = ecn_configuration_handler()
        if(status == 0):
            print_err_flag = 0
            command_is_string = False
        else:
            print_err_flag = 1
    elif "congestion_control_parameters" == command:
        status, result = congestion_control_parameters_handler()
        if(status == 0):
            print_err_flag = 0
            command_is_string = False
        else:
            print_err_flag = 1
    elif nvsm_dump_flag and "nvsm dump health" == command:
        status, result = nvsm_dump_health_handler()
        if(status == 0):
            print_err_flag = 0
            command_is_string = False
        else:
            print_err_flag = 1
    elif(command == "NetworkManager --print-config"):
        status,out = no_log_status_output("systemctl status NetworkManager")
        if (status!=0 and not "active (running)" in out):
            result = "NetworkManager is not running"
            print_err_flag = 1
        else:
            status, result = get_status_output(command)
            if status != 0:
                print_err_flag = 1
    elif (command == "yy_MLX_modules_parameters"):
        st, result = get_status_output("awk '{ print FILENAME " + '"' + "=" + '"' + " $0  }' /sys/module/mlx*/parameters/*")
        if (st == 0):
            status = 0
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
            if not result:
                result = "Could not run: " + '"' + " awk '{ print FILENAME " + '"' + "=" + '"' + " $0  }' /sys/module/mlx*/parameters/* " + '"'
    elif(command == "USER"):
        st, result = get_status_output("logname")
        if (st == 0):
            status = 0
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
            result = "could not run : logname"
    elif (command == "bandwidthTest"):
        st, result = get_status_output("/usr/local/cuda/extras/demo_suite/bandwidthTest --memory=pinned --mode=range --start=65536 --end=65011712 --increment=4194304 --device=all --dtoh", "/usr/local/cuda/extras/demo_suite/bandwidthTest --memory=pinned --mode=range --start=65536 --end=65011712 --increment=4194304 --device=all --htod")
        if (st == 0):
            status = 0
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
            result = "could not run : /usr/local/cuda/extras/demo_suite/bandwidthTest"
    elif (command == "cuda_deviceQuery"):
        st, result = get_status_output("/usr/local/cuda/extras/demo_suite/deviceQuery")
        if (st == 0):
            status = 0
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
            result = "could not run :  /usr/local/cuda/extras/demo_suite/deviceQuery"   
            
    elif (command == "mlnx_ethtool_version"):
        st, result = get_status_output("/opt/mellanox/ethtool/sbin/ethtool --version")
        if (st == 0):
            status = 0
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
            result = "could not run : /opt/mellanox/ethtool/sbin/ethtool --version"  
    elif (command == "sysclass_IB_modules_parameters"):
        status, result = yy_ib_modules_parameters_handler()
        if(status == 0):
            status = 0
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
    elif (command == "sys_class_infiniband_ib_parameters"):
        status, result = sys_class_infiniband_handler()
        if (status == 0):
            status = 0
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
    elif (command == "sys_class_net_ecn_ib"):
        status, result = sys_class_net_handler()
        if (status == 0):
            status = 0
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
    elif "mlxreg -d" in command:
        status, result = mlxreg_handler()
        if (status == 0):
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
    elif (command == "proc_net_bonding_files"):
        status, result = zz_files_handler('/proc/net/bonding/')
        if (status == 0):
            status = 0
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
    elif (command == "Mellanox_Nvidia_pci_buses"):
        status, result = pci_bus_handler()
        if (status == 0):
            status = 0
            print_err_flag = 0
        else:
            status = 1
            print_err_flag = 1
    elif (command == "sys_class_net_files"):
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
            if not result:
                result = "Could not run: " + '"' + "ip link ls type team" + '"'
        team_interfaces = re.findall(r'.*?\:(.*)\: <.*',ip_link_output)
        if team_interfaces:
            for team in team_interfaces:
                run_command = ""
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
                    print_err_flag = 1
                    if not teamdctl_result:
                        teamdctl_result = "Could not run: " + '"' + run_command + '"'
                result += teamdctl_result + '\n\n'
        else:
            status = 1
            print_err_flag = 1
            result = "No team interfaces found"
    elif "mst status" in command:
        status, result = get_status_output(command)
        if status != 0:
            print_err_flag = 1
            if not result:
                result = "Could not run: " + '"' + command + '"'
        else:
            print_err_flag = 0
    elif ( command == "snap_rpc.py controller_list" or command == "snap_rpc.py emulation_functions_list" or command == "virtnet query --all"):
        status, result = get_status_output(command)
        print_err_flag = 0
        if (status != 0):
            print_err_flag = 1
    elif "lscpu" in command:
        # invoking regular command
        print_err_flag = 0
        # status, result = add_command_to_pcie_debug_dict(command)
        status, result = get_status_output(command)
        add_output_to_pcie_folder("lscpu", result)
    elif "uname" in command:
        status = 0
        result = ""
        if is_command_allowed("hostname") or generate_config_flag:
            status, result = get_status_output("uname -a")
        else:
            status, result = get_status_output("uname -s -o -p -i -v -r -m")
        print_err_flag = 0
        if (status != 0):
            print_err_flag = 1
    elif  command == "lspci -tv":
        # invoking regular command
        print_err_flag = 0
        status, result = get_status_output(command)
        add_output_to_pcie_folder("lspci_tv", result)
    else:
        # invoking regular command
        print_err_flag = 0
        status, result = get_status_output(command)
        if (status != 0 and not command.startswith("service") ):
            if not (iscsiadm_st == 0 and command.startswith("iscsiadm")):
                if not result:
                    result = "Could not run: " + '"' + command + '"'
                print_err_flag = 1

    # if iscsiadm --version command exists, add all isciadm commands to the available ones
    if (iscsiadm_st == 0 and command.startswith("iscsiadm")):
        status = 0
        print_err_flag = 0
    # add command to server commands dictionaty only if exists
    if ((status == 0) or (command.startswith("service"))):
        server_commands_dict[command] = result
        if command_is_string:
            available_commands_collection[is_command_string].append(command)
            if not "lspci" in command:
                add_txt_command_output(command, result)
        else:
            available_commands_collection[not is_command_string].append(command)
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
        return "Failed to run saquery ,No SM/SA found on port"

    st, saquery_g = get_status_output("saquery -g 2>/dev/null")
    if (st != 0):
        return "saquery -g command is not found"
    res = "MLIDs list: \n" + saquery_g + "\n\nMLIDs members for each multicast group:"

    st, MLIDS = get_status_output("saquery -g | grep -i Mlid | sed 's/\./ /g'|awk '{print $2}' | sort | uniq")
    if (st != 0):
        return "Could not run: " + '"' + "saquery -g | grep -i Mlid | sed 's/\./ /g'|awk '{print $2}' | sort | uniq" + '"'
    MLIDS = MLIDS.split()

    for MLID in MLIDS:
        st, saquery_mlid = get_status_output("saquery -m " + MLID + " --smkey 1 2>/dev/null")
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
            st, perfquery = get_status_output("perfquery --Ca " + card + " --Port " + port)
            res += perfquery + "\n"
            first = False
    return res

def ib_find_bad_ports_handler(card, port):
    if is_ib != 0:
        return "No ibnetdiscover"

    st, iblinkinfo_bad = get_status_output("iblinkinfo --Ca " + card + " --Port " + port + "| grep Could")
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

    st, iblinkinfo_disabled = get_status_output("iblinkinfo --Ca " + card + " --Port " + port + "| grep Disabled")
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
        return "Failed to run saquery ,No SM/SA found on port"

    MAX_GROUPS=64

    st, saquery = get_status_output("saquery -m --smkey 1 2>/dev/null")
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
            tmp_st, vendstat_N = get_status_output("vendstat -N " + lid)
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
    st, GUIDS = get_status_output("cat " + path + file_name + "/ibnetdiscover_p_" + suffix + " | grep -v -i sfb | grep -e ^SW | awk '{print $4}' | uniq")
    if (st != 0):
        return "Could not run: " + '"' + "cat " + path + file_name + "/ibnetdiscover_p_" + suffix + " | grep -v -i sfb | grep -e ^SW | awk '{print $4}' | uniq" + '"'
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

        st, desc = get_status_output("cat " + path + file_name + "/ibnetdiscover_p_" + suffix + " | grep -v -i sfb | grep -e ^SW | grep " + GUIDS[index] + "..x")

        if (st == 0):
            HCA_ports_count = 0
            switch_ports_count = 0
            desc = desc.split("'")[1]

            st, guid_ports = get_status_output("cat " + path + file_name + "/ibnetdiscover_p_" + suffix + " | grep -v -i sfb | grep -e ^SW | grep " + GUIDS[index] + "..x | awk '{print $8}'")
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
    st, MasterLID = get_status_output("/usr/sbin/sminfo -C " + card +" -P " + port + " | awk '{print $4}'")
    if (st != 0):
        return "Could not retrieve Master LID. Reason: Could not run " + '"' + "/usr/sbin/sminfo -C " + card +" -P " + port + " | awk '{print $4}'" + '"'
    st, all_sms = get_status_output("/usr/sbin/smpquery nodedesc " + MasterLID)
    if (st != 0):
        return "Could not retrieve all SM. Reason: Could not run " + '"' + "/usr/sbin/smpquery nodedesc " + MasterLID + '"'
    res = "IB fabric SM master is: (" + all_sms + ")\nAll SMs in the fabric: "

    st, SMS = get_status_output("saquery -s -C " + card +" -P " + port + " 2>/dev/null |grep base_lid |head -1| sed 's/\./ /g'|awk '{print $2}'")
    if (st != 0):
        return "Could not retrieve all SM. Reason: Could not run " + '"' + "saquery -s -C " + card +" -P " + port + " 2>/dev/null |grep base_lid |head -1| sed 's/\./ /g'|awk '{print $2}'" + '"'
    SMS = set(SMS.split())

    for SM in SMS:
        st, smquery_nodedesc = get_status_output("/usr/sbin/smpquery nodedesc " + SM)
        if (st != 0):
            smquery_nodedesc = "Could not run " + '"' + "/usr/sbin/smpquery nodedesc " + SM + '"'
        st, sminfo = get_status_output("/usr/sbin/sminfo -C " + card +" -P " + port + " " + SM)
        if (st != 0):
            sminfo = "Could not run " + '"' + "/usr/sbin/sminfo -C " + card +" -P " + port + " " + SM + '"'
        res += "\n\nSM: " + SM + "\n" + smquery_nodedesc + "\n" + sminfo

    return res

def sm_info_handler(card, port):
    command = "sminfo -C " + card +" -P " + port
    status, result = get_status_output(command)
    if (status != 0):
        result = "Couldn't find command: " + command
    return result

def sm_status_handler(card, port):
    SmActivity_1=0
    NoSM=2
    res = ""

    for lo in range(0,4):
        get_status_output("sleep 3")
        st, SmActivity = get_status_output("sminfo -C " + card +" -P " + port + " |awk '{ print $10 }'")
        if (st != 0):
            SmActivity = "<N/A>"
        st, c_time = get_status_output("date +%T")
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
        st, res = get_status_output("echo OpenSM installed packages: ; rpm -qa | grep opensm")
        if (st != 0):
            res = "Couldn't find command: echo OpenSM installed packages: ; rpm -qa | grep opensm"
    else:
        st, res = get_status_output("echo OpenSM installed packages: ; dpkg -l | grep opensm")
        if (st != 0):
            res = "Couldn't find command: echo OpenSM installed packages: ; dpkg -l | grep opensm"
    return res

def ibdiagnet_handler(card, port, ibdiagnet_suffix):
    global ibdiagnet_res
    global ibdiagnet_error

    ibdiagnet_command = "ibdiagnet -r --sharp_opt dsc -i "
    if ibdiagnet_ext_flag:
        ibdiagnet_command = "ibdiagnet --extended_speeds all -P all --pm_per_lane --skip dup_guids,dup_node_desc,lids,sm,pkey,aguid,virt --get_phy_info --pc --pm_pause_time 10 -i "

    if (ibdiagnet_is_invoked == False):
        if (os.path.exists(path + file_name + "/" + ibdiagnet_suffix +"/ibdiagnet") == False):
            os.mkdir(path + file_name + "/" + ibdiagnet_suffix + "/ibdiagnet")
        st, ibdiagnet_res = get_status_output(ibdiagnet_command + card +" -p "+ port +" -o " + path + file_name + "/" + ibdiagnet_suffix + "/ibdiagnet", "30")
        if st != 0:
            ibdiagnet_error = True

def clean_ibnodes(ibnodes, start_string):
    res = ""
    ibnodes = ibnodes.split("\n")
    for ibnode in ibnodes:
        if (ibnode.lower().startswith(start_string) == True):
            res += ibnode + "\n"
    return res

def get_dmidecode_info():
    field_name = "dmidecode"
    status, command_output = get_status_output(field_name, "10")
    if (status == 0):
        system_information = re.search("^System((.*\n){4})", command_output, re.MULTILINE)
        if(system_information):
            system_information = system_information.group(0).split("\n",1)[1]
            # add_output_to_pcie_debug_dict("system_information", system_information)
            add_output_to_pcie_folder("system_information", system_information)
        add_ext_file_handler(field_name, field_name, command_output)
    return status

def update_saquery():
    global st_saquery
    st_saquery, SAQUERY = get_status_output("saquery 2>/dev/null")

def add_fabric_command_if_exists(command):
    global fabric_commands_dict
    global available_fabric_commands_collection

    if (command == "Multicast_Information"):
        result = multicast_information_handler()
    elif (command == "ib_mc_info_show"):
        result = ib_mc_info_show_handler()
    elif (command == "perfquery_cards_ports"):
        result = perfquery_cards_ports_handler()
    elif (command == "sm_version"):
        result = sm_version_handler()
    else:
        # invoking regular command
        status, result = get_status_output(command)
        if (status != 0):
            result = "Couldn't find command: " + command
        # elif (command == "ibstat"):
        #         add_output_to_pcie_debug_dict("ibstat", result)

    fabric_commands_dict[command] = result
    available_fabric_commands_collection.append(command)

def add_fabric_multi_sub_command_if_exists(command):
    global ibdiagnet_is_invoked
    global fabric_commands_dict
    global available_fabric_commands_collection

    result = ""
    index = 0

    if not active_subnets:
        result = "Error running the command - there are no active subnets"

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
                status, command_result = get_status_output(command + " -C " + card +" -P " + port)
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
    status, result = get_status_output("cat " + file_full_path)

    # add internal file to files dictionary only if exists
    if (status == 0 and result):
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
# out_file_name - the name of the file that will be linked to
# command_output - is the content of the out_file_name

def add_ext_file_handler(field_name, out_file_name, command_output):
    external_command = ["pcie_debug_dict","sysctl -a","ps -eLo","chkconfig","ucx_info -f","ucx_info -c","numa_node","netstat -anp","lstopo-no-graphics","lstopo-no-graphics -v -c","mlnx_tune -r -i ","zoneinfo","other_system_files","interrupts"]
    forbidden_chars = re.compile('([\/:*?"<||-])')
    out_file_name = forbidden_chars.sub(r'', out_file_name).replace("\\", "") # clean the file name
    out_file_name = out_file_name.replace(" ","_")
    out_file_name = out_file_name.replace("'","")
    full_Path =  path + file_name + "/" + out_file_name
    file_path = out_file_name
    if "lspci" in field_name:
        full_Path =  path + file_name + "/pcie_files/" + out_file_name
        file_path = "pcie_files/" + out_file_name
    elif field_name in external_command:
        full_Path =  path + file_name + "/commands_txt_output/" + out_file_name
        file_path = "commands_txt_output/" + out_file_name
    if ( out_file_name != "pkglist" and (not "erformance" in out_file_name) and (not "sr_iov" in out_file_name)):
        f = open(full_Path, 'a+')
        if sys.version_info[0] == 2:
            try:
                f.write(command_output)
            except UnicodeEncodeError:
                f.write(command_output.encode('utf-8'))
        elif sys.version_info[0] == 3:
            f.write(command_output.encode('ascii', 'ignore').decode("utf-8"))
        f.close()

    if not ("mlnx_tune" in field_name) and not ("pcie_debug" in out_file_name or "pcie_debug_dict" in out_file_name):
        external_files_dict[field_name] = "<td><a href=" + file_path + ">" + field_name + "</a></td>"
        available_external_files_collection.append([field_name, file_path])

def add_external_file_if_exists(field_name, curr_path):
    command_output = ""
    err_flag = 0
    err_command = "No '" + field_name + "' External File\nReason: Couldn't find command/file: "
    if (field_name.startswith("/var/log")):
        if is_command_allowed("file: " + curr_path):
            status, command_output = get_status_output("cat " + curr_path)
            if (status == 0 and command_output):
                if field_name.startswith('/'):
                    field_name = field_name[1:]
                field_name = field_name.replace('/','_')
                filtered_field_name = filter_file_name(field_name)
                add_ext_file_handler(field_name, filtered_field_name, command_output)
            else:
                err_flag = 1
                err_command += field_name
    elif (field_name == "kernel config"):
        if is_command_allowed("file :" + curr_path):
            status, command_output = get_status_output("cat " + curr_path)
            if (status == 0):
                st , uname = get_status_output("uname -r")
                if (st == 0):
                    add_ext_file_handler(field_name, "config-" + uname.strip(), command_output)
                else:
                    err_flag = 1
                    err_command += "uname -r"
            else:
                err_flag = 1
                err_command += "cat " + curr_path
    elif (field_name == "trace"):
        if is_command_allowed("file :" + curr_path):
            file_size_bytes = os.path.getsize(curr_path)
            file_size_kilobytes = file_size_bytes / 1024
            # if trace file less then 150KB or trace file flag enabled  
            if(file_size_kilobytes <= 150 or trace_flag):
                status, command_output = get_status_output("cat " + curr_path)
                if (status == 0):
                        add_ext_file_handler("analyze_fw_trace_file", field_name, command_output)
                else:
                    err_flag = 1
                    err_command += "cat " + curr_path
    elif (field_name == "mlxcables --DDM/--dump"):
        if not no_cables_flag:
            if is_command_allowed("mlxcables --DDM/--dump"):
                st, command_output = mlxcables_options_handler()
                if st != 0:
                    err_flag = 1
                    err_command += "mlxcables --DDM/--dump"
                else:
                    external_files_dict[field_name] = "<td><a href=" + curr_path + ">" + field_name + "</a></td>"
                    available_external_files_collection.append([field_name, curr_path])
        else:
            err_flag = 1
            err_command += "no_cable_flag used,mlxcables --DDM/--dump command are not executed"
    elif (field_name == "config.gz"):
        if is_command_allowed("file : /proc/config.gz"):
           if(os.path.isfile('/proc/config.gz')):
                status, command_output = get_status_output("cp /proc/config.gz " + path + file_name)
                if (status != 0):
                    err_flag = 1
                    err_command += "cp /proc/config.gz" + path + file_name
    elif (field_name == "libvma.conf" or field_name == "zoneinfo" or field_name == "interrupts"):
        if is_command_allowed("file :" + curr_path):
            status, command_output = get_status_output("cat " + curr_path)
            if (status == 0):
                add_ext_file_handler(field_name, field_name, command_output)
            else:
                err_flag = 1
                err_command += "cat " + curr_path
    elif (field_name == "ps -eLo"):
        if is_command_allowed("ps -eLo"):
            status, command_output = get_status_output("ps -eLo lstart,%cpu,psr,nlwp,f,uid,pid,ppid,pri,rtprio,ni,vsz,rss,stat,tty,time,wchan,args")
            if (status == 0):
                add_ext_file_handler(field_name, field_name, command_output)
            else:
                err_flag = 1
                err_command += "ps -eLo lstart,%cpu,psr,nlwp,f,uid,pid,ppid,pri,rtprio,ni,vsz,rss,stat,tty,time,wchan,args"
    elif (field_name == "chkconfig"):
        command = ""
        st,res = get_status_output('pidof systemd && echo "systemd" || echo "other"')
        if "systemd" in res:
            command = "systemctl list-unit-files"
        else:
            command = "chkconfig --list | sort"
        status, command_output = get_status_output(command)
        if (status == 0):
                add_ext_file_handler(field_name, field_name, command_output)
        else:
            err_flag = 1
            err_command +=command
    elif (field_name == "ibnetdiscover"):
        if is_command_allowed("ibnetdiscover","no_ib"):
            if (is_ib == 0 and no_ib_flag == False):
                ibnetdiscover_command = ib_res + " --virt "
                status, command_output = get_status_output(ibnetdiscover_command)
                if (status == 0):
                    add_ext_file_handler("ibnetdiscover", "ibnetdiscover", command_output)
                    for card in active_subnets:
                        for port in active_subnets[card]:
                            status, command_output = get_status_output(ibnetdiscover_command + " -p -C " + card +" -P " + port["port_num"])
                            suffix =  card + "_" + port["port_num"]
                            if (status == 0):
                                add_ext_file_handler("ibnetdiscover --virt -p " + suffix, "ibnetdiscover_p_" + suffix, command_output)
                            else:
                                err_flag = 1
                                err_command = "No 'ibnetdiscover_p' External File\nReason: Couldn't find command: ibnetdiscover -p" + suffix
                else:
                    err_flag = 1
                    err_command += ib_res
                    err_command += "\n\nNo 'ibnetdiscover_p' External File\nReason: Couldn't find command: " + ibnetdiscover_command
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
        if is_command_allowed("Installed_packages"):
            if (cur_os != "debian"):
                status, unrelevant_res = get_status_output("rpm -qa --last > " + path + file_name + "/pkglist")
            else:
                status, unrelevant_res = get_status_output("dpkg --list > " + path + file_name + "/pkglist")
            if (status == 0):
                add_ext_file_handler(field_name, "pkglist", "")
            else:
                err_flag = 1
                err_command += "No file " + path + file_name+"/pkglist"
    elif (field_name == "Performance tuning analyze"):
        if is_command_allowed("file: performance_tuning_analyze.html"):
            status, command_output = get_status_output("cat " + html2_path)
            if (status == 0):
                add_ext_file_handler(field_name, "performance_tuning_analyze.html", command_output)
            else:
                err_flag = 1
                err_command += html2_path
    elif (field_name == "SR_IOV"):
        if is_command_allowed("file: sr_iov.html"):
            status, command_output = get_status_output("cat " + html3_path)
            if status == 0 :
                add_ext_file_handler(field_name, "sr_iov.html", command_output)
            else:
                err_flag = 1
                err_command += html3_path + "\nSince SR_IOV is not activated"
    elif(field_name == "other_system_files"):
        if is_command_allowed("get_ib_sys_files_exclude_uevent_files","no_ib"):
            error_files = ""
            if (no_ib_flag == False):
                cmd = "find /sys | grep infini |grep -v uevent |sort"
                if(interfaces_flag):
                    cmd = "find /sys | grep infini |grep -v uevent | grep -E '" + '|'.join(specific_pci_devices) + "' |sort"
                st,res = get_status_output(cmd)
                if (st == 0 and res != ""):
                    lines = res.splitlines()
                    command_output = ""
                    for line in lines:
                        if(os.path.isfile(line)):
                            try:
                                f = open(line, 'r')
                                command_output += "File: " + line + ": " + f.read()
                                f.close()
                            except: error_files += "File: " + line + "\n"
                    command_output += "\n -------------------------------------------------------- \n"
                    command_output += "Cannot open the following files: \n"
                    command_output += error_files
                    add_ext_file_handler(field_name, field_name, command_output)
                else:
                    err_flag = 1
                    err_command += "find /sys | grep infini |grep -v uevent |sort"
    elif(field_name == "numa_node"):
        if is_command_allowed("get_numa_node_sys_files_exclude_uevent_files"):
            if cur_os == "debian":
                os.system("exec 2>/dev/null")
            st, numas = get_status_output("find /sys | grep numa_node | grep -v uevent |sort")
            if st == 0:
                command_output = ""
                for numa in numas.splitlines():
                    try:
                        with open(numa, 'r') as numa_file:
                            command_output += numa + " " + numa_file.read().strip() + "\n"
                    except:
                        err_flag = 1
                        err_command += "No file " + numa
                add_ext_file_handler(field_name, field_name, command_output)
            else:
                err_flag = 1
                err_command += "find /sys | grep numa_node | grep -v uevent |sort"
    elif ("mlnx_tune" in field_name):
        if is_command_allowed("mlnx_tune","no_ib"):
            status, command_output = get_status_output(field_name + path + file_name , "1m")
            if not (status == 0 or ("Unsupported" in command_output)):
                err_flag = 1
                err_command += field_name + " - tool is not installed, and there is no script mlnx_tune"
                err_command += "\nmlnx_tune tool is available on Mellanox OFED 3.0.0 and above"
            else:
                add_ext_file_handler(field_name, curr_path, command_output)
    elif ("dmidecode" in field_name):
        if is_command_allowed("dmidecode"):
            status = get_dmidecode_info()
            if (status != 0):
                err_flag = 1
                err_command += field_name
    elif field_name == "lspci -vv":
        command_output = lspci_vv_handler()
        add_ext_file_handler(field_name, curr_path, command_output)
    else:
        if is_command_allowed(field_name):
            status, command_output = get_status_output(field_name, "10")
            if (status == 0):
                if "dmesg" in field_name or field_name == "journalctl -k -o short-monotonic":
                    add_ext_file_handler(field_name, curr_path, command_output)
                else:
                    add_ext_file_handler(field_name, field_name, command_output)
            else:
                err_flag = 1
                err_command += field_name
    if (err_flag == 1):
        f = open(path + file_name + "/err_messages/dummy_external_paths", 'a')
        f.write(err_command)
        f.write("\n\n")
        f.close()


#----------------------------------------------------------

def arrange_pcie_debugging_output():
    pcie_debug_result = ""
    for key in available_PCIE_debugging_collection_dict:
        pcie_debug_result += "\n" + key + "\n"
        if key == "devices_information":
            for device in available_PCIE_debugging_collection_dict["devices_information"]:
                pcie_debug_result += "\n"
                for field in device:
                    pcie_debug_result += "\t" + field + ": " + device[field] + "\n"
        else:
            pcie_debug_result += "\n" + available_PCIE_debugging_collection_dict[key] + "\n"

    add_output_to_pcie_folder("devices_information", pcie_debug_result)
    # add_ext_file_handler("pcie_debug", "pcie_debug", pcie_debug_result)

def arrange_server_commands_section():
    update_net_devices()
    if verbose_flag:
        print("\tGenerating server commands section has started")
    #if blueFeild is involved collect the rshim log.
    if is_bluefield_involved:
        commands_collection.append('rshim_log')
        if is_run_from_bluefield_host:
            commands_collection.append('bfver')
    # add server commands list
    for cmd in commands_collection:
        related_flag = ""
        if cmd in pcie_collection:
            related_flag = "pcie"
        if cmd in fw_collection:
            if related_flag:
                related_flag+="/"
            related_flag += "no_fw"
        if cmd in ufm_collection:
            related_flag += "ufm"
        if cmd in fsdump_collection:
            if related_flag:
                related_flag+="/"
            related_flag += "fsdump"
        if cmd in asap_collection:
            related_flag += "asap"
        if cmd in asap_tc_collection:
            related_flag += "asap_tc"
        if cmd in rdma_debug_collection:
            related_flag += "rdma_debug"
        if cmd in gpu_command_collection:
            related_flag += "gpu"
        if cmd in ib_collection:
            if related_flag:
                related_flag+="/"
            related_flag += "no_ib"
        if is_command_allowed(cmd,related_flag):
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
    # add fabric commands list if configured as IB
    for cmd in fabric_commands_collection:
        if is_command_allowed(cmd,"no_ib"):
            if verbose_count == 2:
                print("\t\t" + cmd + " - start")
            add_fabric_command_if_exists(cmd)
            if verbose_count == 2:
                print ("\t\t" + cmd + " - end")
    if verbose_flag:
        print("\tGenerating fabric diagnostic information for multi-subnets commands")

    # add fabric multi-subnets commands list if configured as IB
    for cmd in fabric_multi_sub_commands_collection:
        related_flag = "no_ib"
        if cmd == "ibdiagnet":
            related_flag = "no_ib/ibdiagnet"
        if is_command_allowed(cmd,related_flag):
            if verbose_count == 2:
                print("\t\t" + cmd + " - start")
            add_fabric_multi_sub_command_if_exists(cmd)
            if verbose_count == 2:
                print ("\t\t" + cmd + " - end")
    if verbose_flag:
        print("\tGenerating fabric diagnostic information section has ended")

def arrange_internal_files_section():
    if (cur_os == "debian"):
        internal_files_collection.extend(["/etc/debian_version","/etc/network/interfaces","/etc/networks"])
    if is_bluefield_involved and is_run_from_bluefield_host:
        internal_files_collection.append('/etc/mlnx-release')
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

    if is_command_allowed("file: /etc/modprobe.d/"):
        if (os.path.exists("/etc/modprobe.d/") == True):
            for file in os.listdir("/etc/modprobe.d/"):
                if (os.path.isfile("/etc/modprobe.d/"+file) == True):
                    if verbose_count == 2:
                        print("\t\t/etc/modprobe.d/" + file + " - start")
                    add_internal_file_if_exists("/etc/modprobe.d/" + file)
                    if verbose_count == 2:
                        print("\t\t/etc/modprobe.d/" + file + " - end")
    if is_command_allowed("file: /etc/netplan/"):
        if (os.path.exists("/etc/netplan/") == True):
            for file in os.listdir("/etc/netplan/"):
                if (os.path.isfile("/etc/netplan/"+file) == True):
                    if verbose_count == 2:
                        print("\t\t/etc/netplan/" + file + " - start")
                    add_internal_file_if_exists("/etc/netplan/" + file)
                    if verbose_count == 2:
                        print("\t\t/etc/netplan/" + file + " - end")
    if is_command_allowed("file: /proc/net/vlan/" ):
        if (os.path.exists("/proc/net/vlan/") == True):
            for file in os.listdir("/proc/net/vlan/"):
                if (os.path.isfile("/proc/net/vlan/"+file) == True):
                    if verbose_count == 2:
                        print("\t\t/proc/net/vlan/" + file + " - start")
                    add_internal_file_if_exists("/proc/net/vlan/" + file)
                    if verbose_count == 2:
                        print("\t\t/proc/net/vlan/" + file + " - end")
    if is_command_allowed("file: /sys/devices/system/node/" ):
        if (os.path.exists("/sys/devices/system/node/") == True):
            for file in os.listdir("/sys/devices/system/node/"):
                if (os.path.isfile("/sys/devices/system/node/"+file) == False) and (os.path.exists("/sys/devices/system/node/"+file+"/cpulist")):
                    if verbose_count == 2:
                        print("\t\t/sys/devices/system/node/" + file + "/cpulist - start")
                    add_internal_file_if_exists("/sys/devices/system/node/"+file+"/cpulist")
                    if verbose_count == 2:
                        print("\t\t/sys/devices/system/node/" + file + "/cpulist - end")
    if is_command_allowed("file: /etc/sysconfig/network-scripts/ifcfg*" ):
        if (cur_os != "debian" and os.path.exists("/etc/sysconfig/network-scripts/") == True):
            for file in os.listdir("/etc/sysconfig/network-scripts/"):
                suffixes = [".back", ".bak", ".save"]
                if ( (os.path.isfile("/etc/sysconfig/network-scripts/"+file) == True) and (file.startswith("ifcfg")) and not  any(file.endswith(suffix) for suffix in suffixes) ):
                    if verbose_count == 2:
                        print("\t\t/etc/sysconfig/network-scripts/" + file + " - start")
                    add_internal_file_if_exists("/etc/sysconfig/network-scripts/" + file)
                    if verbose_count == 2:
                        print("\t\t/etc/sysconfig/network-scripts/" + file + " - end")
    if is_command_allowed("file: /etc/sysconfig/network/ifcfg*"):
        if (os.path.exists("/etc/sysconfig/network/") == True):
            for file in os.listdir("/etc/sysconfig/network/"):
                if ( (os.path.isfile("/etc/sysconfig/network/"+file) == True) and (file.startswith("ifcfg-")) ):
                    if verbose_count == 2:
                        print("\t\t/etc/sysconfig/network/" + file + " - start")
                    add_internal_file_if_exists("/etc/sysconfig/network/" + file)
                    if verbose_count == 2:
                        print("\t\t/etc/sysconfig/network/" + file + " - end")
    if is_command_allowed("file: /etc/*release*"):
        if (os.path.exists("/etc/") == True):
            for file in os.listdir("/etc/"):
                if ( (os.path.isfile("/etc/"+file) == True) and ("release" in file) ):
                    if verbose_count == 2:
                        print("\t\t/etc/" + file + " - start")
                    add_internal_file_if_exists("/etc/"+file)
                    if verbose_count == 2:
                        print("\t\t/etc/" + file + " - end")
    if is_command_allowed("file: /etc/infiniband/"):
        if (os.path.exists("/etc/infiniband/") == True):
            for file in os.listdir("/etc/infiniband/"):
                if (os.path.isfile("/etc/infiniband/"+file) == True) and (file != "vf-net-link-name.sh"):
                    if verbose_count == 2:
                        print("\t\t/etc/infiniband/" + file + " - start")
                    add_internal_file_if_exists("/etc/infiniband/"+file)
                    if verbose_count == 2:
                        print("\t\t/etc/infiniband/" + file + " - end")

    if verbose_flag:
        print("\tGenerating internal files section has ended")
        print("\t----------------------------------------------------")

def arrange_external_files_section():
    if (cur_os != "debian"):
        external_files_collection.extend([["chkconfig",""]])
    if verbose_flag:
        print("\tGenerating external files section has started")
    st, var_log_files = get_status_output("ls /var/log/")
    if st == 0:
        var_log_files = var_log_files.splitlines()
        for file in var_log_files:
            if all_var_log_flag :
                if 'syslog' in file  or 'messages' in file or file == 'boot.log' or 'dmesg' in file or "kern.log" in file:
                    add_external_file_if_exists('/var/log/'+ file,'/var/log/'+ file)
            else:
                if file == 'syslog' or file == 'messages' or file == 'boot.log' or file == 'dmesg':
                    add_external_file_if_exists('/var/log/'+ file,'/var/log/'+ file)
    # add external files if exist to the provided external section e.g. "kernel config"
    for pair in external_files_collection:
        if (pair[0] in pcie_collection) :
            is_command_allowed(pair[0],"pcie")
            if (pcie_flag == False):
                continue
        if "biosdecode" in pair[0] and blueos_flag:
            continue
        if verbose_count == 2:
            print("\t\t" + pair[0] + " - start")
        add_external_file_if_exists(pair[0], pair[1])
        if verbose_count == 2:
            print("\t\t" + pair[0] + " - end")
    if (no_ib_flag == False):
        for pair in perf_external_files_collection:
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
    for pair in copy_openstack_dirs:
        if (is_command_allowed("file: " + pair[1] , " openstack")):
            if not os.path.isdir(pair[1]):
                continue
            if (openstack_flag == True):
                if verbose_count == 2:
                    print("\t\t" + pair[1] + " - start")
                try:
                    shutil.copytree(pair[1], path + file_name + "/" + pair[0])
                except:
                    pass
                if verbose_count == 2:
                    print("\t\t" + pair[1] + " - end")
    for pair in copy_openstack_files:
        if (is_command_allowed("file: " + pair[1] , "openstack")):
            if (openstack_flag == True):
                if verbose_count == 2:
                    print("\t\t" + pair[1] + " - start")
                try:
                    if (os.path.exists(path + file_name + "/" + pair[0] + "/") == False):
                        os.mkdir(path + file_name + "/" + pair[0] + "/")
                    if verbose_count == 2:
                        print("\t\t" + "from: " + pair[1] + " to: " +  path + file_name + "/" + pair[0] + "/")
                    shutil.copy(pair[1], path + file_name + "/" + pair[0] + "/")
                except:
                    pass
                if verbose_count == 2:
                    print("\t\t" + pair[1] + " - end")
    if verbose_flag:
        print("\tGenerating external files section has ended")
        print("\t----------------------------------------------------")

def arrange_dicts():
    arrange_server_commands_section()
    arrange_internal_files_section()
    arrange_external_files_section()
    if not no_ib_flag:
        update_saquery()
    if (st_saquery == 0 and no_ib_flag == False):
        arrange_fabric_commands_section()
    else:
        sub_chain_commands.extend(fabric_commands_collection)
        sub_chain_commands.extend(fabric_multi_sub_commands_collection)
    arrange_pcie_debugging_output()
#==========================================================
#        SR-IOV Arranging Dictionaries

def ip_link_show_devices_handler():
    if not sys_class_net_exists:
        return "No Net Devices - The path /sys/class/net does not exist"
    res = ""
    first = True
    for pf_device in pf_devices:
        st, ip_link_device = get_status_output("ip link show dev " + pf_device)
        if not first:
            res += "\n\n------------------------------------------------------------\n\n"
            first = False
        if st == 0:
            res += ip_link_device
        else:
            res += "Could not run: " + '"' + "ip link show dev " + pf_device + '"'
    return res

def lspci_vf_handler():
    st, lspci = get_status_output("lspci -tv ")
    if st != 0:
        if st == CANCELED_STATUS:
            return st,lspci
        return st, "Could not run: lspci -tv "

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
        status, result = get_status_output(command)
        if status != 0 and status != CANCELED_STATUS:
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
    status, result = get_status_output("cat " + file_full_path)

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
        print("\t\tGenerating sr_iov commands section has started")
    # add server commands list
    for cmd in sriov_commands_collection:
        if is_command_allowed(cmd):
            if verbose_count == 2:
                print("\t\t\t" + cmd + " - start")
            add_sriov_command_if_exists(cmd)
            if verbose_count == 2:
                print("\t\t\t" + cmd + " - end")
    if verbose_flag:
        print("\t\tGenerating sr_iov commands section has ended")

#----------------------------------------------------------
#    SR-IOV Internal Files Dictionary Handler

def arrange_sriov_internal_files_section():
    if verbose_flag:
        print("\t\t--------------------------------------------")
        print("\t\tGenerating sr_iov internal files section has started")
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
            if is_command_allowed("file: /sys/class/infiniband/*/device/") :
                if os.path.exists("/sys/class/infiniband/"+ indir + "/device/"):
                    for infile in os.listdir("/sys/class/infiniband/"+ indir + "/device/"):
                        if (infile.startswith("sriov") or infile.startswith("mlx")) and os.path.isfile("/sys/class/infiniband/"+ indir + "/device/" + infile):
                            if verbose_count == 2:
                                print("\t\t\t/sys/class/infiniband/"+ indir + "/device/" + infile + " - start")
                            add_sriov_internal_file_if_exists("/sys/class/infiniband/"+ indir + "/device/" + infile)
                            if verbose_count == 2:
                                print("\t\t\t/sys/class/infiniband/"+ indir + "/device/" + infile + " - end")
            if os.path.exists("/sys/class/infiniband/" + indir + "/iov/"):
                if is_command_allowed("file: /sys/class/infiniband/*/iov" ):
                    if os.path.exists("/sys/class/infiniband/" + indir + "/iov/ports/"):
                        for indir2 in os.listdir("/sys/class/infiniband/" + indir + "/iov/ports/"):
                            if represents_int(indir2) and int(indir2) >= 0 and int(indir2) <= 127:
                                if os.path.isfile("/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/gids/" + indir2):
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/gids/" + indir2 + " - start")
                                    add_sriov_internal_file_if_exists("/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/gids/" + indir2)
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/gids/" + indir2 + " - end")
                                if os.path.isfile("/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/admin_guids/" + indir2):
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/admin_guids/" + indir2 + " - start")
                                    add_sriov_internal_file_if_exists("/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/admin_guids/" + indir2)
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/" + indir2 + "/admin_guids/" + indir2 + " - end")
                                if int(indir2) <= 126:
                                     if os.path.isfile("/sys/class/infiniband/" + indir + "/iov/ports/"  + indir2 + "/pkeys/" + indir2):
                                        if verbose_count == 2:
                                            print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/"  + indir2 + "/pkeys/" + indir2 + " - start")
                                        add_sriov_internal_file_if_exists("/sys/class/infiniband/" + indir + "/iov/ports/"  + indir2 + "/pkeys/" + indir2)
                                        if verbose_count == 2:
                                            print("\t\t\t/sys/class/infiniband/" + indir + "/iov/ports/"  + indir2 + "/pkeys/" + indir2 + " - end")
                    for indir2 in os.listdir("/sys/class/infiniband/" + indir + "/iov/"):
                        if indir2.startswith("0000"):
                            for m in range(1,3):
                                if os.path.isfile("/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/gid_idx/0"):
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/gid_idx/0 - start")
                                    add_sriov_internal_file_if_exists("/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/gid_idx/0")
                                    if verbose_count == 2:
                                        print("\t\t\t/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/gid_idx/0 - end")
                                for n in range(127):    # 0 <= n <= 126
                                    if os.path.isfile("/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/pkey_idx/" + str(n)):
                                        if verbose_count == 2:
                                            print("\t\t\t/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/pkey_idx/" + str(n) + " - start")
                                        add_sriov_internal_file_if_exists("/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/pkey_idx/" + str(n))
                                        if verbose_count == 2:
                                            print("\t\t\t/sys/class/infiniband/" + indir + "/iov/" + indir2 + "/port/" + str(m) + "/pkey_idx/" + str(n) + " - end")
    if is_command_allowed("file: /etc/sysconfig/network-scripts/" ):
        if os.path.exists("/etc/sysconfig/network-scripts/"):
            for infile in os.listdir("/etc/sysconfig/network-scripts/"):
                if infile.startswith("ifcfg-"):
                    if verbose_count == 2:
                        print("\t\t\t/etc/sysconfig/network-scripts/" + infile + " - start")
                    add_sriov_internal_file_if_exists("/etc/sysconfig/network-scripts/" + infile)
                    if verbose_count == 2:
                        print("\t\t\t/etc/sysconfig/network-scripts/" + infile + " - end")
    if is_command_allowed("file: /sys/class/net/"):
        if os.path.exists("/sys/class/net/"):
            for indir in os.listdir("/sys/class/net/"):
                if os.path.isfile("/sys/class/net/" + indir) == False and (indir.startswith("eth") or indir.startswith("ib")):
                    for inSomething in os.listdir("/sys/class/net/" + indir + "/"):
                        if os.path.isfile("/sys/class/net/" + indir + "/" + inSomething) == False:
                            if os.path.isfile("/sys/class/net/" + indir + "/" + inSomething + "/tx_rate"):
                                if verbose_count == 2:
                                    print("\t\t\t/sys/class/net/" + indir + "/" + inSomething + "/tx_rate - start")
                                add_sriov_internal_file_if_exists("/sys/class/net/" + indir + "/" + inSomething + "/tx_rate")
                                if verbose_count == 2:
                                    print("\t\t\t/sys/class/net/" + indir + "/" + inSomething + "/tx_rate - end")
                        elif inSomething.startswith("fdb") or inSomething.startswith("mode") or inSomething.startswith("pkey"):
                            if os.path.isfile("/sys/class/net/" + indir + "/" + inSomething):
                                if verbose_count == 2:
                                    print("\t\t\t/sys/class/net/" + indir + "/" + inSomething + " - start")
                                add_sriov_internal_file_if_exists("/sys/class/net/" + indir + "/" + inSomething)
                                if verbose_count == 2:
                                    print("\t\t\t/sys/class/net/" + indir + "/" + inSomething + " - end")
    if verbose_flag:
        print("\t\tGenerating sr_iov internal files section has ended")


def arrange_sriov_dicts():
    arrange_sriov_commands_section()
    arrange_sriov_internal_files_section()

###########################################################
###############  Out File Name Handlers ###################

def get_json_file_name():
    hst, curr_hostname = no_log_status_output("hostname")
    #curr_hostname = invoke_command(['hostname']).replace('\n', '-')
    json_file_name = "sysinfo-snapshot-v" + version + "-"
    if is_command_allowed("hostname") or generate_config_flag:
        json_file_name += curr_hostname.replace('\n', '-') + "-"
    json_file_name += date_file
    return json_file_name


###########################################################
############### Print Handlers ############################

def print_in_process():
    print("Sysinfo-snapshot is still in process...please wait till completed successfully")
    if generate_config_flag:
        print("Generating config file \nYour patience is appreciated")
    else:
        print("Gathering the information may take a while, especially in large networks\nYour patience is appreciated")

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
                print("firmware \t\t\t- contains all firmware files (mst dump files and commands outputs)")
            elif (fi == "ibdiagnet"):
                print("ibdiagnet \t\t\t- contains all files generated from invoking ibdiagnet")
            elif (fi == "etc_udev_rulesd"):
                print("etc_udev_rulesd \t\t- contains all files under /etc/udev/rules.d")
            elif (fi == "lib_udev_rulesd"):
                print("lib_udev_rulesd \t\t- contains all files under /lib/udev/rules.d")
            elif (fi == "conf_nova"):
                print("conf_nova \t\t- contains all files under /var/lib/config-data/puppet-generated/nova_libvirt")
            elif (fi == "conf_neutron"):
                print("conf_neutron \t\t- contains all files under /var/lib/config-data/puppet-generated/neutron/")
            elif (fi == "conf_nove"):
                print("logs_nova \t\t- contains all files under /var/log/containers/nova")
            elif (fi == "conf_nove"):
                print("logs_neutron \t\t- contains all files under /var/log/containers/neutron")
            else:
                print(fi)

def show_error_message(err_msg):
    print("Error: Unknown option/s: " + err_msg)

###########################################################
############## Main Function's Handlers ###################

def remove_unwanted_temp_files(file,filePath):
    if (file.startswith("tmp.") or file.startswith("hsqldb.")):
        if os.path.isfile(filePath + file):
            os.remove(filePath + file)
        elif os.path.isdir(filePath + file):
            os.rmdir(filePath + file)

# Remove all unwanted side effect files and folders
def remove_unwanted_files():
    # Remove mstflint_lockfiles directory
    no_log_status_output("rm -rf /tmp/mstflint_lockfiles")
    # Remove all unwanted side effect files
    if (path != "/tmp/" and os.path.exists(path) == True):
        for file in os.listdir(path):
            remove_unwanted_temp_files(file , path)
    for tmp_file_name in os.listdir('/tmp/'):
        if(re.search("^status-log-.*" + file_name + "$", tmp_file_name)):
            os.remove("/tmp/" + tmp_file_name)
        remove_unwanted_temp_files( tmp_file_name, "/tmp/" )
    # Remove untared directory out file
    shutil.rmtree( path + file_name)


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
    st, irqbalance = get_status_output("service irqbalance status")
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
    st, cpuinfo = get_status_output("cat /proc/cpuinfo")
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
    st, siblings = get_status_output("cat /proc/cpuinfo | grep " + '"' + "siblings" + '"')
    if (st != 0):
        st, siblings_lines_num = get_status_output("cat /proc/cpuinfo | grep " + '"' + "siblings" + '"' + " | wc -l")
        if (st == 0 and represents_int(siblings_lines_num) and int(siblings_lines_num)==0):
            siblings = ""
        else:
            perf_val_dict[key] = "command not found: cat /proc/cpuinfo | grep " + '"' + "siblings" + '"'
            return

    st, cpu_cores = get_status_output("cat /proc/cpuinfo | grep " + '"' + "cpu cores" + '"')
    if (st != 0):
        st, cpu_cores_lines_num = get_status_output("cat /proc/cpuinfo | grep " + '"' + "cpu cores" + '"' + " | wc -l")
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

    st, ipv = get_status_output("cat " + path)
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

def add_output_to_pcie_debug_dict(key, result):
    pcie_debug_result = {key: result}
    add_ext_file_handler("pcie_debug_dict", "pcie_debug_dict", "\n" + str(pcie_debug_result))
    available_PCIE_debugging_collection_dict.update(pcie_debug_result)

#----------------------------------------------------------

def add_command_to_pcie_debug_dict(command):
    status, result = get_status_output(command)
    add_output_to_pcie_debug_dict(command, result)
    return status, result

#----------------------------------------------------------

pci_devices = []
direct = False

def performance_lspci(check_latest=False):
    global pci_devices
    global direct
    global running_warnings

    key = "PCI Configurations"
    #lspci -d 15b3: - e.g 81:00.0 Ethernet controller: Mellanox Technologies MT27800 Family [ConnectX-5]
    st, cards_num = get_status_output("lspci -d 15b3: | wc -l")
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

    st, mlnx_cards = get_status_output("lspci -d 15b3:")
    if (st != 0 or ("command not found" in mlnx_cards)):
        perf_val_dict[key] = "command not found: lspci -d 15b3:"
        direct = True
        return
    mlnx_cards = mlnx_cards.splitlines()
    i = -1
    is_all_failed = True
    for card in mlnx_cards:
        i += 1
        card_pci = card.split()[0]
        pci_devices.append({"status":"OK", "name":card, "device":card_pci, "current_fw":"", "psid":"", "desired_gen":3.0, "current_gen":3.0, "desired_speed":8.0, "current_speed":8.0, "desired_width":8.0, "current_width":8.0, "desired_payload_size":256.0, "current_payload_size":8.0, "desired_max_read_request":4096.0, "current_max_read_request":4096.0})
        if ( (not "[" in card) or (not "]" in card) ):
            pci_devices[i]["status"] = not_available
            pci_devices[i]["desired_gen"] = not_available
            continue
        card_str = card
        card = card.split("[")[1]
        card = card.split("]")[0]
        card = card.lower()
        if ("pcie 2.0" in card):
            pci_devices[i]["desired_payload_size"] = 256.0
            pci_devices[i]["desired_max_read_request"] = 512.0
        elif (("x-2" in card) or ("x2" in card)):
            pci_devices[i]["desired_payload_size"] = 256.0
            pci_devices[i]["desired_max_read_request"] = 512.0
        else:
            pci_devices[i]["desired_payload_size"] = 256.0
            pci_devices[i]["desired_max_read_request"] = 512.0
        st, firmwares_query, tool_used = general_fw_command_output('fwflint_q', card_pci)
        if (st == 0):
            #firmwares_query :-
            #FW Version:            16.18.1000
            #PSID:                  MT_0000000008
            is_all_failed = False
            check_fw = re.search("FW((.*))", firmwares_query, re.MULTILINE).group(0)
            check_psid = re.search("PSID((.*))", firmwares_query, re.MULTILINE).group(0)
            pci_devices[i]["current_fw"] = check_fw.split()[-1]
            pci_devices[i]["psid"] = check_psid.split()[-1]
            if check_latest:
                if is_command_allowed('mlxfwmanager --online-query-psid',"check_fw"):
                    st, check_latest_fw = get_status_output("mlxfwmanager --online-query-psid " + pci_devices[i]["psid"] , "30")
                    if (st == 0):
                        #     FW             14.20.1010
                        check_latest_fw = re.search("FW((.*\n))", check_latest_fw, re.MULTILINE).group(0).splitlines()
                        if LooseVersion(check_latest_fw[0].split()[-1] ) > LooseVersion(pci_devices[i]["current_fw"]):
                            pci_devices[i]["status"] = "Warning"
                            pci_devices[i]["current_fw"] = 'Warning the current Firmware- ' + pci_devices[i]["current_fw"] + ', is not latest - ' + check_latest_fw[0].split()[-1]
                        else:
                            pci_devices[i]["current_fw"] = pci_devices[i]["current_fw"] + "(latest version)"
                else:
                   running_warnings.append("--check_fw flag was provided but mlxfwmanager --online-query-psid command not allowed")
    if is_all_failed:
        running_warnings.append("--check_fw flag was provided but running flint q for all cards failed")
    st, cards_xxx = get_status_output("lspci -d 15b3: -xxx | grep '^70: '")
    if (st != 0):
        perf_val_dict[key] = "command not found: lspci -d 15b3: -xxx | grep '^70: '"
        direct = True
        return
    i = -1
    cards_xxx = cards_xxx.splitlines()
    for card_xxx in cards_xxx:
        i += 1
        if i < len(pci_devices):
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
    st, cards_gen = get_status_output("lspci -d 15b3: -vvv | grep -i PCIeGen")
    if (st != 0):
        perf_val_dict[key] = "command not found: lspci -d 15b3: -vvv | grep -i PCIeGen"
        direct = True
        return
    i = -1
    cards_gen = cards_gen.splitlines()
    for line in cards_gen:
        line = line.lower()
        i += 1
        try:
            pci_devices[i]["desired_gen"] = float((line.split("pciegen")[1]).strip().split()[0])
        except ValueError:
            pci_devices[i]["desired_gen"] = -1.0
    st, cards_speed_width = get_status_output("lspci -d 15b3: -vvv | grep -i Speed")
    st, cards_speed_width = get_status_output("lspci -d 15b3: -vvv | grep -i Speed")
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
                    pci_devices[i]["current_width"] = float(re.split(',|[(]| ',line.split("width x")[1])[0])
                except ValueError:
                    pci_devices[i]["current_width"] = -1.0
            else:
                pci_devices[i]["current_width"] = -1.0
        elif("lnkcap:" in line):
            try:
                pci_devices[i]["desired_speed"] = float((line.split("gt/s")[0]).split()[-1])
            except ValueError as e:
                pci_devices[i]["desired_speed"] = -1.0
            if (len(line.split("width x")) > 1):
                try:
                    pci_devices[i]["desired_width"] = float(re.split(',|[(]| ',line.split("width x")[1])[0])
                except ValueError:
                    pci_devices[i]["desired_width"] = -1.0
            else:
                pci_devices[i]["desired_width"] = -1.0

    st, cards_payload_read = get_status_output("lspci -d 15b3: -vvv | grep -i MaxReadReq")
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
    if(interfaces_flag):
        specific_pci_dev = []
        for device in specific_pci_devices:
            result = [d for d in pci_devices if d.get('device') == device.split(":",1)[1]]
            specific_pci_dev.append(result[0])
        pci_devices = specific_pci_dev
    PCIE_debugging_information = []
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

        PCIE_debug_info = {"name": pci_devices[i]["name"],"current_fw": pci_devices[i]["current_fw"], "psid": pci_devices[i]["psid"]}
        PCIE_debugging_information.append(PCIE_debug_info)
    
    add_output_to_pcie_debug_dict("devices_information", PCIE_debugging_information)


#----------------------------------------------------------

def amd():
    key = "AMD"
    st, manufacturer = get_status_output("dmidecode -s processor-manufacturer")
    if (st != 0):
        perf_val_dict[key] = "command not found: dmidecode -s processor-manufacturer"
        return

    if "amd" in manufacturer.lower() or "advanced micro devices" in manufacturer.lower():
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
    st, count = get_status_output("cat /etc/security/limits.conf | grep memlock | wc -l")
    if (st != 0 or ("command not found" in count) or (count == "") or (count == "0")):
        perf_status_dict[key] = not_present
        perf_val_dict[key] = ""
    else:
        st, memlock = get_status_output("cat /etc/security/limits.conf | grep memlock")
        if (st != 0):
            perf_status_dict[key] = not_present
            perf_val_dict[key] = ""
        else:
            perf_status_dict[key] = present
            perf_val_dict[key] = memlock

#----------------------------------------------------------


def bw_and_lat():
    global bandwidth
    global latency
    global perf_samples
    st = st_infiniband_devices
    devices = infiniband_devices
    if (st != 0 or ("No such file or directory" in devices)):
        try:
            perf_setting_collection.remove("Bandwidth")
            perf_setting_collection.remove("Latency")
            perf_setting_collection.remove("Perf Samples")
        except:
            pass
        return

    devices = devices.split()
    if len(devices) <= 0:
        return
    st, show_gids = get_status_output("show_gids | sort -k5,6 --numeric-sort")
    if st != 0:
       show_gids = ""
    ##------------------------------------Samples before test------------------------------------------------##
    if is_command_allowed('perf_samples',"no_ib,perf"):
        for pf_device in pf_devices:
            perf_samples[pf_device] = ""
            st, pfc_output = get_status_output("ethtool -S " + pf_device + " | grep -e pause -e discards", "20")
            if st == 0:
                perf_samples[pf_device] += "Before test sample: ethtool -S " + pf_device + " | grep -e pause -e discards \n" + pfc_output + "\n"
            st, pfc_output = get_status_output("ethtool -S " + pf_device + " | grep -e prio", "20")
            if st == 0:
                perf_samples[pf_device] += "Before test sample: ethtool -S " + pf_device + " | grep -e prio \n" + pfc_output + "\n"
        ##------------------------------------End samples before test------------------------------------------------##
        for device in devices:
            perf_samples[device] = ""
            st, cnp_files = get_status_output("ls /sys/class/infiniband/" + device + "/ports/1/hw_counters/*cnp*")
            cnp_files = cnp_files.split()
        ##------------------------------------Samples before test------------------------------------------------##
            for cnp_file in cnp_files:
                st, cnp_output = get_status_output("cat " + cnp_file)
                if st == 0:
                    perf_samples[device] += "Before test sample: cat " + cnp_file + "\n" + cnp_output + "\n"
            st, ecn_output = get_status_output("cat /sys/class/infiniband/" + device + "/ports/1/hw_counters/np_ecn_marked_roce_packets")
            if st == 0:
                perf_samples[device] += "Before test sample: cat /sys/class/infiniband/" + device + "/ports/1/hw_counters/np_ecn_marked_roce_packets \n" + ecn_output + "\n"
            perf_samples[device] += "\n\n------------------------------------------------\n\n"
        ##------------------------------------End samples before test------------------------------------------------##
        if is_command_allowed('ib_write_bw_test',"no_ib,perf"):
            bandwidth[device] = ""
            cmd = "ib_write_bw --report_gbits -d " + device + " >/dev/null & sleep 2; ib_write_bw --report_gbits -d " + device + " localhost"
            st, bandwidth[device] = getstatusoutput(cmd)
            bandwidth[device] = cmd + "\n\n" + bandwidth[device]
        if is_command_allowed('latency',"no_ib,perf"):
            cmd = "ib_write_lat -d " + device + " >/dev/null & sleep 2; ib_write_lat -d " + device + " localhost"
            st, latency[device] = getstatusoutput(cmd)
            latency[device] = cmd + "\n\n" + latency[device]
        if device in show_gids:
            try:
                data = show_gids.split(device)[-1].splitlines()[0].strip().split()
                if len(data)>=5:
                    index = data[1]
                    if is_command_allowed('ib_write_bw_test',"no_ib,perf"):
                        bandwidth[device] += "\n\n##################################################\n\n"
                        cmd = " ib_write_bw -d " + device + " -x" + index + " >/dev/null & sleep 2; ib_write_bw -d " + device + " -x" + index + " localhost"
                        bandwidth[device] += cmd + "\n\n"
                        st, bandwidth_x = getstatusoutput(cmd)
                        bandwidth[device] += bandwidth_x
                    if is_command_allowed('latency',"no_ib,perf"):
                        latency[device] += "\n\n##################################################\n\n"
                        cmd = " ib_write_lat -d " + device + " -x" + index + " >/dev/null & sleep 2; ib_write_lat -d " + device + " -x" + index + " localhost" 
                        latency[device] += cmd + "\n\n"
                        st, latency_x = getstatusoutput(cmd)
                        latency[device] += latency_x
            except:
                pass
        ##------------------------------------Samples after test------------------------------------------------##
        if is_command_allowed('perf_samples',"no_ib,perf"):
            for cnp_file in cnp_files:
                st, cnp_output = get_status_output("cat " + cnp_file)
                if st == 0:
                    perf_samples[device] += "After test sample: cat " + cnp_file + "\n" + cnp_output + "\n"
            st, ecn_output = get_status_output("cat /sys/class/infiniband/" + device + "/ports/1/hw_counters/np_ecn_marked_roce_packets")
            if st == 0:
                perf_samples[device] += "After test sample: cat /sys/class/infiniband/" + device + "/ports/1/hw_counters/np_ecn_marked_roce_packets \n" + ecn_output + "\n"
        ##------------------------------------End samples after test------------------------------------------------##
    ##------------------------------------Samples after test------------------------------------------------##
    if is_command_allowed('perf_samples',"no_ib,perf"):
        for pf_device in pf_devices:
            st, pfc_output = get_status_output("ethtool -S " + pf_device + " | grep -e pause -e discards", "20")
            if st == 0:
                perf_samples[pf_device] += "After test sample: ethtool -S " + pf_device + " | grep -e pause -e discards \n" + pfc_output + "\n"
            st, pfc_output = get_status_output("ethtool -S " + pf_device + " | grep -e prio", "20")
            if st == 0:
                perf_samples[pf_device] += "After test sample: ethtool -S " + pf_device + " | grep -e prio \n" + pfc_output + "\n"
    ##------------------------------------End samples after test------------------------------------------------##
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
    if is_command_allowed('performance_lspci'):
        if verbose_count == 2:
            print("\t\t\tlspci - start")
        performance_lspci(check_fw_flag)
        if verbose_count == 2:
            print("\t\t\tlspci - end")
    if is_command_allowed('dmidecode -s processor-manufacturer'):
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
    if is_command_allowed('ip_forwarding'):
        if (is_ib != 0):
            if verbose_count == 2:
                print("\t\t\tip_forwarding - start")
            ip_forwarding()
            if verbose_count == 2:
                print("\t\t\tip_forwarding - end")
    elif (no_ib_flag == False and perf_flag == True  ) :
        if verbose_count == 2:
            print("\t\t\tbw_and_lat - start")
        bw_and_lat()
        if verbose_count == 2:
            print("\t\t\tbw_and_lat - end")
    else:
        perf_setting_collection.remove("Bandwidth")
        perf_setting_collection.remove("Latency")
        perf_setting_collection.remove("Perf Samples")

def generate_perf_table():
    init_status_dict()
    perform_checkings()

###########################################################
###########################################################
#        HTML Handlers

#==========================================================
#    Main Sysinfo-Snapshot HTML #1 Handlers
#==========================================================

html_path = ""
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
    html = open(html_path, 'w+')
    html.write("<html>")
    html.write("<head><title>" + html_path + "</title></head>")
    html.write("<body><pre>")
    html.write("<a name=" + '"' + "index" + '"' + "></a><h1>Mellanox Technologies</h1>")
    html.write("<br/>")
    html.write("<a name=" + '"' + "index" + '"' + "></a><h2>" + get_welcome() + "</h2>")
    html.write("<br/>")
    html.write("<a name=" + '"' + "index" + '"' + "></a><h2>Version: " + version + "</h2>")
    html.write("<br/><hr/>")

    # WARNIGS section
    if(non_root):
        html.write("<p><font color="+'"'+"red"+'"'+" size="+'"'+"3"+'"'+">Warning: Running as non root user, commands/files that require root permissions are missing. (--non_root flag was provided)</font></p>")


    # Add firmware and I2C alerts status
    if no_fw_flag == True:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Firmware commands are NOT included. (--no_fw flag was provided)</font></p>")
    else:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Firmware commands are included.</font></p>")

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
            if is_ib != 0:
                html.write("<p><font color="+'"'+"red"+'"'+" size="+'"'+"3"+'"'+">Error: --ibdiagnet flag was provided, but could NOT generate ibdiagnet</font></p>")
            elif ibdiagnet_error:
                html.write("<p><font color="+'"'+"red"+'"'+" size="+'"'+"3"+'"'+">Error: --ibdiagnet flag was provided, but it's ouput may not be displayed correctly for all subnets</font></p>")
            else:
                html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: ibdiagnet command is included. (--ibdiagnet flag was provided)</font></p>")
        else:
            html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: ibdiagnet command is NOT included. (--ibdiagnet flag was not provided)</font></p>")

    if with_inband_flag and is_MFT_installed:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: In-band cables information are included (--with_inband flag was provided)</font></p>")
    elif not with_inband_flag:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: In-band cables information are NOT included (--with_inband flag was not provided)</font></p>")
    elif with_inband_flag and not is_MFT_installed:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: In-band cables information are NOT included (--with_inband flag was provided, but could NOT generate in-band cables information)</font></p>")
    if openstack_flag:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: OpenStack commands are included (--openstack flag was provided)</font></p>")
    else:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: OpenStack commands are NOT included. (--openstack flag was not provided)</font></p>")

    if asap_flag:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Asap commands are included (--asap flag was provided)</font></p>")
    else:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Asap commands are NOT included. (--asap flag was not provided)</font></p>")

    if fsdump_flag:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: fsdump command is included (--fsdump flag was provided)</font></p>")
    else:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: fsdump commands is NOT included. (--fsdump flag was not provided)</font></p>")

    if asap_tc_flag:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Asap TC filter commands are included (--asap_tc flag was provided)</font></p>")
    else:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Asap TC filter commands are NOT included. (--asap_tc flag was not provided)</font></p>")

    if rdma_debug_flag:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Rdma commands with iprout2 are included. (--rdma debug flag was provided)</font></p>")
    else:
         html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Rdma commands with iprout2 are NOT included. (--rdma debug flag was not provided)</font></p>")
    if gpu_flag:
        html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Nvidia GPU commands are included. (--gpu flag was provided)</font></p>")
    else:
         html.write("<p><font color="+'"'+"orange"+'"'+" size="+'"'+"3"+'"'+">Alert: Nvidia GPU commands are NOT included. (--gpu flag was not provided)</font></p>")
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
    if(collection == available_commands_collection)  :
        collection = list(chain.from_iterable(collection))
        collection.sort()
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
    original_collection = collection
    if((collection == available_commands_collection)):
        collection = list(chain.from_iterable(collection))
        collection.sort()
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
        if ( (original_collection == available_commands_collection)
            and ( collection[i] in available_commands_collection[not is_command_string])):
            array_output_links_collection = ["fw_ini_dump","mst_commands_query_output","asap_parameters","asap_tc_information","rdma_tool","ecn_configuration","/etc/mlnx_snap","congestion_control_parameters","show_irq_affinity_all","mlxcables","networkManager_system_connections"]
            html.write("<p>")
            if (collection[i] == "ethtool_all_interfaces") or (collection[i] == "devlink_handler") :
                content = dict[collection[i]]
                content = content.split("\n")
                content_final = ""
                for line in content:
                    if "<td><a href=" not in line:
                        content_final += line.replace('<', "&lt;").replace('>', "&gt;") + "\n"
                    else:
                        content_final += line + "\n"
                html.write(content_final)
            elif ( collection[i] in array_output_links_collection ):
                if("mst_commands_query_output" in collection[i] and non_root):
                    html.write("Running as a non-root user - You must be root to use mst tool")
                    html.write("&nbsp;&nbsp;&nbsp;&nbsp;")
                else:
                    for value in server_commands_dict[collection[i]]:
                        html.write("&nbsp;&nbsp;&nbsp;&nbsp;")
                        html.write(value)
            else:
                if(server_commands_dict[collection[i]]):
                    for value in server_commands_dict[collection[i]]:
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
    #available_commands_collection.sort()
    if (is_ib == 0 and no_ib_flag == False): # IB Fabric
        available_fabric_commands_collection.sort()
    available_internal_files_collection.sort()

    #=======================BEGIN OF SERVER COMMANDS SECTION ====================
    html_write_section(html, "1. Server Commands: ", available_commands_collection, 1000)

    #=======================END OF SERVER COMMANDS SECTION =======================

    #=======================BEGIN OF FABRIC DIGNASTICS SECTION ===================
    if (st_saquery == 0 and no_ib_flag == False):
        html_write_section(html, "2. Fabric Diagnostic Information: ", available_fabric_commands_collection, 2000)

    #=======================END OF FABRIC DIGNASTICS SECTION =====================

    #=======================BEGIN OF FILES SECTION ===============================

    if (st_saquery == 0 and no_ib_flag == False):
        html_write_section(html, "3. Internal Files: ", available_internal_files_collection, 3000)
    else:
        html_write_section(html, "2. Internal Files: ", available_internal_files_collection, 3000)

    #=======================EXTERNAL FILES =======================================
    if (st_saquery == 0 and no_ib_flag == False):
        html.write("<h2>4. External Files/commands:</h2>")
    else:
        html.write("<h2>3. External Files/commands:</h2>")
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
        html.write("<td width=" + '"' + "16%" +'"' + "><a href='" + pair[1] + "'>" + pair[0] + "</a></td>")
        c = c+1
        if ( (c % 6) == 0):
            html.write("</tr><tr>")
            r = r+1
            c=0

    html.write("</tr></table>")

    #=======================END OF FILES SECTION =================================
    #=======================Paragraph 1 - Server Commands ========================

    parag_1_end = html_write_paragraph(html, 1000, available_commands_collection, server_commands_dict, 0)

    #=============================================================================
    #=======================Paragraph 2 - Fabric Commands ========================

    if (st_saquery == 0 and no_ib_flag == False): # IB Fabric
        parag_2_end = html_write_paragraph(html, 2000, available_fabric_commands_collection, fabric_commands_dict, parag_1_end)
    else:
        parag_2_end = parag_1_end

    #============================================================================
    #=======================Paragraph 3 - Internal Files ========================

    parag_3_end = html_write_paragraph(html, 3000, available_internal_files_collection, files_dict, parag_2_end)

    #=============================================================================


    html.write("</body></pre>")
    html.write("</html>")

    html.close()

#==========================================================
#    Performance Tuner HTML Handlers
#==========================================================

html2_path = ""
html2_flag=0

def initialize_html2(html2_flag):
    if (html2_flag == 1):
        return
    html2_flag = 1
    html2 = open(html2_path, 'w+')
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

def html2_write_samples(html2):
    i = 0
    for device, val in perf_samples.items():
        i += 1
        if (i > 1):
            html2.write("<br/>")
        html2.write(device + "<br/>" + val + "<br/>")
        if (i < len(perf_samples)):
            html2.write("<br/>****************************************<br/>")

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
        elif (perf_setting_collection[i] == "Perf Samples"):
            html2_write_samples(html2)
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

    if (no_ib_flag == False and os.path.exists(path+file_name+"/commands_txt_output/mlnx_tune_r") == True):
        html2.write("<h2>2. External Files/commands:</h2>")
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
            html2.write("<td width=" + '"' + "16%" +'"' + "><a href='commands_txt_output/" + pair[1] + "'>" + pair[0] + "</a></td>")
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

html3_path = ""
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
    html3.write("<a name=" + '"' + "index" + '"' + "></a><h2>Single Root IO Virtualization (SR_IOV)</h2>")
    html3.write("<br/>")
    html3.write("<a name=" + '"' + "index" + '"' + "></a><h2>Version: " + sriov_version + "</h2>")
    html3.write("<br/><hr/>")

    html3.close()

#----------------------------------------------------------

def build_and_finalize_html3():
    html3 = open(html3_path, 'a')

    #=======================PRINT PROPER MESSAGE - NO SRIOV ====================

    if len(available_sriov_commands_collection) == 0 and len(available_sriov_internal_files_collection) == 0:
        html3.write("There are neither available SR_IOV commands nor available SR_IOV related internal files")
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
        html_write_section(html3, "1. SR_IOV Commands: ", available_sriov_commands_collection, 1000)
        if_section_num = "2. "
        if_index = 2000

    #=======================END OF SERVER COMMANDS SECTION =====================
    #=======================BEGIN OF SR-IOV INTERNAL FILES SECTION =============

    if len(available_sriov_internal_files_collection) > 0:
        html_write_section(html3, if_section_num + "SR_IOV Related Internal Files: ", available_sriov_internal_files_collection, if_index)

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
    st, mlnx_cards = no_log_status_output("lspci -d 15b3:")
    if (st != 0 or ("command not found" in mlnx_cards)):
        st = st_infiniband_devices
        mlnx_cards = infiniband_devices
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
    file_paths = ["{}/{}{}/err_messages/dummy_functions".format(path, file_name, ""),
              "{}/{}{}/err_messages/dummy_paths".format(path, file_name, ""),
              "{}/{}{}/err_messages/dummy_external_paths".format(path, file_name, "")]
    for file_path in file_paths:
        with open(file_path, 'a'):
            pass

# Load module if needed and save old mst status
def load_modules():
    global driver_required_loading
    global is_MFT_installed
    global is_MST_installed
    global are_inband_cables_loaded
    global mst_devices_exist

    st, output = get_status_output('flint --version')
    if st != 0:
        if non_root:
            print("Running as a non-root user - You must be root to use mst tool")
        else:
            print ('MFT is not installed,flint --version failed')
        is_MFT_installed = False
    else:
        is_MFT_installed = True
    os.system("mst start > /dev/null 2>&1")
    if with_inband_flag:
        os.system("mst cable add --with_ib > /dev/null 2>&1")
    else:
        os.system("mst cable add > /dev/null 2>&1")

    if os.path.isdir('/dev/mst'):
        mst_devices_exist = True
    else:
        mst_devices_exist = False

    if mst_devices_exist:
        current_mst_devices = os.listdir("/dev/mst")
        for device in current_mst_devices:
            if ((device.startswith('SW') or device.startswith('CA')) and ('cable') in device):
                are_inband_cables_loaded = True
                break

    st, mst_start = get_status_output('mstflint -v')
    if st != 0:
        print ('mstflint is not installed.')
        is_MST_installed = False
    else:
        is_MST_installed = True

    return

def generate_pcie_debug_info():
    ensure_out_dir_existence()
    no_log_status_output("mkdir " + path + file_name)
    no_log_status_output("mkdir " + path + file_name + "/firmware")
    no_log_status_output("mkdir " + path + file_name + "/pcie_files")
    no_log_status_output("mkdir " + path + file_name + "/err_messages")
    no_log_status_output("mkdir " + path + file_name + "/commands_txt_output")
    create_empty_log_files()
    load_modules()
    update_net_devices()
    for command in PCIE_debugging_collection:
        if "performance_lspci" in command:
            performance_lspci()
        elif "dmidecode" in command:
            get_dmidecode_info()
        elif "mlxlink / mstlink" in command:
            result = ""
            if not no_cables_flag:
                result = mstcommand_d_handler('mlxlink / mstlink',pcie_debug = True)
                # add_output_to_pcie_debug_dict("mlxlink_mstlink", result)
            else:
                result = "no_cable_flag used, mlxlink / mstlink commands are not executed"
        elif "dmesg" in command:
            add_external_file_if_exists("dmesg -T", "dmesg")
        elif "mst_commands_query_output" in command:
            mst_func_handler()
            # add_output_to_pcie_debug_dict("lspci -vv", result)
        elif "lscpu" in command:
            status, result = get_status_output(command)
            add_output_to_pcie_folder("lscpu", result)
        else:
            add_command_to_pcie_debug_dict(command)
    arrange_pcie_debugging_output()
    create_tar_file()
    remove_unwanted_files()
    print("Out file name is " + path + file_name + ".tgz\n")
    print("Running sysinfo-snapshot has ended successfully!")

def add_output_to_pcie_folder(file,output):
    """
    
    Function that takes specific output and writes it to a new file with name 'file' under the 'pcie_files' directory.
    :param file: the name of the file to be written
    :param output: the content to be written to the file
    :return: None

    """
    full_path =path + file_name + "/pcie_files/" + file
    with open(full_path, "w") as f:
        f.write(output)

def create_tar_file():
    # Arrange status log and copy it into the tar file
    arrange_command_status_log()
    try:
        subprocess.run(['tar', '-czf', path + file_name + ".tgz", '-C',path, file_name])
    except :
        get_status_output('tar -zcvf ' + path + file_name + ".tgz " +'-C ' + path + " "  +file_name,"20")

def generate_output():
    global csvfile
    global ibdiagnet_error
    global with_inband_flag

    validate_not_file()
    print_in_process()
    confirm_mlnx_cards()

    # Create output directories
    ensure_out_dir_existence()
    no_log_status_output("mkdir " + path + file_name)
    #invoke_command(['mkdir', path + file_name])
    no_log_status_output("mkdir " + path + file_name + "/tmp")
    #invoke_command(['mkdir', path + file_name + "/tmp"])
    no_log_status_output("mkdir " + path + file_name + "/err_messages")
    #invoke_command(['mkdir', path + file_name + "/err_messages"])
    no_log_status_output("mkdir " + path + file_name + "/commands_txt_output")
    #if no_fw_flag:
    no_log_status_output("mkdir " + path + file_name + "/firmware")
    #invoke_command(['mkdir', path + file_name + "/firmware"])
    no_log_status_output("mkdir " + path + file_name + "/pcie_files")
    #cables:
    if not no_cables_flag:
        no_log_status_output("mkdir " + path + file_name + "/cables")
    if asap_flag:
        no_log_status_output("mkdir " + path + file_name + "/asap")
        #invoke_command(['mkdir', path + file_name + "/asap"])

    if asap_tc_flag:
        no_log_status_output("mkdir " + path + file_name + "/asap_tc")
        #invoke_command(['mkdir', path + file_name + "/asap_tc"])
    if rdma_debug_flag:
        no_log_status_output("mkdir " + path + file_name + "/rdma_tool")
    # Create empty log files
    create_empty_log_files()
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
            print("\tGenerating sr_iov HTML page has started")
        initialize_html3(html3_flag)
        arrange_sriov_dicts()
        if verbose_flag and not generate_config_flag:
            print("\tGenerating sr_iov HTML page has ended")
    elif generate_config_flag:
        arrange_sriov_dicts()
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
    #generate sub chain commands in config file
    if generate_config_flag:
        command_flag_map = [["mstregdump/mstdump","no_fw/no_fw_regdumps"],["mstconfig/mlxconfig","no_mstconfig"],["mget_temp","no_cables"]\
        ,["mlxlink / mstlink","no_cables"],["mlxmcg","no_cables"]]
        for command in command_flag_map:
            is_command_allowed(command[0],command[1])
        for command in sub_chain_commands:
            related_flag = ""
            if command == "ibdiagnet":
                related_flag = "no_ib/ibdiagnet"
            elif command == "mlxfwmanager --online-query-psid":
                related_flag = "check_fw"
            elif command == "ib_write_bw_test" or command =="latency"or command =="perf_samples":
                related_flag= "no_ib/perf"
            elif command in fabric_commands_collection or command in fabric_multi_sub_commands_collection:
                related_flag= "no_ib"
            is_command_allowed(command,related_flag)
    # copy config file to .tgz output
    if config_file_flag:
        st , out = get_status_output("cp " + config_path + " " + path + file_name )
    # Major operations for creating the .json file
    if (verbose_flag == True and json_flag == True and not generate_config_flag):
        print("\t----------------------------------------------------")
        print("\tGenerating JSON file has started")
    if (json_flag == True and json_found == True):
        json_content = json.dumps(l1_dict, sort_keys=True)
        try:
            with open(path + file_name + "/" + file_name + ".json", 'w') as json_file:
                json_file.write(json_content)
            #print >> json_file, json_content
            #json_file = open(path + file_name + "/" + file_name + ".json", 'w')
            #print >> json_file, json_content
            #json_file.close()
        except:
            print("\tCould not open the file: " + file_name + "/" + file_name + ".json")

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
        os.system('mst stop > /dev/null 2>&1')
    else:
        if verbose_flag:
            print("The modules were loaded, hence, starting them via 'mst start'\n")
        os.system('mst start > /dev/null 2>&1')

    # Print generated config file message
    if generate_config_flag:
        config_dir = os.path.dirname(config_path)
        csv_writer = csv.writer(csvfile,lineterminator="\n")
        for key, value in config_dict.items():
            csv_writer.writerow([key, value["approved"],value["related flag"]])
        csvfile.close()
        print("\t----------------------------------------------------\n")
        print("Generating a new configuration file has ended successfully")
        print("The temporary destination directory is "+ config_dir +"\n")
        remove_unwanted_files()
        return
    if verbose_flag and not generate_config_flag:
        print("Creating tgz file has started")
    # Create result tar file

    if verbose_flag and not generate_config_flag:
        print("Creating tgz file has ended\n")
        print("------------------------------------------------------------\n")

    # Print Destination
    print_destination_out_file()
    # Create the output tar
    create_tar_file()
    # Remove all unwanted files
    remove_unwanted_files()

#------------parse interfaces flag value and map it to pci ,net and rdma devices-------------------------
specific_rdma_mlnx_devices = []
specific_pci_devices = []
specific_net_devices = []
specific_mst_devices = []
specific_cable_devices = []
def parse_interfaces_handler(interfaces):
    print('Running sysinfo-snapshot per specific interfaces ' + interfaces + "\n")
    interfaces = interfaces.split(',')
    global specific_rdma_mlnx_devices
    global specific_net_devices 
    global specific_pci_devices
    global specific_mst_devices
    global specific_cable_devices
    ibdev2netdev_mapping = {}
    ibdev2pcidev_mapping = {}
    pcidev2mstdev_mapping = {}
    mst2cabledev_mapping = {}
    # map mst devices to RDMA , and cable devices to mst
    cmd = "mst status -v"
    st, ibdev2mstdev_result = get_status_output(cmd)
    if st == 0:
        ibdev2mstdev_result = re.split("-----+",ibdev2mstdev_result)
        if(len(ibdev2mstdev_result) > 2):
            cables_result = ibdev2mstdev_result[3]
            ibdev2mstdev_result = ibdev2mstdev_result[2]
            lines = ibdev2mstdev_result.splitlines()
            for line in lines:
                row = re.split(r'\s+',line)
                if len(row) > 4:
                    pcidev2mstdev_mapping["0000:" + row[2]] = row[1].split('/')[-1]
            cables_result_lines = cables_result.splitlines()
            for line in cables_result_lines:
                mst = line.split("_cable")[0]
                if mst:
                    mst2cabledev_mapping[mst.strip()] = line.strip()
    # map PCI devices to RDMA     
    ibdev2pcidev = ibdev2pcidev_handler()
    ibdev2pcidevLines = ibdev2pcidev.splitlines()
    for line in ibdev2pcidevLines:
        line = line.split("==>")
        if len(line) > 1:
            pci_address = line[1].strip()
            mlnx_device = line[0].strip()
            ibdev2pcidev_mapping[mlnx_device] = pci_address
            #map net devices to RDMA 
            cmd = "find /sys/devices -path */" + pci_address + "/net"
            st, res = get_status_output(cmd)
            if st == 0 and res:
                cmd = "ls " + res.strip()
                st1, net_dev = get_status_output(cmd)
                if st1 == 0:
                    ibdev2netdev_mapping[mlnx_device] = net_dev.strip()
    #get all net,pci and rdma devices to validate entered interfaces
    rdma_st, all_rdma_dev = get_status_output("ls /sys/class/infiniband")
    if rdma_st == 0:
        all_rdma_dev = all_rdma_dev.splitlines()
        all_rdma_dev = [s.strip() for s in all_rdma_dev]
    net_st , all_net_dev = get_status_output("ls /sys/class/net")
    if net_st == 0:
        all_net_dev = all_net_dev.splitlines()
        all_net_dev = [s.strip() for s in all_net_dev]
    pci_st , lspci_out = get_status_output("lspci -d 15b3:")
    all_pci_dev = []
    if pci_st == 0:
        lspci_out = lspci_out.splitlines()
        for line in lspci_out:
            all_pci_dev.append("0000:" + line.strip().split()[0])
    all_mst_dev = []
    if os.path.isdir('/dev/mst'):
        all_mst_dev = os.listdir("/dev/mst")
    # check the entered interfaces 
    for interface in interfaces:
        interface = interface.strip()
        if "rdma" in interface or "mlx5" in interface:
            if(rdma_st == 0 and interface in all_rdma_dev):
                if interface in ibdev2netdev_mapping:
                    specific_net_devices.append(ibdev2netdev_mapping[interface])
                if interface in ibdev2pcidev_mapping:
                    specific_pci_devices.append(ibdev2pcidev_mapping[interface])
                specific_rdma_mlnx_devices.append(interface)
                if ibdev2pcidev_mapping[interface] in pcidev2mstdev_mapping:
                    specific_mst_devices.append(pcidev2mstdev_mapping[ibdev2pcidev_mapping[interface]])
                    if pcidev2mstdev_mapping[ibdev2pcidev_mapping[interface]] in mst2cabledev_mapping:
                        specific_cable_devices.append(mst2cabledev_mapping[pcidev2mstdev_mapping[ibdev2pcidev_mapping[interface]]])
            else:
                print(interface + " not found in rdma/mlnx_5 devices , please make sure you entered correct device \n")
        elif len(interface.split(":")) >= 2:
            if not interface.strip().startswith("0000:"):
                interface = "0000:" + interface
            if( pci_st == 0 and interface in all_pci_dev):
                specific_pci_devices.append(interface)
                keys = [key for key, value in ibdev2pcidev_mapping.items() if value == interface]
                if len(keys) > 0:
                    specific_rdma_mlnx_devices.append(keys[0])
                    if keys[0] in ibdev2netdev_mapping:
                        specific_net_devices.append(ibdev2netdev_mapping[keys[0]])
                if interface in pcidev2mstdev_mapping:
                    specific_mst_devices.append(pcidev2mstdev_mapping[interface])
                    if pcidev2mstdev_mapping[interface] in mst2cabledev_mapping:
                        specific_cable_devices.append(mst2cabledev_mapping[pcidev2mstdev_mapping[interface]])
            else:
                print(interface + " not found in pci devices , please make sure you entered correct device \n")
        elif "/dev/mst/" in interface:
            interface = interface.split("/")[-1]
            if interface in all_mst_dev:
                specific_mst_devices.append(interface)
                if interface in mst2cabledev_mapping:
                    specific_cable_devices.append(mst2cabledev_mapping[interface])
                keys = [key for key, value in pcidev2mstdev_mapping.items() if value == interface]
                if len(keys) > 0:
                    specific_pci_devices.append(keys[0])
                    ib_keys = [key for key, value in ibdev2pcidev_mapping.items() if value == keys[0]]
                    if len(ib_keys) > 0 :
                        specific_rdma_mlnx_devices.append(ib_keys[0])
                        if ib_keys[0] in ibdev2netdev_mapping:
                            specific_net_devices.append(ibdev2netdev_mapping[ib_keys[0]])
            else:
                print(interface + " not found in mst devices , please make sure you entered correct device \n")
        else:
            if net_st == 0 and interface in all_net_dev:
                keys = [key for key, value in ibdev2netdev_mapping.items() if value == interface]
                if len(keys) > 0:
                    specific_rdma_mlnx_devices.append(keys[0])
                    if keys[0] in ibdev2pcidev_mapping:
                        specific_pci_devices.append(ibdev2pcidev_mapping[keys[0]])
                        if ibdev2pcidev_mapping[keys[0]] in pcidev2mstdev_mapping:
                            specific_mst_devices.append(pcidev2mstdev_mapping[ibdev2pcidev_mapping[keys[0]]])
                            if pcidev2mstdev_mapping[ibdev2pcidev_mapping[keys[0]]] in mst2cabledev_mapping:
                                specific_cable_devices.append(mst2cabledev_mapping[pcidev2mstdev_mapping[ibdev2pcidev_mapping[keys[0]]]])
                specific_net_devices.append(interface)
            else:
                print(interface + " not found in net devices , please make sure you entered correct device \n")
    
def update_flags(args):
    global no_fw_flag
    global no_ib_flag
    global keep_info_flag
    global trace_flag
    global interfaces_flag
    global with_inband_flag
    global pcie_debug_flag
    global fsdump_flag
    global no_fw_regdumps_flag
    global no_cables_flag
    global no_mstconfig_flag
    global all_var_log_flag
    global json_flag
    global verbose_flag
    global verbose_count
    global ibdiagnet_flag
    global ibdiagnet_ext_flag
    global mtusb_flag
    global perf_flag
    global pcie_flag
    global check_fw_flag
    global generate_config_flag
    global config_file_flag
    global ufm_flag
    global isFile
    global csvfile
    global path
    global html_path
    global html2_path
    global html3_path
    global openstack_flag
    global asap_flag
    global asap_tc_flag
    global rdma_debug_flag
    global gpu_flag
    global config_dict
    global config_path
    global file_name
    global non_root
    global nvsm_dump_flag
    isFile = False
    if (args.config):
        config_file_flag = True
        config_path = args.config
        try:
            with open(config_path, 'r') as csvfile:
                reader = csv.reader(csvfile)
                next(reader)
                config_dict = {rows[0]:{"approved":rows[1],"related flag":rows[2]} for rows in reader}
            #e.g config_dict{COMMAND_CSV_HEADER: INVOKED_CSV_HEADER }
        except:
            print('Unable to read the configuration file. Please make sure that config file(config.csv) is in the same directory\n')
            parser.print_help()
            sys.exit(1)
    if (args.dir):
        path = args.dir
        html_file_name = ""
        if is_command_allowed("hostname") or generate_config_flag:
            hst, curr_hostname = no_log_status_output("hostname")
            html_file_name = curr_hostname.replace('\n', '-') + "-" + date_file
        else:
            html_file_name = "sysinfo-snapshot" + "-" + date_file
        file_name = get_json_file_name()
        html_path = path + file_name + "/" + html_file_name + ".html"
        html2_path = path + file_name + "/performance_tuning_analyze.html"
        html3_path = path + file_name + "/sr_iov.html"
        if (len(path) > 0):
            if (not path.endswith("/")):
                path = path + "/"
                html_path = path + file_name + "/" + html_file_name + ".html"
                html2_path = path + file_name + "/performance_tuning_analyze.html"
                html3_path = path + file_name + "/sr_iov.html"
            if (os.path.isfile(path[:-1]) == True):
                isFile = True
    if(args.non_root):
        non_root = True
    if(args.nvsm_dump):
        nvsm_dump_flag =True
    if (args.no_fw):
        no_fw_flag = True
    if (args.fsdump):
        fsdump_flag = True
    if (args.no_fw_regdumps):
        no_fw_regdumps_flag = True
    if (args.no_cables):
        no_cables_flag = True
    if (args.no_mstconfig):
        no_mstconfig_flag = True
    if (args.all_var_log):
        all_var_log_flag = True
    if (args.perf):
        perf_flag = True
    if (args.ibdiagnet_ext):
        ibdiagnet_flag = True
        ibdiagnet_ext_flag = True
    if (args.ibdiagnet):
        ibdiagnet_flag = True
    if (args.no_ib):
        no_ib_flag = True
    if (args.keep_info):
        keep_info_flag = True
    if (args.trace):
        trace_flag = True
    if (args.interfaces):
        interfaces_flag = True
        parse_interfaces_handler(args.interfaces)
    if (args.ufm):
        ufm_flag = True
    if (args.with_inband):
        with_inband_flag = True
    if (args.pcie_debug):
        pcie_debug_flag = True
    if (args.openstack):
        openstack_flag = True
    if (args.asap):
        asap_flag = True
    if (args.asap_tc):
        asap_tc_flag = True
    if (args.rdma_debug):
        rdma_debug_flag = True
    if (args.gpu):
        gpu_flag = True
    if (args.json):
        json_flag = True
    if (args.pcie):
        pcie_flag = True
    if (args.generate_config):
        generate_config_flag = True
        config_path = args.generate_config
        if not ( os.path.isdir(config_path)):
            try:
                csvfile = open(config_path, 'w+')
                csvfile.write("Generated by sysinfo-snapshot version " + version +" \n")
                fieldnames = [COMMAND_CSV_HEADER, INVOKED_CSV_HEADER,FLAG_RELATED_HEADER]
                config_file = csv.DictWriter(csvfile, fieldnames=fieldnames,lineterminator="\n")
                if (sys.version_info[0] == 2 and sys.version_info[1] < 7 ):
                    config_file.writerow({COMMAND_CSV_HEADER: COMMAND_CSV_HEADER,
                            INVOKED_CSV_HEADER: INVOKED_CSV_HEADER},{FLAG_RELATED_HEADER})
                else:
                    config_file.writeheader()
                config_dict = {}
            except PermissionError:
                print('Unable to create a configuration file due to pemissions, please make sure that you have the required acsses permission to the provided path. The path must be full path, including file name .\n')
                parser.print_help()
                sys.exit(1)
            except:
                print('Unable to create a configuration file .\n')
                parser.print_help()
                sys.exit(1)
        else:
            print('Unable to find configuration file. Please make sure that config file(config.csv) is in the provided directory\n')
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
        # Change Name: mst_commands_query_output --> mst_commands_query_output / i2c-mst_commands_query_output
        try:
            commands_collection.remove('mst_commands_query_output')
        except:
            pass
        commands_collection.extend(['mst_commands_query_output / i2c-mst_commands_query_output'])
        try:
            fw_collection.remove('mst_commands_query_output')
        except:
            pass
        fw_collection.extend(['mst_commands_query_output / i2c-mst_commands_query_output'])

def confirm_root():
    st, user = no_log_status_output('id -u')
    if (st != 0):
        print('Unable to distinguish user')
        sys.exit(1)
    if(user != '0'):
        if(non_root):
            print('Running as a non-root user. (--non_root flag was provided)\n')
        else:
            print('Running as a non-root user\nPlease switch to root user (super user) and run again.\n')
            parser.print_help()
            sys.exit(1)
    elif(non_root):
        print('Running as root user with a --non_root flag.\nPlease switch to non-root user or remove the --non_root flag.\n\nNote: the system will continue running as non-root.\n')

def execute(args):
    global len_argv
    global csvfile
    global config_file
    global config_dict
    global file_name
    update_flags(args)
    confirm_root()
    file_name = get_json_file_name()
    if args.pcie_debug:
        print('Running sysinfo-snapshot to generate PCIE debug info.')
        generate_pcie_debug_info()
    else:
        generate_output()

def config_callback(option, opt_str, value, parser):
    assert value is None
    value = DEFAULT_CONFIG_PATH

    for arg in parser.rargs:
        if arg:
            value = arg

    setattr(parser.values, option.dest, value)

def dir_callback(option, opt_str, value, parser):
    assert value is None
    value = DEFAULT_PATH

    for arg in parser.rargs:
        if arg:
            value = arg

    setattr(parser.values, option.dest, value)

def get_parsed_args():
    global parser

    if (sys.version_info[0] == 2 and sys.version_info[1] < 7 ):
        parser = OptionParser(prog='Sysinfo-snapshot', usage=' %prog version: ' + version + ' [options]'
                                                                        + "\n\tThe sysinfo-snapshot command gathers system information and places it into a tar file."
                                                                        + "\n\tIt is required to run this script as super user (root) and using python 2.7 or higher version")
        parser.add_option("-d", "--dir", dest="dir", default='/tmp/', action="callback", callback=dir_callback, help="set destination directory (default is /tmp/).")
        parser.add_option("-v", "--version", help="show the tool's version information and exit.", action='store_true')
        parser.add_option("-p", "--perf",  help="include more performance commands/functions, e.g. ib_write_bw and ib_write_lat.", action='store_true')
        parser.add_option("--ufm", help="add ufm logs to the output.", action='store_true')
        parser.add_option("--no_fw", help="do not add firmware commands to the output.", action='store_true')
        parser.add_option("--fsdump", help="add fsdump firmware command to the output.", action='store_true')
        parser.add_option("--no_fw_regdumps", help="disable regdumps firmware command.", action='store_true')
        parser.add_option("--no_mstconfig", help="disable mstconfig firmware command.", action='store_true')
        parser.add_option("--all_var_log", help="collect all logs in /var/log/ dir", action='store_true')
        parser.add_option("--no_cables", help="disable mlxlink, mget_temp, mlxmcg command that is related to cables.", action='store_true')
        parser.add_option("--mtusb", help="add I2C mstdump files to the output.", action='store_true')
        parser.add_option("--ibdiagnet", help="add ibdiagnet command to the output.", action='store_true')
        parser.add_option("--ibdiagnet_ext", help="add ibdiagnet ext command to the output.", action='store_true')
        parser.add_option("--with_inband", help="add in-band cable info to the output.", action='store_true')
        parser.add_option("--no_ib", help="do not add server IB commands to the output.", action='store_true')
        parser.add_option("--keep_info", help="do not delete logs that were gathered, even if sysinfo run is canceled in the middle. ", action='store_true')
        parser.add_option("--trace", help="gather /sys/kernel/debug/tracing/trace file even if the size is huge(more than 150 KB),\
                                        if the file not huge it will be gathered by defualt", action='store_true')
        parser.add_option('--interfaces', dest='interfaces' ,help='set List of interfaces either ETH netdev based or RDMA - mlx5 based that you want to run sysinfo on (comma separated list)')
        parser.add_option("--openstack", help="gather openstack relevant conf and log files", action='store_true')
        parser.add_option("--asap", help="gather asap relevant commands output", action='store_true')
        parser.add_option("--asap_tc", help="gather asap tc filter commands output", action='store_true')
        parser.add_option("--rdma_debug", help="gather rdma tool that comes with iproute2 commands output", action='store_true')
        parser.add_option("--gpu", help="gather Nvidia GPU commands", action='store_true')
        parser.add_option("--json", help="add json file to the output.", action='store_true')
        parser.add_option("--pcie", help="add pcie commands/functions to the output.", action='store_true')
        parser.add_option("--pcie_debug", help="generate only pcie debug info.", action='store_true')
        parser.add_option("--config", dest="config", action="callback", callback=config_callback, help="set the customized configuration file path including filename, to choose which commands are approved to run.\n"
                                                                                    + "In case a path is not provided, the default file name(config.csv) and it path are set for the same directory.")
        parser.add_option("--generate_config", dest="generate_config", action="callback", callback=config_callback, help="Generates configuration file under provided path,Path must be full path, including file name.\n"
                                                                                           +"Generated config file will include all the commands available in the script listed.\n By default all the commands that run will be marked as yes for execution, unless additional flag is required for them.\n"
                                                                                            + "In case a path is not provided, a default path is assumed, which is current directory with config.csv file name.")
        parser.add_option("--check_fw", help="check if the current adapter firmware is the latest version released, output in performance html file [Internet access is required]", action='store_true')
        parser.add_option("--verbose", help="first verbosity level, available if option is provided only once, lists sections in process.second verbosity level, available if option is provided twice, lists sections and commands in process.", action='count')
        parser.add_option("--non_root", help=" Allow the tool to run as non_root.", action='store_true')
        parser.add_argument("-t","--nvsm_dump" , help=" collect nvsm dump health.", action='store_true')
        (options, args)  = parser.parse_args()

        if (len(args) > 0) and ( not (options.dir) and not (options.config) and not (options.generate_config) ):
            parser.error("Incorrect number of arguments")
        return options
    else:
        import argparse
        parser = argparse.ArgumentParser(prog='Sysinfo-snapshot', usage=' %(prog)s version: ' + version + ' [options]'
                                                                    + "\n\tThe sysinfo-snapshot command gathers system information and places it into a tar file."
                                                                    + "\n\tIt is required to run this script as super user (root) and using python 2.7 or higher version.")
        parser.add_argument("-d", "--dir", nargs="?", const="/tmp/", default="/tmp/", help="set destination directory (default is /tmp/).")
        parser.add_argument("-v", "--version", help="show the tool's version information and exit.", action='store_true')
        parser.add_argument("-p", "--perf",  help="include more performance commands/functions, e.g. ib_write_bw and ib_write_lat.", action='store_true')
        parser.add_argument("--ufm", help="add ufm logs to the output.", action='store_true')
        parser.add_argument("--no_fw", help="do not add firmware commands to the output.", action='store_true')
        parser.add_argument("--fsdump", help="add fsdump firmware command to the output.", action='store_true')
        parser.add_argument("--no_fw_regdumps", help="disable regdumps firmware command.", action='store_true')
        parser.add_argument("--no_mstconfig", help="disable mstconfig firmware command.", action='store_true')
        parser.add_argument("--no_cables", help="disable mlxlink, mget_temp, mlxmcg command that is related to cables.", action='store_true')
        parser.add_argument("--all_var_log", help="collect all logs in /var/log/ dir ", action='store_true')
        parser.add_argument("--mtusb", help="add I2C mstdump files to the output.", action='store_true')
        parser.add_argument("--with_inband", help="add in-band cable info to the output.", action='store_true')
        parser.add_argument("--ibdiagnet_ext", help="add ibdiagnet ext command to the output.", action='store_true')
        parser.add_argument("--ibdiagnet", help="add ibdiagnet command to the output.", action='store_true')
        parser.add_argument("--no_ib", help="do not add server IB commands to the output.", action='store_true')
        parser.add_argument("--keep_info", help="do not delete logs that were gathered, even if sysinfo run is canceled in the middle. ", action='store_true')
        parser.add_argument("--trace", help="gather /sys/kernel/debug/tracing/trace file even if the size is huge(more than 150 KB),\
                                        if the file not huge it will be gathered by defualt", action='store_true')
        parser.add_argument('--interfaces',  nargs='?', help='set List of interfaces either ETH netdev based or RDMA - mlx5 based that you want to run sysinfo on(comma separated list)')
        parser.add_argument("--openstack", help="gather openstack relevant conf and log files", action='store_true')
        parser.add_argument("--asap", help="gather asap relevant commands output", action='store_true')
        parser.add_argument("--asap_tc", help="gather asap tc filter commands output", action='store_true')
        parser.add_argument("--rdma_debug", help="gather rdma tool that comes with iproute2 commands output", action='store_true')
        parser.add_argument("--gpu", help="gather Nvidia GPU commands", action='store_true')
        parser.add_argument("--json", help="add json file to the output.", action='store_true')
        parser.add_argument("--pcie", help="add pcie commands/functions to the output.", action='store_true')
        parser.add_argument("--pcie_debug", help="generate only pcie debug info.", action='store_true')
        parser.add_argument("--config", nargs="?", const=DEFAULT_CONFIG_PATH, help="set the customized configuration file path including the filename, to choose which commands are approved to run.\n"
                                                                                    + "In case a path is not provided, the default file name(config.csv) and it path are set for the same directory.")
        parser.add_argument("--generate_config", nargs="?", const=DEFAULT_CONFIG_PATH, help="Generates configuration file under provided path,Path must be full path, including file name.\n"
                                                                                           +"Generated config file will include all the commands available in the script listed.\n By default all the commands that run will be marked as yes for execution,unless additional flag is required for them.\n"
                                                                                            + "In case a path is not provided, a default path is assumed, which is current directory with config.csv file name.")
        parser.add_argument("--check_fw", help="check if the current adapter firmware is the latest version released, output in performance html file [Internet access is required]", action='store_true')
        parser.add_argument("--verbose", help="first verbosity level, available if option is provided only once, lists sections in process.second verbosity level, available if option is provided twice, lists sections and commands in process.", action='count')
        parser.add_argument("--non_root", help=" allow the tool to run as non-root.", action='store_true')
        parser.add_argument("-t","--nvsm_dump" ,help=" collect nvsm dump health.", action='store_true')
        args = parser.parse_args()
        return args

def main():
    parsed_args = get_parsed_args()
    if (parsed_args.version):
        print('Sysinfo-snapshot version: ' + version)
    else:
        execute(parsed_args)
if __name__ == '__main__':
    main()