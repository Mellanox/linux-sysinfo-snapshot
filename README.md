# linux-sysinfo-snapshot
Linux Sysinfo Snapshot

1. Objective

Automated sysinfo-snapshot tool is designed to take a snapshot of all the configuration and relevant information on the server and Mellanox's adapters.

2. Description
The Sysinfo Snapshot is a python script that gathers system information and places it into a tar file.

3. Script Expected Output:
By default, the followings are the expected file output when running the script:
* "Performance tuning analyze" html file: this file dumps the performance status.
* "Sysinfo snapshot" html file: this file dumps the server info and status.
* "SR-IOV" html file: this file dumps all sr-iov related commands/internal files.
* "commands_txt_output" folder which contains output of each command in a separate file.
* "Status-log-sysinfo-snapshot" A log which contains each command invoked on the host, if it passed / failed and time taken.
* commands_txt_output directory - a collection of commands output saved into files
* "err_messages" folder which contains error message logs.

4 Specific Requirements:\
The followings are the server/system requirements to run the script:
* Python installed- minimum required Python version 2.6
* Linux based OS
* Root (super user) privileges
NOTE: The tool doesn't change any module status during runtime, except for the 'mst module'. If the 'mst module' is stopped, the tool loads it via 'mst start' and revert   \
it to it's initial status via 'mst stop'.

5.1 Running the tool without a configuration file:
Running Sysinfo Snapshot without a configuration file will gather the relevant information and   \
configuration on the server and Nvidia's adapters, By adding additional flags, the user will have more   \
control on the generated output, for more detailed information regarding the flags, please refer to  section 5.3 - Script flags.

To run the script without a configuration:
1. Untar the file by invoking - tar -zxvf sysinfo-snapshot-<version>.tgz
2. Run the following command (as admin):
#./sysinfo-snapshot.py <relevant flags> 
3. Extract the tar file from the default directory: /tmp/
4. Open the relevant html/text files 

5.2 Running the tool with a configuration file 
Running Sysinfo Snapshot with a configuration file will provide a more advanced control on the
gathered information and configuration on the server and Nvidia's adapters, the configuration is 
intended to list all commands that are gathered by the Sysinfo Snapshot tool.
Modifying the configuration file will allow the user to control which commands are allowed to run on 
the host running the tool.
	
To run the script with a configuration file:
1. Untar the file by invoking - tar -zxvf sysinfo-snapshot-<version>.tgz
2. Run the following command (as admin):
#./sysinfo-snapshot.py --generate_config
3. Review the generated config.csv file and modify the Approved column based on the requirements
4. Run the following command (as admin):
#./sysinfo-snapshot.py –config ./config.csv
5. Extract the tar file from the default directory: /tmp/
6. Open the relevant html/text files

5.3 Script Flags \
 There are many flags (options) for the user to refer to and add. Please see the list of flags below (5.1.1 to 5.1.23). \
5.3.1 d|--dir  \
By default, the destination directory is /tmp. The destination directory can be changed using -d|--dir  \
flags/options. If the destination directory does not exist, the script automatically creates it. \
5.3.2 v|--version \
show the tool's version information and exit. \
5.3.3 -p|--perf  \
By default, the "Performance tuning analyze" html file is added to the output. This html file dumps the  \
performance status according to the Performance Tuning for Mellanox Adapters. In addition, it  \
contains the output of the tool 'mlnx_tune'. If you add the '-p|' or the '--perf' flag, the output of the  \
tests below is added to the html output:  \
ib_write_bw \
ib_write_lat \
5.3.4 --ufm  \
Add ufm logs to the output. \
5.3.5 --no_fw \
do not add firmware commands to the output. \
5.3.6 --fsdump \
add fsdump firmware command to the output. \
5.3.7 --mtusb \
By default, I2C firmware related server commands/functions are not added to the output. They can be  \
added to the output by providing the '--mtusb' flag. \
5.3.8 --with_inband \
add in-band cable info to the output. \
5.3.9 --ibdiagnet_ext \
Add ibdiagnet ext command to the output. \
5.3.10 --ibdiagnet \
By default, the 'ibdiagnet' command is not added to the output. It can be added by providing the '-- ibdiagnet' flag. \
5.3.11 --no_ib \
By default, IB commands are added to the output. These commands can be removed from the output  \
by providing the flag '--no_ib'. \
5.3.12 --openstack  \
gather openstack relevant conf and log files. \
5.3.13 --asap \
gather asap relevant commands output. \
5.3.14 --asap_tc \
gather asap tc filter commands output. \
5.3.15 --rdma_debug \
gather rdma tool that comes with iproute2 commands output. \
5.3.16 --gpu \
gather Nvidia GPU commands. \
5.3.17 --json \
By default, the JSON output file is not generated. It can be added to the output by providing the  \
'--json' flag. To have the JSON output file, make sure the json python module is installed. \
5.3.18 --pcie \
By default, the PCIE commands/functions are not added to the output. They can be added by adding  \
the '--pcie' flag, e.g. 'lspci -vvvxxxxx'. \
5.3.19 --pcie_debug \
Generate only PCIE debug information. \
5.3.20 --config \
set the customized configuration file path including the filename, to choose which commands are  \
approved to run. In case a path is not provided, the default file name(config.csv) and it path are set  \
for the same directory. \
5.3.21 --generate_config  \
Generates configuration file under provided path, Path must be full path, including file name. \
Generated config file will include all the commands available in the script listed. By default, all the  \
commands that run will be marked as yes for execution, unless additional flag is required for them. \
In case a path is not provided, a default path is assumed, which is current directory with config.csv file  \
name. \
5.3.22 --check_fw \
This flag checks if the current adapter firmware is the latest version released. The expected output is  \
in the performance html file (Internet access is required). \
5.3.23 --verbose \
first verbosity level, available if option is provided only once, lists sections in process.second verbosity \
level, vailable if option is provided twice, lists sections and commands in process. \
5.3.24 -t | --non_root \
Allow the tool to run as non-root user, commands/files that require root permissions are missing.\
5.3.25 -t | --nvsm_dump \
Collect nvsm dump health.\

6. Generate Config – Guidelines

6.1 Usage  \
Adding --generate_config will generate a csv configuration file which includes all the commands  \
available in the script listed. \
By default, all the commands that run will be marked as yes for execution, unless additional flag is  \
required for them. \
Modifying the configuration file is done by only changing the values under "approved" column.  \
The allowed values - "yes" or "no". \
To run the sysinfo-snapshot using the modified configuration file, please add the --config flag. \
Note: Adding additional flags while generating the configuration file will not change the  \
defualt allowed values.

6.2 Generated config file format \
• First line has the sysinfo-snapshot generated version,  \
e.g sysinfo-snapshot version 3.7.0.

• csv configuration file format. \

Commands: generated automatically by the system \
Approved: "is" or "no" \
related flag: By default all the commands that run will be marked as yes for execution \
              generated automatically by the system. please refer to Script Flags for more information.  \
Files and directories are annotated with "file: " prefix, to help identifying them.

6.3 Functions \
Generated functions invoke multiple related queries that are gathered from the customer server.

ibdev2pcidev: Map each IB device in /sys/class/infiniband/ to it PCI device \
ethtool_all_interfaces: Gather the output of ethtool command on all relevant ethernet interfaces  \
        with each of the following flags:"-i", "-g", "-a", "-k", "-c", "-T", "--show-priv-flags", "-n", "-l", "-x", "-S" \
ib_write_bw_test: Invoke relevant ib_write_bw test \
Installed_packages: Invoke relevant command: rpm -qa --last / dpkg --list / pkglist \
mst_commands_query_output: From each relevant mst device: \
	• Gather mstregdump / mstdump command three consecutive runs  \
	• Gather mlxconfig/mstconfig with -e flag \
	• Gather flint/mstflint with q and dc flags  \
	• Gather mlxdump with pcie_uc --all flag \
ethtool_version: Gets the ethtool version installed /usr/sbin/ethtool or /sbin/ethtool \
asap_parameters: Run the following: \
	• ovs-dpctl dump-flows -m \
	• tc qdisc show \
	• ovs-vsctl get Open_vSwitch . other_config \
	• ovs-vsctl show \
	• ovs-ofctl dump-flows \
asap_tc_information: Run the following: \
	tc -s filter show dev \
show_irq_affinity_all: From each relevant mst device, gather show_irq_affinity.sh output \
yy_MLX_modules_parameters: Gather relevant parameters from: /sys/module/mlx*/parameters/ \
yy_ib_modules_parameters_handler: Gather relevant IB parameters from: /sys/module/ib_*/parameters/ \
proc_net_bonding_files: Gather files from /proc/net/bonding/ \
sys_class_net_files: Gather files from /sys/class/net/ \

teamdctl_state / teamdctl_state_view / eamdctl_config_dump / teamdctl_config_dump_actual  \
teamdctl_config_dump_noports: ther relevant teamdctl output

show_pretty_gids: Gather relevant gids and gid_attrs information from: /sys/class/infiniband \
devlink_handler: Gather relevant output from each relevant devlink reporter \
ufm_logs: Gather relevant information from: /opt/ufm/scripts/vsysinfo output \
sys_class_net_ecn_ib: Gather relevant ecn files from /sys/class/net \
performance_lspci: Gather relevant information from: lspci, mstflint/flint for providing  \
performance advise in the performance html file  \
hyper_threading / core_frequency: Gather relevant information from: /proc/cpuinfo \
ib_mc_info_show / Multicast_Information: Gather relevant information from saquery output \
sm_version: Gather opensm version installed: rpm -qa | grep opensm / dpkg -l | grep opensm \
perfquery_cards_ports: Gather relevant information from perfquery command output 
ib_find_bad_ports / ib_find_disabled_ports_handler: Gather relevant information from iblinkinfo command output  \
ib_switches_FW_scan_handler: Gather relevant information from ibswitches and ibdiagnet commands output  \
ib_topology_viewer: Gather relevant information from ibnetdiscover command output  \
get_numa_node_sys_files_exclude_uevent_files: Invoke the following command:  \
	"find /sys | grep numa_node | grep -v uevent"  \
se_linux_status: Gather SELinux configuration from command getenforce output  \
ip_forwarding: Gather relevant information from:  \
	/proc/sys/net/ipv4  \
	/proc/sys/net/ipv6/  \
perf_samples: Gather relevant perf samples information from:  \
	ethtool -s and /sys/class/infiniband/device counters  \
mget_temp_query: Gather information from mget_temp command output  \
rdma_tool: Gather the output of: /opt/mellanox/iproute2/sbin/rdma  \
		command with each of the following flags:  \
		"resource show","resource show cm_id","resource show qp","res show cq"  \
roce counters: Gather relevant counter and hardware counter information from Infiniband   \
	devices listed under - /sys/class/infiniband  \
	/sys/class/infiniband/<ib_device>/ports/<portcounter>  \
USER: Gather relevant information from logname command output  \
congestion_control_parameters: Gather relevant counter and hardware counter information from Infiniband  devices listed under:  \
	/sys/kernel/debug/mlx5  \
networkManager_system_connections: Gather NetworkManager information:  \
	systemctl status NetworkManager  \
	get relevant connection files from:  \
	/etc/NetworkManager/system-connections/
 
Note, Commands that are not listed as function in the above list are invoked directly as a shell command. 
