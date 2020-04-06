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

4 Specific Requirements:
The followings are the server/system requirements to run the script:
* Python installed
* Linux based OS
* Root (super user) privileges
NOTE: The tool doesn't change any module status during runtime, except for the 'mst module'. If the 'mst module' is stopped, the tool loads it via 'mst start' and revert it to it's initial status via 'mst stop'.

5 Usage:
1. Untar the file by invoking: tar -zxvf sysinfo sysinfo-snapshot-<version>.tgz
2. Run the following command (as admin):
#./sysinfo-snapshot.py
3. Extract the tar file from the default directory: /tmp.
4. Open the relevant html/text files.

5.1 Script Flags \
	There are many flags (options) for the user to refer to and add. Please see the list of flags below (5.1.1 to 5.1.18). \
5.1.1	d|--dir\
	By default, the destination directory is /tmp. The destination directory can be changed using -d|--dir flags/options. If the\
     destination       directory does not exist, the script automatically creates it.\
5.1.2	v|--version\
     show the tool's version information and exit.\
5.1.3	--no_fw\
     do not add firmware commands to the output.\
5.1.4	--fsdump\
     add fsdump firmware command to the output.\
5.1.5	--pcie\
     By default, the PCIE commands/functions are not added to the output. They can be added by adding the '--pcie' flag, e.g. 'lspci -\ 
     vvvxxxxx'.\
5.1.6	--config\
    set the customized configuration file path, to choose which commands are approved to run.\
    In case a path is not provided, the default file(config.csv) path is for the same directory.\
5.1.7	--generate_config\
    Set the file path of the generated configuration file, by default all commands are approved to be invoked. \
    In case a path is not provided, the default file(config.csv) path is for the same directory\
5.1.8	--mtusb\
    By default, I2C firmware related server commands/functions are not added to the output. They can be added to the output by
    providing the '--mtusb' flag.\
5.1.9	--with_inband\
    add in-band cable info to the output.\
5.1.10	-no_ib\
    By default, IB commands are added to the output. These commands can be removed from the output by providing the flag '-no_ib'. \
5.1.11	--openstack\
    gather openstack relevant conf and log files\
5.1.12	--asap\
    gather asap relevant commands output\
5.1.13	--asap_tc\
    gather asap tc filter commands output\
5.1.14	--ibdiagnet\
    By default, the 'ibdiagnet' command is not added to the output. It can be added by providing the '--ibdiagnet' flag. \
5.1.15	--json\
    By default, the JSON output file is not generated. It can be added to the output by providing the '--json' flag. To have the JSON \
    output file, make sure the json python module is installed. \
5.1.16	-p|--perf\
     By default, the "Performance tuning analyze" html file is added to the output. This html file dumps the performance status \
     according to the Performance Tuning for Mellanox Adapters. In addition, it contains the output of the tool 'mlnx_tune'. If you add\ 
     the '-p|' or the '--perf' flag, the output of the tests below is added to the html output: \
     ib_write_bw\
     ib_write_lat \
5.1.17	--check_fw\
     This flag checks if the current adapter firmware is the latest version released. The expected output is in the performance html \
     file (Internet access is required).\
5.1.18	--verbose\
     first verbosity level, available if option is provided only once, lists sections in process.second verbosity level,\
     available if option is provided twice, lists sections and commands in process.\
5.1.19	--pcie_debug\
     Generate only PCIE debug information\
