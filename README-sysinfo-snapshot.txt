Python sysinfo-snapshot 
Mellanox Technologies LTD.


- The sysinfo-snapshot command gathers system information and places it into a tar file.
- It is required to run this script as super user (root).

sysinfo-snapshot.py can be invoked, in case it is in the current path, as following: ./sysinfo-snapshot.py
There are many flags (options) that you can provide as below:

- By default the destination directory is /tmp 
* The destination directory can be changed using -d|--dir flags/options
* If the destination directory does not exist, the script will create it.

- Firmware related server commands/functions are split into two:
1) commands/functions that are added to the output by default: [mstregdump-func, mlxcables]
2) commands/functions that are not added to the output by default: [itrace, mlxmcg -d, fw_ini_dump, mlxdump]
* The later commands/functions can be added to the output by providing one of the flags/options -fw|--firmware
* You may consider little delay if -fw|--firmware is provided

- By default I2C firmware related server commands/functions are not added to the output
* They can be added to the output by providing the flag/option '--mtusb' 

- By default IB commands are added to the output
* These commands can be removed from the output by providing the flag/option -no_ib
* You may consider running the script with the -no_ib flag especially when the firmware is stuck
  which leads to hanging when invoking any ib command, e.g. ibstat
* You can check if the firmware is stuck by reviewing dmesg

- By default 'ibdiagnet' command is not added to the output
* It can be added by providing '--ibdiagnet' flag

- By default JSON out file is not generated
* JSON file can be added to the output by providing the flag/option --json
* If you consider having JSON out file, you should make sure json python module is installed
  Elsewise the script will print a proper message and generate the out directory without any JSON file. 

- By default "Performance tuning analyze" external file will be added to the
  output. This html file dumps the performance status according to "Mellanox
  Performance Tuning Guide", in addition it contains the output of the tool
  mlnx_tune which is effective starting from mlnx_ofed 3.0.0 and on.
* ib_write_bw and ib_write_lat are part of this HTML, they are not run by default though
* -p|--perf need to be provided in order to add these two tests to the oputput

- By default "SR-IOV" external file will be added to the output in case sr-iov
  is activated (virtual functions exist).
  This html file dumps all sr-iov related commands/internal files

- The tool doesn't change any module status at all during runtime, except for:
* mst module, if the mst module was stopped before, the tool will load it via 'mst start'
* and revert it to it's initial status via 'mst stop'

OUT TAR FILE: <path>/sysinfo-snapshot-<version>-<hostname>-<year><month><day>-<hour><minutes>.tgz

Which includes 1 directory with the name sysinfo-snapshot-<version>-<hostname>-<year><month><day>-<hour><minutes>

sysinfo-snapshot-<version>-<hostname>-<year><month><day>-<hour><minutes> content:
- sysinfo-snapshot-<version>-<hostname>-<year><month><day>-<hour><minutes>.html
- sysinfo-snapshot-<version>-<hostname>-<year><month><day>-<hour><minutes>.json (not by default)
- err_messages directory's content:
	- dummy_functions - contains all not found commands
	- dummy_paths - contains all not existing internal files (/paths)
	- dummy_external_paths - contains all not existing external files (/paths)
	- ... 
- Directory ibdiagnet - contains all ibdiagnet command out files (included only if IB fabric and -no_ib flag is not provided)
- Other Helping Files, e.g. external files.


For any clarifications or features requests, please contact Mellanox Support Department
Mellanox Call Center
+1 408.916.0055

Toll-free (USA only)
86-Mellanox (8663552669)

Email: support@mellanox.com


Copyright ©2015-2017 by Mellanox Technologies LTD.
All rights reserved. This tool or any portion thereof
may not be reproduced or used in any manner whatsoever
without the express written permission of the publisher.

