Python sysinfo-snapshot 
Mellanox Technologies LTD.


- The sysinfo-snapshot command gathers system information and places it into a tar file.
- It is required to run this script as super user (root).

sysinfo-snapshot.py can be invoked, in case it is in the current path, as following: ./sysinfo-snapshot.py
There are many flags (options) that you can provide as below:

- By default the destination directory is /tmp 
* The destination directory can be changed using -d|--dir flags/options
* If the destination directory does not exist, the script will create it.

- By default firmware related server commands/functions are not added to the output
* Firmware commands/functions are [itrace, mlxmcg -d, fw_ini_dump, mstregdump-func]
* These commands/functions can be added to the output by providing one of the flags/options -fw|--firmware
* You may consider little delay if -fw|--firmware is provided, since some of them call sleep function for 10 seconds per each Mellanox lspci device

- By default I2C firmware related server commands/functions are not added to the output
* They can be added only if both '--firmware' and '--mtusb' were provided 

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


OUT TAR FILE: <path>/sysinfo-snapshot-<version>-<hostname>-<year><month><day>-<hour><minutes>.tgz

Which includes 1 directory with the name sysinfo-snapshot-<version>-<hostname>-<year><month><day>-<hour><minutes>

sysinfo-snapshot-<version>-<hostname>-<year><month><day>-<hour><minutes> content:
- sysinfo-snapshot-<version>-<hostname>-<year><month><day>-<hour><minutes>.html
- sysinfo-snapshot-<version>-<hostname>-<year><month><day>-<hour><minutes>.json (not by default)
- dummy_functions - contains all not found commands
- dummy_paths - contains all not existing internal files (/paths)
- Directory ibdiagnet - contains all ibdiagnet command out files (included only if IB fabric and -no_ib flag is not provided)
- Other Helping Files, e.g. external files.


For any clarifications or features requests, please contact Mellanox Support Department
Mellanox Call Center
+1 408.916.0055

Toll-free (USA only)
86-Mellanox (8663552669)

Email: support@mellanox.com


Copyright © 2015 by Mellanox Technologies LTD.
All rights reserved. This tool or any portion thereof
may not be reproduced or used in any manner whatsoever
without the express written permission of the publisher.

