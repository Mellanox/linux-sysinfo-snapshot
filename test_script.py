
import subprocess
import sys

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


if __name__ == '__main__':
    interface_array_eth = ["enp175s0d1", "eno1", "eno2", "enp59s0f1", "enp94s0f1"]
    interface_array_ib = ["ib0", "ib1", "ib2"]
    command_array_2_7 = [
        "python sysinfo-snapshot.py -p --mtusb --ibdiagnet --no_ib --pcie  --verbose --verbose -fw --json -d /tmp/",
        "python sysinfo-snapshot.py -p --mtusb --ibdiagnet --pcie  --verbose --verbose -fw --json -d /tmp/new/ ",
        "python sysinfo-snapshot.py",
        "python sysinfo-snapshot.py -test",
        "python sysinfo-snapshot.py -p",
        "python sysinfo-snapshot.py --check_fw",
        "python sysinfo-snapshot.py --mtusb -fw",
        "python sysinfo-snapshot.py --ibdiagnet ",
        "python sysinfo-snapshot.py --no_ib",
        "python sysinfo-snapshot.py --pcie",
        "python sysinfo-snapshot.py -fw",
        "python sysinfo-snapshot.py --json",
        "python sysinfo-snapshot.py -d /tmp/",
        "python sysinfo-snapshot.py --verbose --verbose",
        "python sysinfo-snapshot.py -p  --ibdiagnet --no_ib --pcie  --verbose --verbose -fw --json" ,
        "python sysinfo-snapshot.py -p  --ibdiagnet --pcie  --verbose --verbose -fw" ,
        "python sysinfo-snapshot.py -p --ibdiagnet --no_ib --pcie  --verbose --verbose -fw --json" ,
        "python sysinfo-snapshot.py -p  --ibdiagnet --pcie  --verbose --verbose -fw "    
	]
    command_array_3_6 = [
        "python3.6 sysinfo-snapshot.py -p --mtusb --ibdiagnet --no_ib --pcie  --verbose --verbose -fw --json -d /tmp/",
        "python3.6 sysinfo-snapshot.py -p --mtusb --ibdiagnet --pcie  --verbose --verbose -fw --json -d /tmp/new/ ",
        "python3.6 sysinfo-snapshot.py",
        "python3.6 sysinfo-snapshot.py -test",
        "python3.6 sysinfo-snapshot.py -p",
        "python3.6 sysinfo-snapshot.py --check_fw",
        "python3.6 sysinfo-snapshot.py --mtusb -fw",
        "python3.6 sysinfo-snapshot.py --ibdiagnet ",
        "python3.6 sysinfo-snapshot.py --no_ib",
        "python3.6 sysinfo-snapshot.py --pcie",
        "python3.6 sysinfo-snapshot.py -fw",
        "python3.6 sysinfo-snapshot.py --json",
        "python3.6 sysinfo-snapshot.py -d /tmp/",
        "python3.6 sysinfo-snapshot.py --verbose --verbose",
        "python3.6 sysinfo-snapshot.py -p --ibdiagnet --no_ib --pcie  --verbose --verbose -fw --json" ,
        "python3.6 sysinfo-snapshot.py -p --ibdiagnet --pcie  --verbose --verbose -fw" ,
        "python3.6 sysinfo-snapshot.py -p --ibdiagnet --no_ib --pcie  --verbose --verbose -fw --json" ,
        "python3.6 sysinfo-snapshot.py -p --ibdiagnet --pcie  --verbose --verbose -fw "
    ]

    for interface in interface_array_eth:
        get_status_output("timeout 10s ifconfig " + interface + " up")
    for interface in interface_array_ib:
        get_status_output("timeout 10s ifconfig " + interface + " up")  

    test_num = 1
    for command in command_array_2_7:
        print "Command running - " + command
        if command == command_array_2_7[14]:
            for interface in interface_array_eth:
                get_status_output("timeout 10s ifconfig " + interface + " down")
        if command == command_array_2_7[16]:
            for interface in interface_array_eth:
                get_status_output("timeout 10s ifconfig " + interface + " up")
            for interface in interface_array_ib:
                get_status_output("timeout 10s ifconfig " + interface + " down")
    
        st, test_output = get_status_output("timeout 600s " + command)
        if st != 0 :
            with open("/tmp/errors_" + str(test_num) + ".txt", 'w') as errors_file:
                errors_file.write(command + " \n\n" + test_output + " \n\n" )

        with open("/tmp/output_" + str(test_num) + ".txt", 'w') as output_file:
            output_file.write(command + "\n\n" + test_output + " \n\n")
        test_num += 1

    for interface in interface_array_eth:
        get_status_output("timeout 10s ifconfig " + interface + " up")
    for interface in interface_array_ib:
        get_status_output("timeout 10s ifconfig " + interface + " up")            
    
    ###################################################################################
    for command in command_array_3_6:
        print "Command running - " + command
        if command == command_array_3_6[14]:
            for interface in interface_array_eth:
                get_status_output("timeout 10s ifconfig " + interface + " down")
        if command == command_array_3_6[16]:
            for interface in interface_array_eth:
                get_status_output("timeout 10s ifconfig " + interface + " up")
            for interface in interface_array_ib:
                get_status_output("timeout 10s ifconfig " + interface + " down")
    
        st, test_output = get_status_output("timeout 600s " + command)
        if st != 0 :
            with open("/tmp/errors_" + str(test_num) + ".txt", 'w') as errors_file:
                errors_file.write(command + " \n\n" + test_output + " \n\n" )

        with open("/tmp/output_" + str(test_num) + ".txt", 'w') as output_file:
            output_file.write(command + "\n\n" + test_output + " \n\n")
        test_num += 1
    print "Finished testing"