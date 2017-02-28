#!/usr/bin/python -tt

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# Author	: Nizar Swidan, nizars@mellanox.com
# Version	: 1.0.0
# Release Date	: 15-NOV-2015
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

import sys
import os

myfile = ""
exists = False

def main():
	global exists
	global myfile

	if len(sys.argv) < 2:
		print ("Please provide sysinfo-snapshpt output")
		sys.exit(1)
	myfile = sys.argv[1]

	if myfile.endswith(".tgz"):
		if os.path.exists(myfile.split(".tgz")[0]):
			exists = True
		os.system("tar zxvf " + myfile + " > /dev/null 2>&1")
		myfile = myfile.split(".tgz")[0]
	else:
		exists = True
			
	with open(myfile + "/" + myfile + ".html") as f:
		data = f.read()
		ofed_info = data.split("ofed_info -s</h2><p>")[1].split("</p>")[0]
		os_info = data.split("/etc/issue</h2><p>")[1].split("</p>")[0]
		print "ofed_info -s\n" + ofed_info + "\n\nos_info\n" + os_info	

	if not exists:
		os.system("rm -rf " + myfile) 

if __name__=='__main__':
	main()

