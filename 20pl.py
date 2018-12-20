import subprocess, os
import sys

my_env = os.environ.copy()
my_env["OS_USERNAME"] = "csbauditor.gen"
#my_env["OS_AUTH_URL"] = "https://cloud-rcdn-1.cisco.com:5000/v3"
my_env["OS_PASSWORD"] = "CowGoM00!"
#my_env["OS_PROJECT_NAME"] = "deepika-2-os"
my_env["OS_USER_DOMAIN_NAME"] = "cisco"
my_env["OS_PROJECT_DOMAIN_NAME"] = "cisco"

with open('regionsP3.txt','r') as regions:
	for region in regions:
		details = region.strip().split(" ")
		regionName = details[0]
		regionurl = details[1]
		
		pListFile = regionName + '.txt'
#		print regionName
#		print regionurl
#		print pListFile
		my_env["OS_AUTH_URL"] = regionurl
		file = open(pListFile,'a+')
		
		pListCmd = 'openstack project list -f value'
		pListprocess = subprocess.Popen(pListCmd, shell= True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,env=my_env)
		
		with open(pListFile,'r') as filecheck:
			firstline = filecheck.read()
			if len(firstline) == 0:
				for newline in pListprocess.stdout:
					file.write(newline)
			else:
				for newline in pListprocess.stdout:
					for line in file:
						if newline in line:
							break
					else:
						file.write(newline)