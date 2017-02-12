#!/usr/bin/python
import requests
from base64 import b64encode 
import getpass
username=raw_input('Enter your CORPAU account (e.g.corpau\l0888880): ')
yourpass = getpass.getpass('Enter passowrd: ')
userandpass=username+":"+yourpass
userpass = b64encode(userandpass).decode("ascii")
auth ="Basic " + userpass
def send_request():

    try:
        response = requests.get(
            url="https://10.138.80.28/api/2.0/services/securitygroup/lookup/virtualmachine/vm-69",
            verify=False,  
            headers={
                "Authorization": auth,
                "Content-Type": "application/xml",
            },
            )
        print('Response HTTP Status Code: {status_code}'.format(status_code=response.status_code))
        #print('Response HTTP Response Body: {content}'.format(content=response.content))
	if response.status_code == 403:
		print "***********************************************************************"
		print "WARNING: your username or password is wrong, please retry again!"
		print "***********************************************************************"	
        if  response.status_code == 200:
		print "***********************************************************************"
		print('Response HTTP Response Body: {content}'.format(content=response.content))
	member=response.text
        vm_sg_member = open('vm_sg.xml','w')
        vm_sg_member.write(member)
        vm_sg_member.close()
    except requests.exceptions.RequestException:
        print('HTTP Request failed')
send_request()
