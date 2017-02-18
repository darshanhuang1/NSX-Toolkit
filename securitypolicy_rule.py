#!/usr/bin/python
from bs4 import BeautifulSoup
import requests

print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "This tool is to provide firewall rules information around a specific security polciy"
print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "\n"
# Author: David Zhang
# Contact: davidzg@au1.ibm.com

#section 1: get the session ID
sp_file = raw_input("Enter your security policy XML file: ")
securitypolicy = open(sp_file,"r")
contents = securitypolicy.read()
soup = BeautifulSoup(contents,'xml')
wrongSG = False
rule_id = 0
for child in soup.securityPolicy:
	key = child.name
	if key == "name":
		secp_name = child.string
		print "+++++++++++++++++++++++++++++++++++++++++"
		secp_name = "Securtity Policy Name: " + secp_name
		print secp_name
	if key == "securityGroupBinding":
		for child in  soup.securityPolicy.securityGroupBinding:
			nextkey = child.name
			if nextkey == "name":
				sg_name = child.string
				sg_name = "This Security Policy has been linked to the Security Group: " + sg_name
				print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
				print sg_name
				print "******************************************************************"
				print "******************************************************************"
				print "\n"
for child in  soup.securityPolicy.actionsByCategory.action:
	actionkey = child.name
	if actionkey == "name":
		rule_id = rule_id +1
		str_ruleid = str(rule_id)
		print "+++++++++++++++++++++++++++++++"
		rulename = child.string
		rulename ="Rule Name for Firewall Rule " +str_ruleid +" :" + rulename
		print rulename
	if actionkey == "direction":
		direct = "Direction:"+ child.string
		print "+++++++++++++++++++++++++++++++"
		print direct
		print "\n"
	if actionkey == "secondarySecurityGroup":
		for child in soup.securityPolicy.actionsByCategory.action.secondarySecurityGroup:
			secondarySecurityGroupkey = child.name
			if secondarySecurityGroupkey == "name":
				print "+++++++++++++++++++++++++++++++"
				remotesg= child.string
				remotesg= "Remote SecurityGroup: " + remotesg
				print remotesg
	if actionkey == "applications":
		applicationgroup_ifany = child.find("applicationGroup")
		if applicationgroup_ifany != None:
			for child in  soup.securityPolicy.actionsByCategory.action.applications.applicationGroup:
				applicationgroupkey = child.name
				if applicationgroupkey == "name":
					service = child.string
					print "++++++++++++++++++++++++++++++++++++++"
					service = "Service: " + service
					print service
		else:
			for child in  soup.securityPolicy.actionsByCategory.action.applications.application:
				applicationkey = child.name
				if applicationkey == "name":
					service = child.string
					print "++++++++++++++++++++++++++++++++++++++"
					service = "Service: " + service
					print service


for sibling in soup.securityPolicy.actionsByCategory.action.find_next_siblings():
	for child in sibling:		
		actionkey = child.name
        	if actionkey == "name":
                	rule_id = rule_id +1
                	str_ruleid = str(rule_id)
                	print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                	rulename = child.string
                	rulename ="Rule Name for Firewall Rule " +str_ruleid +" :" + rulename
                	print rulename
			print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        	if actionkey == "direction":
                	direct = "Direction:"+ child.string
                	print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                	print direct
			print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++"
			print "\n"
		if actionkey == "secondarySecurityGroup":
			remotesg= child.contents[13].get_text()
			remotesg= "Remote SecurityGroup: " + remotesg
			print remotesg
		if actionkey == "applications":
			applicationgroup_ifany = child.find("applicationGroup")
			if applicationgroup_ifany != None:
				#print child.applicationGroup.contents
				print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++"
				service = child.applicationGroup.contents[13].get_text()
				service = "Service: " + service
				print service
			else:
				print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++"
				service = child.application.contents[13].get_text()
				service = "Service: " + service
				print service
