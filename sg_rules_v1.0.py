from bs4 import BeautifulSoup
import requests

print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "This tool is to provide firewall rules information around a specific security group"
print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "\n"
# Author: David Zhang
# Contact: davidzg@au1.ibm.com

#section 1: get the session ID
dfwrules = "./dfwrules_20161120.xml"
print "Please be patient! The tool is loading the NSX DFW DB"
dfwrules_infile = open(dfwrules,"r")
contents = dfwrules_infile.read()
soup = BeautifulSoup(contents,'xml')
wrongSG = False
def sg_check():
	#print "+++++++Please Type In Your Security Group Name+++++++++"
	securitygroup = raw_input()
	# reformat the End user input
	securitygroup = securitygroup.replace(' ','') 
	securitygroup = securitygroup.lower()
	print "+++++++++++++++++++++++++++++++++++++"
	print "\n"
	print "\n"
	# initialize the value of SGName check
	wrongSG = False
	# Check if the end user provided SG Name is correct or not
	for child in soup.firewallConfiguration.layer3Sections:
		sectionid = child['id']
		sectiongroup = child['name']
		sgname = sectiongroup.replace(' ','')
		sgname = sgname.replace('SGSection:','')
		sgname = sgname.lower()
		if securitygroup in sgname:
			wrongSG = True
			break
		else:
			continue
	#return wrongSG and sectionID from the function
	return wrongSG, sectionid
while wrongSG == False:
	print "\n"
	print "Now please type in the name of security group. Or you just provided the wrong security group name, please check and retry again."
	print "**********************************NOTE******************************************" 
	print "the security group name is OpenStack Security group name which includes UUID."
	print "********************************************************************************"
	wrongSG, sectionid = sg_check()
	


#Section 2: Make a API call to NSX manager to get secion.xml file



# Section 3: Get all firewall rules from the SG section xml file"
sectionfile =  "section"+ sectionid + ".xml"
print sectionfile
section_infile = open(sectionfile,"r")
section_xml = section_infile.read()
soup = BeautifulSoup(section_xml,'xml')
contents = section_infile.read()
print "\n"
print "\n"
i = 0 # define i as Rule Number
for child in soup.section:
	i = i +1
	str_i = str(i) # Change the rule no from int to string
 	RuleNo = "Rule-No:" + str_i
        print RuleNo
	comment = child['id'] # Get the NSX rule id
	ruleid = "NSX Rule-ID: " + comment
	print ruleid
	# create the firewall rules
	print "======================Source======================"
	source_ifany = child.find("source")
        if source_ifany == None: #verify if the source attribute is existed or not
                print "ANY"
	else:
		print child.source.contents[0].get_text()
	print "====================Destination==================="
	dest_ifany = child.find("destination")
	if dest_ifany == None:
		print "ANY"
	else:
		print child.destination.contents[0].get_text()
	print "====Protocol===="
	dest_ifany = child.find("destination")
        if dest_ifany == None:
                print "ANY"
	else:
		print child.services.protocolName.text
        print "====PortNumber==="
        dest_ifany = child.find("destination")
	destport_ifany = child.find("destinationPort")
        if dest_ifany == None:
                print "ANY"
	elif	child.service.protocolName.text == "ICMP":
		print child.services.subProtocolName.text
	elif 	destport_ifany == None:
		print "ANY"
	else:
		print child.services.destinationPort.text

	print "++++++++++++++++++++++++++++++++++++++++++++++++++"
	print "\n"
	
        
