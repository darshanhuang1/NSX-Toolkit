from bs4 import BeautifulSoup
import requests
import time

print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "This tool is to create security group base"
print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "\n"
# Author: David Zhang
# Contact: davidzg@au1.ibm.com

sg = "./securitygroup.xml"
print "Please be patient! We are creating the security group list for you!"
sg_infile = open(sg,"r")
contents = sg_infile.read()
soup = BeautifulSoup(contents,'xml')
date = time.strftime("%Y-%m-%d")
print date
filename = "sgnamelist_"+date+".txt"
def sg_check():
	for child in soup.list.securitygroup:
		key = child.name
        	if key == "name":
                	sg = child.string
			sgname = open(filename,'a+')
                        sgname.write(sg)
                        sgname.write("\n")
                        sgname.close()
	for sibling in soup.list.securitygroup.find_next_siblings():
        	for child in sibling:
                	key = child.name
                	if key == "name":
                        	sg = child.string
				sgname = open(filename,'a+')
        			sgname.write(sg)
				sgname.write("\n")
				sgname.close()
sg_check()

