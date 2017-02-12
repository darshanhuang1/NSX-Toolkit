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
date = time.strftime("%Y-%m-%d-%H-%M-%S")
print date
filename = "sgnamelist_"+date+".txt"
def sg_check():
	for child in soup.list.securitygroup:
		key = child.name
		count = 0
        	if key == "name":
                	sg = child.string
			sgname = open(filename,'a+')
                        sgname.write(sg)
                        sgname.write("\n")
                        sgname.close()
		if key == "member":
			count = count+1
	if count ==0:
		print "There is not any member in this SG"
		print "\n"	
	for sibling in soup.list.securitygroup.find_next_siblings():
		count =0
        	for child in sibling:
                	key = child.name
                	if key == "name":
                        	sg = child.string
				sgname = open(filename,'a+')
        			sgname.write(sg)
				sgname.write("\n")
				sgname.close()
			if key == "member":
                        	count = count+1
                if count==0:
			print sg
			print "there is not any member in this SG"
			print "\n"
sg_check()

