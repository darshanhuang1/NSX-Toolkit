from bs4 import BeautifulSoup
print "+++++++Please Type In Your SG Membership XML Filename+++++++++"
myxml = raw_input()
infile = open(myxml,"r")
contents = infile.read()
soup = BeautifulSoup(contents,'xml')
#print (soup.prettify())
#for child in soup.securityGroups.securityGroups:
	#for child in soup.securityGroups.securityGroups.securitygroup:
		#item = child.name
                #value = child.string
                #name1 = child.text
                #print item
                #print "+++++++++++++++++++++++++++"
                #print value
for child in soup.securityGroups.securityGroups.securitygroup:
        key = child.name
	if key == "name":
      		print child.string
for sibling in soup.securityGroups.securityGroups.securitygroup.find_next_siblings():
	for child in sibling:
		key = child.name
         	if key == "name":
                	print child.string
#print (soup.securityGroups.securityGroups.get_text())

