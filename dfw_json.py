import json
import os
import csv
import string
import time
import codecs
import requests
from base64 import b64encode
import getpass

nsxmip=raw_input('Enter NSXManager IP: ')
username=raw_input('Enter your AD account (e.g.ad\l0888880): ')
yourpass = getpass.getpass('Enter passowrd: ')
userandpass=username+":"+yourpass
userpass = b64encode(userandpass).decode("ascii")
auth ="Basic " + userpass
date = time.strftime("%Y-%m-%d-%H-%M-%S")
filename = "dfwrules_"+date+".json"
api_url = "https://" + nsxmip + "/api/4.0/firewall/globalroot-0/config"

#Get current working directory
cwd = os.getcwd()

def send_request():
    try:
        response = requests.get(
            url=api_url,
            verify=False,  
            headers={
                "Authorization": auth,
                "Content-Type": "application/json",
                "Accept":"application/json",
            },
            )
        print('Response HTTP Status Code: {status_code}'.format(status_code=response.status_code))
        if response.status_code == 403:
                print "***********************************************************************"
                print "WARNING: your username or password is wrong, please retry again!"
                print "***********************************************************************"
        if  response.status_code == 200:
                print "***********************************************************************"
                print "Your request is successful."
        dfwrules=response.text
        #ipnet=json.dumps(ipnet, indent=4)
        dfwFile = open(filename,'w')
        dfwFile.write(dfwrules)
        dfwFile.close()
    except requests.exceptions.RequestException:
        print('HTTP Request failed')
send_request()

csvfilename = "dfwrules_" + date +".csv"
csvfile = open(csvfilename, "w")
writer=csv.writer(csvfile)

# Two ways to open a file
#with open('./site1_dfwrules_2018-06-26-07-17-39.json', 'r') as f:
#    data = json.load(f)
fullpath = cwd + "/" + filename
f =codecs.open(fullpath, 'r', 'UTF-8')
data = json.load(f)
print type(data)

sections=data["layer3Sections"]["layer3Sections"]
#print type(sections)
#print "how many section in total: " 
#print len(sections)
sectionCount = len(sections)
#headers=['ruleId','name','sectionId','direction','disabled','sourceName','sourceType','destinationName','destinationType','serviceName','serviceType','protocolName','destinationPort','serviceValue','action','applied-to']
headers =['ruleId','name','sectionId','direction','disabled','source','destination','service','action','applied-to','logged']
writer.writerow(headers)
for i in range(sectionCount):
	section = sections[i]
	section_json = json.dumps(section, indent = 4)
	rule_list=section["rules"]
	#rules type is "list"
	#print "how many rules in this section: "
	ruleCount = len(rule_list)
	for h in range(ruleCount):
		rule = rule_list[h]
		rule_json = json.dumps(rule,indent = 4)
		# data type for "rule" is dict
		rlist = []
		rlist.append(rule["id"])
		try:
			rulename = rule["name"]
			rlist.append(rulename)
		except:
			rlist.append("n/a")
		rlist.append(rule["sectionId"])
		rlist.append(rule["direction"])
		rlist.append(rule["disabled"])

		#firewall rule source
		ruleSourceCSVLists = []
		if(rule.get("sources",0) > 0):
			ruleSources = rule["sources"]
			ruleSourceList= ruleSources["sourceList"]
			#print ruleSourceList
			for s in range(len(ruleSourceList)):
				ruleSourceCSVList = []
				ruleSourceType = ruleSourceList[s]["type"]
				ruleSourceValue = ruleSourceList[s]["value"]
				try:
					ruleSourceName = ruleSourceList[s]["name"]
					ruleSourceCSVList.append(ruleSourceName.encode("utf-8"))
					ruleSourceCSVList.append(ruleSourceValue.encode("utf-8"))
					#ruleSourceCSVList.append(ruleSourceType)
				except:
					#ruleSourceCSVList = ["n/a",ruleSourceValue,ruleSourceType]
					ruleSourceCSVList = ["n/a",ruleSourceValue.encode("utf-8")]
				ruleSourceCSVLists.append(ruleSourceCSVList)

		else:
			ruleSourceCSVLists = ['any','any']
		rlist.append(ruleSourceCSVLists)
		
		#firewall rule destionation	
		ruleDestinationCSVLists = []
                if(rule.get("destinations",0) > 0):
                        ruleDestinations = rule["destinations"]
                        ruleDestinationList= ruleDestinations["destinationList"]
                        #print ruleDestinationList
                        for s in range(len(ruleDestinationList)):
                                ruleDestinationCSVList = []
                                ruleDestinationType = ruleDestinationList[s]["type"]
                                ruleDestinationValue = ruleDestinationList[s]["value"]
                                try:
                                        ruleDestinationName = ruleDestinationList[s]["name"]
                                        ruleDestinationCSVList.append(ruleDestinationName.encode("utf-8"))
                                        ruleDestinationCSVList.append(ruleDestinationValue.encode("utf-8"))
                                        #ruleDestinationCSVList.append(ruleDestinationType)
                                except:
                                        #ruleDestinationCSVList = ["n/a",ruleDestinationValue,ruleDestinationType]
                                        ruleDestinationCSVList = ["n/a",ruleDestinationValue.encode("utf-8")]
                                ruleDestinationCSVLists.append(ruleDestinationCSVList)

                else:
                        ruleDestinationCSVLists = ['any','any']
                rlist.append(ruleDestinationCSVLists)

		#firewall service
		ruleServiceCSVLists = []
		if(rule.get("services",0) > 0):
			ruleServices = rule["services"]
                        ruleServiceList= ruleServices["serviceList"]
			for s in range(len(ruleServiceList)):
				ruleServiceCSVList =[]
                        	try:
                                	ruleServiceType = ruleServiceList[s]["type"]
                        	except:
                                	ruleServiceType = "n/a"
                        	try: 
                                	ruleServiceValue = ruleServiceList[s]["value"]
                        	except:
                                	ruleServiceValue = "n/a"
                        	#protocol name: tcp/udp/icmp
                        	try:
                                	ruleprotocolName = ruleServiceList[s]["protocolName"]
                        	except:
                                	ruleprotocolName = "n/a"
                        	#destinationPort
                        	try:
                                	ruledestinationPort = ruleServiceList[s]["destinationPort"]
                        	except:
                                	ruledestinationPort = "n/a"
                        	#serviceName
                        	try:
                                	ruleServiceName = ruleServiceList[s]["name"]
                        	except:
                                	ruleServiceName = "n/a"

				if ruleServiceName != "n/a":
					ruleServiceCSVList.append(ruleServiceName.encode("utf-8"))

				#if ruleServiceType != "n/a":
				#	ruleServiceCSVList.append(ruleServiceType.encode("utf-8"))
				
				if ruleprotocolName != "n/a":
					ruleServiceCSVList.append(ruleprotocolName.encode("utf-8"))
				
				if ruledestinationPort != "n/a":
					ruleServiceCSVList.append(ruledestinationPort.encode("utf-8"))
				
				if ruleServiceValue != "n/a":
					ruleServiceCSVList.append(ruleServiceValue.encode("utf-8"))
	
				ruleServiceCSVLists.append(ruleServiceCSVList)
                else:
			ruleServiceCSVLists = ['any']
                rlist.append(ruleServiceCSVLists)
		
		#firewall rule action:allow/deny/block
		ruleAction = rule["action"]
		rlist.append(ruleAction)
		
		#firewall rule applied to
		ruleApplied = rule["appliedToList"]
                ruleAppliedToList = ruleApplied["appliedToList"]
		appliedLists = []
                for n in range(len(ruleAppliedToList)):
			appliedList = [];
                        try:
                                ruleAppliedToListName = ruleAppliedToList[n]["name"]
				ruleAppliedToListValue = ruleAppliedToList[n]["value"]
				ruleAppliedToListType = ruleAppliedToList[n]["type"]
                        except:
                                ruleAppliedToListName = "n/a"
				ruleAppliedToListValue ="n/a"
                        	ruleAppliedToListType = "n/a"
                	appliedList.append(ruleAppliedToListName.encode("utf-8"))
                	#appliedList.append(ruleAppliedToListType.encode("utf-8"))
			appliedList.append(ruleAppliedToListValue.encode("utf-8"))			
			appliedLists.append(appliedList)
		rlist.append(appliedLists)
		#firewall rule log setting
		rlist.append(rule["logged"])
		#write rows into csv
		writer.writerow(rlist)

csvfile.close()
