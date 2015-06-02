#!/usr/bin/env python
"""
	Command Injection Module for Grabber v0.1
	Inspired by Romain Gaucher's Grabber - http://rgaucher.info
"""
import sys
from grabber import getContent_POST, getContent_GET
from grabber import getContentDirectURL_GET, getContentDirectURL_POST

from grabber import single_urlencode, partially_in, unescape

# order of the Command Injection operations
orderCommand = ["GREP","EXEC","EVAL"]


overflowStr = "" 
for k in range(0,512):
	overflowStr += '9'

def detect_commandInjection(output, ):
	listWords = ["GREP","EXEC","EVAL"]
	for wrd in listWords:
		if output.count(wrd) > 0:
			return True
	return False


def equal(h1,h2):
	if h1 == h2:
		return True
	return False

def generateOutput(url, gParam, instance,method,type):
	astr = "<commandInjection>\n\t<method>%s</method>\n\t<url>%s</url>\n\t<parameter name='%s'>%s</parameter>\n\t<type name='Command Injection Type'>%s</type>"  % (method,url,gParam,str(instance),type)
	if method in ("get","GET"):
		# print the real URL
		p = (url+"?"+gParam+"="+single_urlencode(str(instance)))
		astr += "\n\t<result>%s</result>" % p
	astr += "\n</commandInjection>\n"
	return astr

def generateOutputLong(url, urlString ,method,type, allParams = {}):
	astr = "<commandInjection>\n\t<method>%s</method>\n\t<url>%s</url>\n\t<type name='Command Injection Type'>%s</type>"  % (method,url,type)
	if method in ("get","GET"):
		# print the real URL
		p = (url+"?"+urlString)
		astr += "\n\t<result>%s</result>" % (p)
	else:
		astr += "\n\t<parameters>"
		for k in allParams:
			astr += "\n\t\t<parameter name='%s'>%s</parameter>" % (k, allParams[k])
		astr += "\n\t</parameters>"
	astr += "\n</commandInjection>\n"
	return astr



def process(url, database, attack_list):
	plop = open('results/commandInjection_GrabberAttacks.xml','w')
	plop.write("<CommandInjectionAttacks>\n")

	for u in database.keys():
		if len(database[u]['GET']):
			print "Method = GET ", u
			# single parameter testing
			for gParam in database[u]['GET']:
				defaultValue = database[u]['GET'][gParam]
				defaultReturn = getContent_GET(u,gParam,defaultValue)
				if defaultReturn == None:
					continue
				# check with the attack list
				for cmd in attack_list:
					tmpError = getContent_GET(u,gParam,cmd)
					if tmpError == None:
						continue
					if equal(defaultReturn.read(), tmpError.read()):
						basicError  = getContent_GET(u,gParam,'')
						overflowErS = getContent_GET(u,gParam,overflowStr)
						if basicError == None or overflowErS == None:
							continue
						if equal(basicError.read(), overflowErS.read()):
							for key in orderCommand:
								for instance in attack_list[key]:
									tmpError  = getContent_GET(u,gParam,instance)
									if tmpError == None:
										continue
									if equal(basicError.read(), tmpError.read()):
										# should be an error
										# print u,gParam,instance
										plop.write(generateOutput(u,gParam,instance,"GET",key))
						else:
							# report a overflow possible error
							#print u,gParam, "overflow"
							plop.write(generateOutput(u,gParam,"Overflow in Command Injection","GET","Overflow"))
					
			
		if len(database[u]['POST']):
			print "Method = POST ", u
			# single parameter testing
			for gParam in database[u]['POST']:
				defaultValue = database[u]['POST'][gParam]
				defaultReturn = getContent_POST(u,gParam,defaultValue)
				if defaultReturn == None:
					continue
				# check with the attack list
				for cmd in attack_list:
					tmpError = getContent_POST(u,gParam,cmd)
					if tmpError == None:
						continue
					if equal(defaultReturn.read(), tmpError.read()):
						basicError  = getContent_POST(u,gParam,'')
						overflowErS = getContent_POST(u,gParam,overflowStr)
						if basicError == None or overflowErS == None:
							continue
						if equal(basicError.read(), overflowErS.read()):
							for key in orderCommand:
								for instance in attack_list[key]:
									tmpError  = getContent_POST(u,gParam,instance)
									if tmpError == None:
										continue
									if equal(basicError.read(), tmpError.read()):
										# should be an error
										plop.write(generateOutput(u,gParam,instance,"POST",key))
						else:
							# report a overflow possible error
							plop.write(generateOutput(u,gParam,"Overflow in Command Injection","POST","Overflow"))
	plop.write("\n</CommandInjectionAttacks>\n")
	plop.close()
	return ""
