from elasticsearch import Elasticsearch
from elasticsearch import helpers
import re


PATH = "fast.log"
PAGE = 1000
reip = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d]):\d{1,5}\s->\s(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d]):\d{1,5}')
SDIP = {}

es = Elasticsearch('http://127.0.0.1')

def handleFile():
    global SDIP

    file = open(PATH)
    while 1:
	line = file.readline()
	if not line:
	    break
	
	message = line.split('[**]')[1].split(']')
	detectMessage = message[1]
	
	for ip in reip.findall(line):
    	    #print ">>>", ip
	    sip = ip.split(':')[0]
	    dip = ip.split(' ')[2].split(':')[0]
	    dport =  ip.split(':')[2]	

	    ipKey = sip + ":" + dip + ":" + dport
	    if SDIP.has_key(ipKey):
		SDIP[ipKey].append(detectMessage)	# add
		SDIP[ipKey] = list(set(SDIP[ipKey]))	# distinct
	    else:
		SDIP[ipKey] = [detectMessage]		# add
	    
		
def show():
    global SDIP
	
    for key, value in SDIP.items():
	print '==================='
	print 'ips:' + key
	print 'classes:' + str(len(value))
	print value

def log2Json():
    jsonData = []

    for key, value in SDIP.items():
	tempKey = key.split(':')
	
	sip = tempKey[0]
	dip = tempKey[1]
	dport = tempKey[2]
	classes = str(len(value))
	
	buf = {"_index": "fastlog", "_type": "suricata"}
	mjson = {'sip':sip, 'dip': dip, 'dport': dport, 'classes': classes, 'message': value}
    	buf['_source'] = mjson
	jsonData.append(buf)
	
    return jsonData

# may by pieces
def log2ES():
    data = log2Json()
    
    try:
	helpers.bulk(es, data)
    except Exception, e:
	print "log2ES Exception"
	print Exception, e    


if __name__ == "__main__":
    handleFile()
	
    log2ES()

    print 'over...'
