# /usr/bin/python
import pyshark
import ast
import uuid
import geoip2.database
import json
import os
import time
import traceback

from threading import Timer
from IPy import IP
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch import helpers


# http://blog.csdn.net/xiaoxinwenziyao/article/details/49471977
es = Elasticsearch('http://127.0.0.1')



def makeSessionId():
    import md5, time, base64, string
    m = md5.new()
    m.update(str(datetime.now()))
    return string.replace(base64.encodestring(m.digest())[:-3], '/', '$')


# http://blog.sina.com.cn/s/blog_1358eca6d0102w1ul.html
# http://my.oschina.net/u/2242064/blog/601389
cache = []
def write2ES(jsonData):
    global cache

    try:
        if len(cache) >= 10000:		
	    #es.bulk(body=cache, index='packet', doc_type='PlugX_DNS')	
	    helpers.bulk(es,cache)	
	    cache = []
        else:
	    buf = {"_index": "packet", "_type": "PlugX_DNS"}	
	    buf["_source"] = jsonData
	    cache.append(buf)	
	    buf = {}
    except Exception, e:
	print "write2ES"
	print Exception, e
	exstr = traceback.format_exc()
        print exstr
    return


# for last data
def flush2ES():
    global cache
   
    try: 
        if len(cache) > 0:
	    helpers.bulk(es, cache)
            cache = []
	    print "has flush last data to ES"	
    except Exception, e:
	print "flush2ES"
	exstr = traceback.format_exc()
	print exstr
    return



def TakeElementsToES(pkt, fileName):

    layer_len = len(pkt.layers) 
    try:
        time_string = pkt.sniff_timestamp
        timestamp = ast.literal_eval(time_string)
        time_obj = str(datetime.fromtimestamp(timestamp))
    	
	pkt_len = pkt.length
        tmp = {	'author'	: 'qiuxuelong', 
	       	'@timestamp'	: time_obj, 
		'layer_len' 	: layer_len, 
		'layers' 	: pkt.frame_info.protocols, 
		'highest_layer'	: pkt.highest_layer,
		'fileName'	: fileName,
		'captured_length': pkt.captured_length}
   
        for i in range(0, layer_len):
            tmp.update(pkt.layers[i]._all_fields)    
        if tmp.has_key(''):
            del tmp['']

	# replace . to _
        json2es = {}
        tmp_ = {}
        for key in tmp:
	    if '.' in key:
	        key_ = key.replace(".", "_")
	        tmp_[key_] = tmp[key]
            else:
                tmp_[key] = tmp[key]
            json2es.update(tmp_)
        tmp_ = {}
        tmp = {}    
        
	#print(json2es["tcp_flags"])
        json2es['tcp_flags'] = '0x0000' # i don't know why

        #res = es.index(index="packet", doc_type='PlugX_DNS', body=json2es)
    	write2ES(json2es)
    except Exception,e:
	print "TakeElementsToES function"
        print Exception,e
	exstr = traceback.format_exc()
        print exstr
    return


AllPackets = 0
def HandleFoo(fpath, fileName):
    global AllPackets

    cap = pyshark.FileCapture(fpath, keep_packets=False)
    sum = 0
    try:
	#cap.apply_on_packets(TakeElementsToES, timeout=86400) # one day 86400sprint(dir(cap))
	for pkg in cap:
	   sum = sum + 1   
	   TakeElementsToES(pkg, fileName)

        print(fpath + " get packets: " + str(sum))
	AllPackets = AllPackets + sum
    except Exception, e:
        print "handleFoo function"
	print Exception, e
	exstr = traceback.format_exc()
	print exstr
    finally:
	sum = 0    
    return


def main():
    index = 0
    
    for root,dirs,files in os.walk('/home/qiuxuelong/Desktop/python/testDir'):
	for file in files:
            fpath = root + os.sep + file
	    index = index + 1	    
		
	    try:	
	   	print(str(fpath) + " is handling, process is:" + str(index) + "/" + str(len(files)))
	    	HandleFoo(fpath, file)
    	    except Exception, e:
		print "main error"
		exstr = traceback.format_exc()
		print exstr
    return


if __name__ == '__main__':

    start = time.time()
    main()
    flush2ES() 

    print "====================================="
    print "cost time:" + str(time.time() - start) + " seconds"
    print "All Packtets num:" + str(AllPackets)
