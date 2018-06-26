#!/usr/bin/python
#==================================================================
#
#       $:vim /etc/profile
#       $:export PYTHONDONTWRITEBYTECODE=x      # delete .pyc file
#       $:source /etc/profile 
#
#==================================================================
import os
import urllib2
import json
import time
import traceback
import threading
import sys
from sys import path

path.append('/home/qiuxuelong/Desktop/python/ioc/PyLib')
import confloader

import FrameAnalyser
import Log

URL = "http://localhost:9200/packet/_search?"


# for load data from elasticsearch by page
def loadData(url):
    try:
        response = urllib2.urlopen(url).read()
        data = json.loads(response)
    
        if data["timed_out"] != "False":
	    return data
        else:
	    # return null data
	    print("loadData get timed_out error")
 	    return {}
    except Exception, e:
	print Exception, e


def calcTotalSize():
    global URL

    murl = URL + "size=1" 
    data = loadData(murl)
 	
    print("all totals num is:" + str(data['hits']['total']))
    return  data["hits"]["total"] 


PAGESIZE = 10000
def handleESData():
    global URL
    global PAGESIZE

    length = calcTotalSize()
    #length = 5000000			# for test

    # load conf info
    #PAGESIZE = confloader.getParameters('PAGESIZE')

    times = length / PAGESIZE		# pages
    remainSize = length % PAGESIZE	# last block num
   
    for i in range(times + 1):
	murl = ''
        if i < times:
 	    murl = URL + "size=" + str(PAGESIZE) + "&from=" + str(i * PAGESIZE)
	else:
	    murl = URL + "size=" + str(remainSize) + "&from=" + str(i * PAGESIZE) 

	data = ''
	data = loadData(murl)
	collectInfo(data)

	print murl	
	time.sleep(2)   


def collectInfo(data):
    global DOMAINS    

    try:
    	for hit in data['hits']['hits']:
            source =  hit['_source']
       
	    # look at here
	    FrameAnalyser.Analysis(source)	    

    except Exception, e:
	print "collection:"
	exstr = traceback.format_exc()
        print exstr
    return


# use elasticsearch's web api.not python es client
def fetchByESClient():
    # we can search the data value like this
    # _source="false"
    # search_type="count"
    # size="1000"
    # fields={"ip_addr","ip_src_host"} # cause ip_addr is unindexed filed, so cant search
    #res = es.search(index="packet",doc_type="PlugX_DNS",_source="false",search_type="count",fields={"ip_addr"})

    #res = es.search(index="packet",doc_type="PlugX_DNS",_source="true",size="1",from="2")
    #res = es.search(index="packet",doc_type="PlugX_DNS",body={"query": {"term": {"ip_addr":"192.168.17.14"}}})
    print("fetchByESClient")


def createLogDirectory():
    # create directory
    if not os.path.exists("Log"):
        os.mkdir("Log")
     

if __name__ == "__main__":
   
    # create dir
    createLogDirectory()


    # fetch data from elasticsearch and handle them
    start = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
    handleESData()
    print("start time:" + start)
    print("end time:" + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))))


    Log.FlushLog()
