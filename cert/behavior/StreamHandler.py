#!/usr/bin/python
#=======================================================
#
#               Stream Handle For Tshark Log 
#
#=======================================================
from __future__ import division
import os
import datetime

import TrafficAnalyser
import HighestLayerAnalyser
import HighestLayerJudge
import ElasticSearchClient


LogPath = '/home/qiuxuelong/Desktop/python/behavior/pcaplog'
#LogPath = 'C:\\Users\\Administrator\\Desktop\\python\\behavior\\pcaplog'


def LoopLogPath(filePath):

    files = os.listdir(filePath)
    for file in files:
        fileName = os.path.join(filePath, file)
        if os.path.isdir(fileName):
            LoopFilePath(fileName)
        else:
            fullPath = os.path.join(filePath, fileName)
	    
            print fullPath + ' is handling'
            LogHandle(fullPath)
    return


def LogHandle(fileName):
    
    f = open(fileName, 'r')
    while 1:
        line = f.readline().replace('\n', '')
        if not line:
            break

        StreamLog(line)	
    f.close()
    return   



def StreamLog(line):

    message = line.replace('"', '').split(',')
    leftIP          = message[0]		# ipSrc
    rightIP         = message[1]		# ipDst
    tcpLeftport     = message[2]		# tcpSrcport
    tcpRightport    = message[3]		# tcpDstport
    udpLeftport     = message[4]		# udpSrcport
    udpRightport    = message[5]		# udpDstport
    CapturedLen     = int(message[6])
    Layers    	    = message[7]
    TimeHeader 	    = message[8]
    TimeEnder	    = message[9]

    # format time
    date = (TimeHeader + ',' + TimeEnder)
    dd = datetime.datetime.strptime(date[0:(len(date) - 4)], '%b %d, %Y %H:%M:%S.%f')
    CapturedTime = dd.strftime('%Y-%m-%d %H:%M:%S.%f').replace(' ', '_')

    # highest layer calc
    HighestLayerAnalyser.calcProtoCount(Layers)
    
    # ignore arp,llmnr(part of no ip) protocols
    if leftIP == '' or rightIP == '':
        return

    # traffic analysis
    # open or close base yourself
    #TrafficAnalyser.TrafficAnalysis(leftIP, rightIP, CapturedLen, CapturedTime)

    # stream analysis
    StreamAnalysis(leftIP, rightIP, tcpLeftport, tcpRightport, udpLeftport, udpRightport, CapturedLen, Layers, CapturedTime)

    return


StreamMap = {}
def StreamAnalysis(leftIP, rightIP, tcpLeftport, tcpRightport, udpLeftport, udpRightport, CapturedLen, Layers, CapturedTime):
    global StreamMap
    
    # 1.tcp/udp 	: ok
    # 2.icmp/other	: N
    transport = ''
    highestLayer = ''
    key = ''
    key_reverse = ''
    if tcpLeftport != '' and tcpRightport != '':
        transport = 'tcp'
        highestLayer =  HighestLayerJudge.JudgeForHighestLayer(Layers, tcpLeftport, tcpRightport)
        
        key = leftIP + ':' + tcpLeftport + '->' + rightIP + ':' + tcpRightport
        key_reverse = rightIP + ':' + tcpRightport + '->' + leftIP + ':' + tcpLeftport
    elif udpLeftport != '' and udpRightport != '':
        transport = 'udp'
        highestLayer = HighestLayerJudge.JudgeForHighestLayer(Layers, udpLeftport, udpRightport)
        
        key = leftIP + ':' + udpLeftport + '->' + rightIP + ':' + udpRightport
        key_reverse = rightIP + ':' + udpRightport + '->' + leftIP + ':' + udpLeftport
    else:
        transport = 'N'
        highestLayer = 'N' 
        
        key = leftIP + '->' + rightIP
        key_reverse = rightIP + '->' + leftIP


    if StreamMap.has_key(key):
	# add for left IP
        if transport in StreamMap[key]['transport']:
	    pass
	else:
            StreamMap[key]['transport'] = StreamMap[key]['transport'] + '_' + transport
        
	if highestLayer in StreamMap[key]['highestLayer']:
	    pass
	else:
            StreamMap[key]['highestLayer'] = StreamMap[key]['highestLayer'] + '_' + highestLayer

        StreamMap[key]['leftBytes'] = StreamMap[key]['leftBytes'] + CapturedLen          # need long type???
        StreamMap[key]['leftPackets'] = StreamMap[key]['leftPackets'] + 1

        StreamMap[key]['endTime'] = CapturedTime
    elif StreamMap.has_key(key_reverse):
        # add for rightIP
        if transport in StreamMap[key_reverse]['transport']:
	    pass
	else:
            StreamMap[key_reverse]['transport'] = StreamMap[key_reverse]['transport'] + '_' + transport
        
	if highestLayer in StreamMap[key_reverse]['highestLayer']:
	    pass
	else:
            StreamMap[key_reverse]['highestLayer'] = StreamMap[key_reverse]['highestLayer'] + '_' + highestLayer

        StreamMap[key_reverse]['rightBytes'] = StreamMap[key_reverse]['rightBytes'] + CapturedLen
        StreamMap[key_reverse]['rightPackets'] = StreamMap[key_reverse]['rightPackets'] + 1

        StreamMap[key_reverse]['endTime'] = CapturedTime
    else:
        # add new key 
        StreamMap[key] = {'transport'         : transport,	# str
                          'highestLayer'      : highestLayer,   # str
                          'leftBytes'         : CapturedLen,	# int
                          'leftPackets'       : 1,
                          'rightBytes'        : 0,
                          'rightPackets'      : 0,
                          'startTime'         : CapturedTime,	# str
                          'endTime'           : ''}
    return


def StreamStore():
    global StreamMap

    for key, value in StreamMap.items():
        keys = key.split('->')
        leftIP = keys[0].split(':')[0]
        leftPort = keys[0].split(':')[1]
        rightIP = keys[1].split(':')[0]
        rightPort = keys[1].split(':')[1]

	# for human look        
        newKey = leftIP + '->' + rightIP
        newValue = leftPort + ','
        newValue = newValue + rightPort + ','
        newValue = newValue + value['transport'] + ','
        newValue = newValue + value['highestLayer'] + ','
        newValue = newValue + humanFormat(value['leftBytes'] + value['rightBytes']) + ','
        newValue = newValue + str(value['leftPackets'] +  value['rightPackets']) + ','
        newValue = newValue + humanFormat(value['leftBytes']) + ','
        newValue = newValue + str(value['leftPackets']) + ','
        newValue = newValue + humanFormat(value['rightBytes']) + ','
        newValue = newValue + str(value['rightPackets']) + ','
        newValue = newValue + value['startTime'] + ','
        newValue = newValue + value['endTime'] + ','
        AddElement(newKey, newValue)
        
        # 1. key need change to sip,sport,dip,dport,cause to EK
        # 2. dont have log file, and just for EK store
	tmpjson = {'_index'	: 'stream',
		   '_type'	: 'analysis',
		   '_source'	: {'leftIP'		: leftIP,
				   'leftPort' 		: leftPort,
				   'rightIP' 		: rightIP,
				   'rightPort' 		: rightPort,
				   'transport' 		: value['transport'],
				   'highestLayer' 	: value['highestLayer'],
				   'allBytes' 		: humanFormat(value['leftBytes'] + value['rightBytes']),
				   'allPackets' 	: str(value['leftPackets'] + value['rightPackets']),
				   'leftBytes' 		: humanFormat(value['leftBytes']),
				   'leftPackets'	: str(value['leftPackets']),
				   'rightBytes' 	: humanFormat(value['rightBytes']),
				   'rightPackets' 	: str(value['rightPackets']),
				   'startTime' 		: value['startTime'],
				   'endTime' 		: value['endTime']}
		}
	ElasticSearchClient.putData(tmpjson)
	tmpjson = {}
	
    return


def humanFormat(sum):
    if sum <= 1024:
    	return str(sum) + ' Bytes'

    if 1024 < sum <= (1024 * 1024):
   	tmp = str(sum / 1024)
    	v = tmp.split('.')
    	value = v[0] + '.' + v[1][0:2]
    	return value + ' KB'

    if (1024 * 1024) < sum:
    	tmp = str(sum / (1024*1024))
    	v = tmp.split('.')
    	value = v[0] + '.' + v[1][0:2]
    	return value + ' MB'


# key: sip->dip
# value: ports,tcp,http,..
IPTableMap = {}
def AddElement(key, value):
    global IPTableMap

    if IPTableMap.has_key(key):
        IPTableMap[key] = IPTableMap[key] + ';' + value
    else:
        IPTableMap[key] = value   # create a new time

    return


def IPTableMapStore():
    global IPTableMap

    f = open('iptable.csv', 'a')
    f.write('leftIP->rightIP,leftPort, rightPort, transport, highestLayer, allBytes, allPackets, leftBytes, leftPackets, rightBytes, rightPackets, startTime, endTime\n')
    
    for key, value in IPTableMap.items():
        tmp = ''
        tmp = key + '\n'
        for v in value.split(';'):	# has cache in some case
            tmp = tmp + ',' + v + '\n'  # for excel format
        f.write(tmp)
    f.close()
    return


if __name__ == '__main__':
    print 'sss'

    LoopLogPath(LogPath)

    StreamStore()
    IPTableMapStore()
    
    TrafficAnalyser.FlushLog()
    HighestLayerAnalyser.flush2Log()

    # for last data to es
    ElasticSearchClient.flush2ES()
    print 'over'

