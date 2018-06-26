#!/usr/bin/python

#================================================
#
#	collection data, like data store
#
#================================================

ProtocolBean = {}
'''
	FrameID
	SendBytes
	ReceiveBytes
	SendPackets
	ReceivePackets
	StartTime
	EndTime
	KeepTime
	SrcIP
	DstIP
	udp_srcport,tcp_srcport
	udp_dstport,tcp_dstport
	PayLoad
	Layers
'''


def addItem(key, value):
    global ProtocolBean
    
    ProtocolBean[key] = value
    return    


def getItem(key):
    global ProtocolBean

    if ProtocolBean.has_key(key):
	return ProtocolBean[key]
    return ''


def clearItem():
    global ProtocolBean

    ProtocolBean = {}    
    return


if __name__ == '__main__':
    print 'sss'
