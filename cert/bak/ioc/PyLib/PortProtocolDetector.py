#!/usr/bin/python
#=================================================
#
#         Port Protocol White Analyser
#
#=================================================
import DataBean
import confloader

PATH_Port_Protocol_White_List = '/home/qiuxuelong/Desktop/python/ioc/conf/port2protocol.yml'


BUFFER = {}
def getPortProtocolWhiteList():
    global PATH_Port_Protocol_White_List
    global BUFFER

    f = open(PATH_Port_Protocol_White_List, 'r')
    lines = f.readlines()
    for line in lines:
        mline = line.strip()
        if ('#' in mline) or (mline == ''):
            pass
        else:
            key = mline.split('=')[0].strip()
            value = mline.split('=')[1].strip()

            BUFFER[key] = value
    f.close()
    return


def PortProtocolCheck():
    global BUFFER

    if len(BUFFER) == 0:
	getPortProtocolWhiteList()

    key = ''
    tmp_sport = ''
    tmp_dport = ''
    if DataBean.getItem('transport_layer').upper() == 'UDP':
	key = 'UDP'
	tmp_sport = 'UDP-' + DataBean.getItem('udp_srcport')
	tmp_dport = 'UDP-' + DataBean.getItem('udp_dstport')
    else:
	key = 'TCP'
	tmp_sport = 'TCP-' + DataBean.getItem('tcp_srcport')
        tmp_dport = 'TCP-' + DataBean.getItem('tcp_dstport')

    # ETH:IP:UDP -> ignore
    # ETH:IP:TCP -> ignore handle and bye packets
    if DataBean.getItem('layers').upper() == 'ETH:IP:TCP':
	return

    # for eth:ip:icmp:ip:udp
    if (DataBean.getItem('layers').upper().startswith('ETH:IP:UDP')) or (DataBean.getItem('layers').upper().startswith('ETH:IP:TCP')):
    	layers = DataBean.getItem('layers').upper().split(key + ":")[1].split(':')
    	for layer in layers:
	    if BUFFER.has_key(layer):
	        if ((BUFFER[layer].find(tmp_sport) < 0) and (BUFFER[layer].find(tmp_dport)) < 0):
		    PortProtoLog(layer)	
	    else:
	        pass

    return


#sip_dip_proto,times
PortProtoDict = {}
PortProtoDictMaxLength = 10000 # 10k
def PortProtoLog(layer):
    global PortProtoDict
    global ProtProtoDictMaxLength

    sip = DataBean.getItem('ip_src')
    dip = DataBean.getItem('ip_dst')
    
    key = sip + '_' + dip + '_' + layer
    if PortProtoDict.has_key(key):
	PortProtoDict[key] = PortProtoDict[key] + 1
    else:
	if len(PortProtoDict) ==  PortProtoDictMaxLength:
	    PortProtoStore()
	    PortProtoDict = {}	    	    
    
	PortProtoDict[key] = 1
    return
	

titleHasWrite = 'false'
def PortProtoStore():
    global PortProtoDict
    global titleHasWrite

    LOG_PATH = confloader.getParameters('LOG_PATH')
    LOG_PROT_PROTOCOL_NAME = confloader.getParameters('LOG_PROT_PROTOCOL_NAME')

    f = open(LOG_PATH + '/' + LOG_PROT_PROTOCOL_NAME, 'a')     # use 'a' not 'w'
    if titleHasWrite == 'false':
	f.write('ip and abnormal proto, times\n')
	titleHasWrite = 'true'

    for key, value in PortProtoDict.items():
        f.write(key + ', ' + str(value) + '\n')

    f.close()
    return    
    

def FlushLog():
    PortProtoStore()
    return


if __name__ == '__main__':
    print 'sss'
   
    PortProtocolCheck() 
