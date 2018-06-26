#!/usr/bin/python
import sqldb 
import os
import sys

import confloader


ALL_IP = set()		# for all ip in traffic
def collectionIP(source):
    global ALL_IP 

    if source.has_key('ip_src'):
 	ALL_IP.add(source['ip_src'])
    if source.has_key('ip_dst'):
	ALL_IP.add(source['ip_dst'])
   
    analysisSIP(source)

    return  


def checkBlackIP():
    global ALL_IP

    # load conf info
    LOG_PATH = confloader.getParameters('LOG_PATH')
    LOG_FOR_BLACK_IP_NAME = confloader.getParameters('LOG_FOR_BLACK_IP_NAME')

    # add test ip
    ALL_IP.add('52.200.243.123') 
    result = sqldb.checkBlack(ALL_IP)

    # use 'a' not 'w'
    f = open(LOG_PATH + '/' + LOG_FOR_BLACK_IP_NAME, 'a')
    f.write(result)
    f.close()
    return
   
 
# for create src_ip ---> packetNum,protocols,dstip,dst_domain
'''
get message from a pkt(packet),struct as:
struct SIP{
    sip1:{      
        pkt:num
        hightestProto:proto
        dip:dip                 # all dip
    }
    sip2:{
        like above
    }
    ...
} 
'''
SIP = {}
def analysisSIP(source):
    global SIP

    # for arp or others
    if source['layer_len'] < 3:
        return

    if source.has_key('ip_src') and source.has_key('ip_dst'):
        sip = source['ip_src']
        dip = source['ip_dst']

        hlp = source['highest_layer']

        if SIP.has_key(sip):
            # update
            SIP[sip]["pktNum"] =  SIP[sip]["pktNum"] + 1

            hl = SIP[sip]["highestLayer"]
            if hl.has_key(hlp):
                hl[hlp] = hl[hlp] + 1
            else:
                hl[hlp] = 1

            #SIP[sip]['dstIP'].add(dip)
            SIP[sip]['dstIP'].append(dip)
            SIP[sip]['dstIP'] = list(set(SIP[sip]['dstIP']))
        else:
            # create struct
            SIP[sip] = {"pktNum":1,
                        "highestLayer":{hlp:1},
                        #"dstIP":set(dip)
                         "dstIP": [dip]
                        }

        if source.has_key('dns_qry_name'):
            SIP[sip]['dstIP'].append(source['dns_qry_name'])




def showSIP():
    global SIP

    message = ""
    for key, value in SIP.items():
        message = message + "\nsip:" + str(key)

        # Highest Layer
        message = message + "\nhighestLayer:" + str(SIP[key]["pktNum"])

        # protocols
        for hkey, hvalue in SIP[key]["highestLayer"].items():
            message = message + "\n" + str(hkey) + ":" + str(hvalue)

        # dstIP 
        for dip in SIP[key]["dstIP"]:
            #if len(dip) > 0:
            message = message + "\n" + str(dip)

        message = message + "\n=============="
    return message


def flush2Log():
    checkBlackIP()
    
    #print showSIP()


if __name__ == '__main__':
    print 'sss'
    print LOG_PATH
