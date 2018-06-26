#!/usr/bin/python
#=======================================================
#
#	Dispatcher For Check Protocols
#
#=======================================================
import confloader
import DataBean

import DnsAnalyser
import HttpAnalyser
import SnmpAnalyser
import UnknownProtoAnalyser

def Dispatcher(source):
  
    layers = DataBean.getItem('layers').upper() 
    highest_layer = DataBean.getItem('highest_layer').upper()
   
    # Just confirm by protocol name
    if (('DNS' == highest_layer) and (confloader.getParameters('DnsCheck').lower() == 'yes')):
	DnsAnalyser.Analysis(source)
    elif (('HTTP' in layers) and (confloader.getParameters('HttpCheck').lower() == 'yes')):
	# 1. eth:ip:http:media
	# 2. https ???????????
	HttpAnalyser.Analysis(source)
    elif 'SNMP' in layers:
	SnmpAnalyser.Analysis()
    else:
    	UnknownProtoAnalyser.Analysis()	
    return


def ProtocolConfirm():
    # how confirm application protocol???
    layers = DataBean.getItem('transport').upper()
    transport = DataBean.getItem('transport')

    sport = ''
    dport = ''
    if transport == 'tcp':
    	sport = str(DataBean.getItem('tcp_srcport'))
	dport = str(DataBean.getItem('tcp_dstport'))
    else:
	sport = str(DataBean.getItem('udp_srcport'))
	dport = str(DataBean.getItem('udp_dstport'))

    if 'HTTP' in layers and (sport == '80' or dport == '80'):
	return 'HTTP'
    if 'SSL' in layers and (sport == '443' or dport == '443'):
	return 'HTTPS'
    if 'DNS' in layers and (sport == '53' or dport = '53'):
	return 'DNS'
    if 'SMTP' in layers and (sport == '25' or dport == '25'):
	return 'SMTP' 
    return


if __name__ == '__main__':
    print 'sss'
