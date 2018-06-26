#!/usr/bin/python
#=================================================
#
#               IP Layer Analyser
#
#=================================================
import DataBean

import IcmpAnalyser
import UdpAnalyser
import TcpAnalyser


def Analysis(source):
    
    ip_src = str(source['ip_src'])
    ip_dst = str(source['ip_dst'])
    DataBean.addItem('ip_src', ip_src)
    DataBean.addItem('ip_dst', ip_dst)

    ip_proto = str(source['ip_proto'])
    if ip_proto	== '1':			# icmp(ipv4)
	IcmpAnalyser.Analysis(source)
    elif ip_proto == '6':		# tcp
	TcpAnalyser.Analysis(source)
    elif ip_proto == '17':		# udp
	UdpAnalyser.Analysis(source)
    elif ip_proto == '58':		# icmp(ipv6)
	pass
    else:				# unknown code
	pass

    return     

if __name__ == '__main__':
    print 'sss'
