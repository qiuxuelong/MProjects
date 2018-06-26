#!/usr/bin/python
#=======================================================
#
#              SNMP Protocol Analyser
#
#=======================================================
import DataBean
import confloader

import PortProtocolDetector


def Analysis():
    SnmpCheck()

    CommonCheck()
    return


def SnmpCheck():
    ip_src = DataBean.getItem('ip_src')
    ip_dst = DataBean.getItem('ip_dst')

    if (isInnerIP(ip_src) == False) or (isInnerIP(ip_dst) == False):
        SnmpLog(ip_src, ip_dst)
    return


def CommonCheck():
    PortProtocolDetector.PortProtocolCheck()
    return


InnerIPMap = {'10.'	: '10.', 	# 10.x.x.x
	      '192.168.': '192.168.',	# 192.168.x.x
	      '172.16.'	: '172.16.',	# 172.16.x.x
	      '172.17.'	: '172.17.',
	      '172.18.' : '172.18.',
	      '172.19.' : '172.19.',
	      '172.20.' : '172.20.',
	      '172.21.' : '172.21.',
	      '172.22.' : '172.22.',
	      '172.23.' : '172.23.',
	      '172.24.' : '172.24.',
	      '172.25.' : '172.25.',
	      '172.26.' : '172.26.',
	      '172.27.' : '172.27.',
	      '172.28.' : '172.28.',
	      '172.29.' : '172.29.',
	      '172.30.' : '172.30.',
	      '172.31.' : '172.31.',
		}
def isInnerIP(ip):
    global InnerIPMap

    fields = ip.split('.')
    ipHeader = fields[0] + '.' + fields[1] + '.'
    if ip.startswith('10.'):
	return True

    if InnerIPMap.has_key(ipHeader):
	return True 
    return False


SnmpLogMap = {}
def SnmpLog(ip_src, ip_dst):
    global SnmpLogMap

    key = ip_src + '->' + ip_dst
    if SnmpLogMap.has_key(key):
	SnmpLogMap[key] = SnmpLogMap[key] + 1
    else:
	SnmpLogMap[key] = 1
    return


def SnmpStore():
    global SnmpLogMap

    LOG_PATH = confloader.getParameters('LOG_PATH')
    LOG_SNMP_STORE_NAME = confloader.getParameters('LOG_SNMP_STORE_NAME')

    f = open(LOG_PATH + '/' + LOG_SNMP_STORE_NAME, 'a')     # use 'a' not 'w'
    buf = 'sip->dip, times\n'
    for key, value in SnmpLogMap.items():
	buf = buf + (key + ',' + str(value) + '\n')

    f.write(buf)
    f.close()
    return


def flushLog():
    
    SnmpStore()
    return 


if __name__ == '__main__':
    print 'sss'

    ip_src = '10.168.0.1'
    ip_dst = '192.168.0.2'
    if (isInnerIP(ip_src) == False) or (isInnerIP(ip_dst) == False):
	print 'yes'
    else:
	print 'no'
    print 'over'
