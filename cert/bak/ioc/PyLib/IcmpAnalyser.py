#!/usr/bin/python
#=================================================
#
#               ICMP(IPV4) Layer Analyser
#
#=================================================
import DataBean
import binascii
import confloader
import sys

reload(sys)
sys.setdefaultencoding('gb18030')


def Analysis(source):
    
    icmp_type = str(source['icmp_type'])
    icmp_code = str(source['icmp_code'])
    icmp_data = source['data']			# data
    layers = str(source['layers'])
    DataBean.addItem('icmp_type', icmp_type)
    DataBean.addItem('icmp_code', icmp_code)
    DataBean.addItem('icmp_data', icmp_data)
    DataBean.addItem('layers', layers)

    IcmpProtoDetect()	
    return    


def IcmpProtoDetect():
    typeField = DataBean.getItem('icmp_type')
    codeField = DataBean.getItem('icmp_code') 
    
    '''
        source['highest_layer'] == icmp | short;
        ip_proto = 1;
    '''
    if (typeField == '8' and codeField == '0') or (typeField == '0' and codeField == '0'):      # ping(request and reply)
	# protocol analysis
	IcmpClassCalc()	
	IcmpCompare()	
	# behavior analysis	
    else:                                                                                       # traceroute,redirect ...
        pass     

    return


IcmpMap = {}
IcmpMapMaxLength = 10000
def IcmpClassCalc():
    global IcmpMap
    global IcmpMapMaxLength
    
    data = DataBean.getItem('icmp_data').strip()   
    if IcmpMap.has_key(data):
	IcmpMap[data] = IcmpMap[data] + 1
    else:
	if len(IcmpMap) == IcmpMapMaxLength:
	    IcmpClassLog()
	    IcmpMap = {}

	IcmpMap[data] = 1 
    return


def IcmpClassLog():
    global IcmpMap

    LOG_PATH = confloader.getParameters('LOG_PATH')
    LOG_ICMP_CLASS_LOG_STORE_NAME = confloader.getParameters('LOG_ICMP_CLASS_LOG_STORE_NAME')

    f = open(LOG_PATH + '/' + LOG_ICMP_CLASS_LOG_STORE_NAME, 'a')	# use 'a' not 'w'
    for key, value in IcmpMap.items():
        string = ''
        try:
            string = binascii.a2b_hex(key.strip())
            string = string.strip().replace(',', '_')   		# for excel format
        except:
            string = 'cant decode'
        finally:
            f.write(key + ',' + string + ',' + str(value) + '\n')

    f.close()
    return


IcmpCompareDict = {}
def IcmpCompare():
    global IcmpCompareDict

    ip_src = DataBean.getItem('ip_src')
    ip_dst = DataBean.getItem('ip_dst')
    data = DataBean.getItem('icmp_data')

    key = ip_src + '->' + ip_dst
    key_reverse = ip_dst + '->' + ip_src

    if (IcmpCompareDict.has_key(key) == True) and (IcmpCompareDict.has_key(key_reverse) == False):
	if len(data) != IcmpCompareDict[key]:
	    IcmpCompareLog(key)
	return
    elif (IcmpCompareDict.has_key(key) == False) and (IcmpCompareDict.has_key(key_reverse) == True):
	if len(data) != IcmpCompareDict[key_reverse]:
	    IcmpCompareLog(key_reverse)
	return
    elif (IcmpCompareDict.has_key(key) == False) and (IcmpCompareDict.has_key(key_reverse) == False):
	IcmpCompareDict[key] = len(data)
    return


IcmpCompareMap = {}
IcmpCompareMapMaxLength = 10000
def IcmpCompareLog(key):
    global IcmpCompareMap
    global IcmpCompareMapMaxLength
   
    if IcmpCompareMap.has_key(key):
	IcmpCompareMap[key] = IcmpCompareMap[key] + 1
    else:
	if len(IcmpCompareMap) == IcmpCompareMapMaxLength:
	    IcmpCompareStore()
	    IcmpCompareMap = {}
	
	IcmpCompareMap[key] = 1
    return


def IcmpCompareStore():
    global IcmpCompareMap

    LOG_PATH = confloader.getParameters('LOG_PATH')
    LOG_ICMP_COMPARE_LOG_STORE_NAME = confloader.getParameters('LOG_ICMP_COMPARE_LOG_STORE_NAME')

    f = open(LOG_PATH + '/' + LOG_ICMP_COMPARE_LOG_STORE_NAME, 'a')	# use 'a' not 'w'
    for key, value in IcmpCompareMap.items():
        f.write(key + '  :  ' + str(value) + '\n')

    f.close()
    return


def FlushLog():
    IcmpClassLog()

    IcmpCompareStore()
    return    


if __name__ == '__main__':
    print 'sss'
