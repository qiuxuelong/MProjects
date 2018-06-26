#!/usr/bin/python
#=================================================
#
#               DNS Layer Analyser
#
#=================================================
import DataBean
import confloader

import PortProtocolDetector


def Analysis(source):

    DnsCheck(source)
    
    CommonCheck()
    return


def DnsCheck(source):

    ip_src = DataBean.getItem('ip_src')
    ip_dst = DataBean.getItem('ip_dst')

    # query
    if (int(source['dns_count_queries']) > 0 and int(source['dns_count_answers']) == 0):
        domain = source['dns_qry_name']
        domainCheck(ip_src, 'request', domain)

        #if (str(source['dns_qry_type']) == '0x0010') and txt > 0

    # response
    if (int(source['dns_count_queries']) > 0 and int(source['dns_count_answers']) > 0):
        domain = source['dns_resp_name']
        domainCheck(ip_dst, 'response', domain)

        if str(source['dns_resp_type']) == '0x0010' and source.has_key('dns_resp_len'):
            if int(source['dns_resp_len']) > 0:
                AddElement(ip_dst, 'response_txt_times')
    return


def CommonCheck():

    PortProtocolDetector.PortProtocolCheck()    
    return


def domainCheck(ip, direction, domain):
   
    # domain length distribution
    AddLengthDistribution(len(domain)) 

    # domain max length
    if len(domain) >  int(confloader.getParameters('DomainMaxLength')):
	AddElement(ip, 'above_max_domain_length_times')	
	
    # domain lable nums
    lables = domain.split('.')
    if len(lables) > int(confloader.getParameters('LableMaxNum')):
	AddElement(ip, 'above_max_lable_num_times')

    # domain lable limit    
    for lable in lables:
	if len(lable) >= int(confloader.getParameters('LableMaxLimit')):
	    AddElement(ip, 'above_max_lable_limit_times')
	break

    # has upper
    if domain.lower() != domain:
	AddElement(ip, 'has_upper_character_times')

    # add direction
    if direction == 'request':
	AddElement(ip, 'request_times')
    elif direction == 'response':
        AddElement(ip, 'response_times')

    return


DnsMap = {}
DnsMapMaxLength = 10000 # 10k
def AddElement(ip, element):
    global DnsMap
    global DnsMapMaxLength

    if DnsMap.has_key(ip):
	DnsMap[ip][element] = DnsMap[ip][element] + 1
    else:
	if len(DnsMap) == DnsMapMaxLength:
	    DnsLog()
	    DnsMap = {}
	
	DnsMap[ip] = {'request_times' 			:	0,
		      'response_times'			:	0,
		      'above_max_domain_length_times'	:	0,
		      'above_max_lable_num_times'	:	0,
		      'above_max_lable_limit_times'	:	0,
		      'has_upper_character_times'	:	0,
		      'response_txt_times'		:	0
		     }
	DnsMap[ip][element] = DnsMap[ip][element] + 1
    
    return


ExcelTitle = 'false'
def DnsLog():
    global DnsMap
    global ExcelTitle
    
    LOG_PATH = confloader.getParameters('LOG_PATH')
    LOG_DNS_NAME = confloader.getParameters('LOG_DNS_NAME')

    f = open(LOG_PATH + '/' + LOG_DNS_NAME, 'a')	# use 'a' not 'w'
    if ExcelTitle == 'false':
	title = 'ip, '
	title = title + 'request_times, '
	title = title + 'response_times, '
	title = title + 'above_max_domain_length_times, '
	title = title + 'above_max_lable_num_times, '
	title = title + 'above_max_lable_limit_times, '
	title = title + 'has_upper_character_times, '
	title = title + 'response_txt_times\n'
	f.write(title)
	ExcelTitle = 'true'

    for key, value in DnsMap.items():
        tmp = ''
        tmp = str(value['request_times'])
        tmp = tmp + ', ' + str(value['response_times'])
        tmp = tmp + ', ' + str(value['above_max_domain_length_times'])
        tmp = tmp + ', ' + str(value['above_max_lable_num_times'])
        tmp = tmp + ', ' + str(value['above_max_lable_limit_times'])
        tmp = tmp + ', ' + str(value['has_upper_character_times'])
	tmp = tmp + ', ' + str(value['response_txt_times'])
        f.write(key + ', ' + tmp + '\n')

    f.close()
    return


LengthDistribution = {'block_10' : 0,  # (0-10]
                      'block_20' : 0,  # (10,20]
                      'block_30' : 0,  # (20,30]
                      'block_40' : 0,  # (30,40]
                      'block_50' : 0,  # (40,50]
                      'block_60' : 0   # (50,..]
                       }
def AddLengthDistribution(domainLength):
    global LengthDistribution

    if domainLength > 0 and domainLength <= 10:
        LengthDistribution['block_10'] = LengthDistribution['block_10'] + 1
    elif domainLength > 10 and domainLength <= 20:
        LengthDistribution['block_20'] = LengthDistribution['block_20'] + 1
    elif domainLength > 20 and domainLength <= 30:
        LengthDistribution['block_30'] = LengthDistribution['block_30'] + 1
    elif domainLength > 30 and domainLength <= 40:
        LengthDistribution['block_40'] = LengthDistribution['block_40'] + 1
    elif domainLength > 40 and domainLength <= 50:
        LengthDistribution['block_50'] = LengthDistribution['block_50'] + 1
    elif domainLength > 50:
        LengthDistribution['block_60'] = LengthDistribution['block_60'] + 1
    return    


def LengthDistributionLog():
    global LengthDistribution

    tmp = ''
    tmp = tmp + '(0_10]' + ', ' + str(LengthDistribution['block_10']) + '\n'
    tmp = tmp + '(10_20]' + ', ' + str(LengthDistribution['block_20']) + '\n'
    tmp = tmp + '(20_30]' + ', ' + str(LengthDistribution['block_30']) + '\n'
    tmp = tmp + '(30_40]' + ', ' + str(LengthDistribution['block_40']) + '\n'
    tmp = tmp + '(40_50]' + ', ' + str(LengthDistribution['block_50']) + '\n'
    tmp = tmp + '(60_..)' + ', ' + str(LengthDistribution['block_60']) + '\n'

    LOG_PATH = confloader.getParameters('LOG_PATH')
    LOG_DNS_LENGTH_DISTRIBUTION_NAME = confloader.getParameters('LOG_DNS_LENGTH_DISTRIBUTION_NAME')

    f = open(LOG_PATH + '/' + LOG_DNS_LENGTH_DISTRIBUTION_NAME, 'a')	# use 'a' not 'w'
    f.write(tmp)

    f.close()
    return


def FlushLog():
    
    DnsLog()
    LengthDistributionLog()
    return	


if __name__ == '__main__' :
    print 'sss'
