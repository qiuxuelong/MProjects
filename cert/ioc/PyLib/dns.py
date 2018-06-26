#!/usr/bin/python
#================================================
#	For DNS Protocol Detect
#
# @Structure Define:
# 1. Domain check: query/response
#	domain_times		===> 	domain too long
#	lable_num_times		===>    domain has more lable nums
#	upper_times		===>	has upper charactors
#	domain_equals		===>	request domain and response domain equals
# 
# 2. Data Length: response
#	dns_resp_len_times	===>	dns_resp_length
#
# 3. Authority/Additional
#	author_times		===>	authority
#	addition_times		===>	additional
#
# @Length Distribution:
#    [0-10]  : 23
#    [10-20] : /L1234
#    [20-30] : 34
#
# @Log
#    sip->dip : domain_times:3;	
#		lable_num_times:10;
#		... ...	
#
#===============================================
import confloader

Global_DNS_MAP = {}
Global_DNS_MAP_MAX_LENGTH = 10000 	# 10k

Length_Distribution = {'block_10' : 0,	# (0-10]
		       'block_20' : 0,	# (10,20]
		       'block_30' : 0,	# (20,30]
		       'block_40' : 0,	# (30,40]
		       'block_50' : 0,	# (40,50]
		       'block_60' : 0	# (50,..]
			}



def dnsChecks(source):

    highest_layer = source['highest_layer']
    if highest_layer == 'DNS':

        ip_src = source['ip_src']
        ip_dst = source['ip_dst']
 	key = ip_src + '->' + ip_dst
	
	'''
	if ip_src == '192.168.12.199' and ip_dst == '192.168.12.234':
	    pass
	else:
	    return
	'''
	
	# query
	if int(source['dns_count_queries']) > 0 and int(source['dns_count_answers']) == 0:
	    domain = source['dns_qry_name']
	    domainCheck(key, domain)
	
	# response
	if int(source['dns_count_queries']) > 0 and int(source['dns_count_answers']) > 0:
	    # response domain
	    if source.has_key('dns_resp_name'):
	    	if source['dns_qry_name'] != source['dns_resp_name']:
		    addElement(key, 'domain_equals')	
	    	else:
		    domain = source['dns_resp_name']
		    domainCheck(key, domain)
		
	    # response data
	    if source.has_key('dns_resp_len') and int(source['dns_resp_len']) > 0:
		addElement(key, 'dns_resp_len_times')

	
	# authority
	if int(source['dns_count_auth_rr']) > 0:
	    addElement(key, 'author_times')
	
	# additional
	if int(source['dns_count_add_rr']) > 0:
	    addElement(key, 'addition_times')	
    return


#########################################################################################################
def domainCheck(key, domain):

    # domain length distribution
    addLengthDistribution(len(domain))

    # domain length check
    Domain_Max_Length = int(confloader.getParameters('Domain_Max_Length'))
    if len(domain) > Domain_Max_Length:
	addElement(key, 'domain_times')
    
    # domain lables
    Lable_Max_Num = int(confloader.getParameters('Lable_Max_Num'))
    if len(domain.split('.')) > Lable_Max_Num:
	addElement(key, 'lable_num_times') 

    # upper
    if domain.lower() != domain:
	addElement(key, 'upper_times')
    return


#########################################################################################################
def addElement(key, element):
    global Global_DNS_MAP
    global Global_DNS_MAP_MAX_LENGTH

    if Global_DNS_MAP.has_key(key):
	Global_DNS_MAP[key][element] = Global_DNS_MAP[key][element] + 1
    else:
	# buffer to disk
	if len(Global_DNS_MAP) == Global_DNS_MAP_MAX_LENGTH:
	    dns_Log()
	    Global_DNS_MAP = {}		# clear map

	# create new key
	Global_DNS_MAP[key] = {
				'domain_times'	 :	0,
				'lable_num_times':	0,
				'upper_times'	 :	0,
				'domain_equals'	 : 	0,
				'dns_resp_len_times':	0,
				'author_times'	 :	0,
				'addition_times' :	0	
				}
	# add element
	Global_DNS_MAP[key][element] = Global_DNS_MAP[key][element] + 1
    return


def dns_Log():
    global Global_DNS_MAP
	
    # load conf info
    LOG_PATH = confloader.getParameters('LOG_PATH')
    LOG_DNS_NAME = confloader.getParameters('LOG_DNS_NAME')

    # use 'a' not 'w'
    f = open(LOG_PATH + '/' + LOG_DNS_NAME, 'a')
    for key, value in Global_DNS_MAP.items():
	tmp = ''
	tmp = str(value['domain_times']) 
	tmp = tmp + ', ' + str(value['lable_num_times'])
	tmp = tmp + ', ' + str(value['upper_times'])
	tmp = tmp + ', ' + str(value['domain_equals'])
	tmp = tmp + ', ' + str(value['dns_resp_len_times'])
	tmp = tmp + ', ' + str(value['author_times'])
	tmp = tmp + ', ' + str(value['addition_times'])
	f.write(key + ", " + tmp + '\n')	
    f.close()
	
    # delete all itmes
    Global_DNS_MAP.clear()
    return


def addLengthDistribution(domain_length):
    global Length_Distribution

    if domain_length > 0 and domain_length <= 10:
	Length_Distribution['block_10'] = Length_Distribution['block_10'] + 1
    elif domain_length > 10 and domain_length <= 20:
	Length_Distribution['block_20'] = Length_Distribution['block_20'] + 1
    elif domain_length > 20 and domain_length <= 30:
	Length_Distribution['block_30'] = Length_Distribution['block_30'] + 1
    elif domain_length > 30 and domain_length <= 40:
	Length_Distribution['block_40'] = Length_Distribution['block_40'] + 1 
    elif domain_length > 40 and domain_length <= 50:
	Length_Distribution['block_50'] = Length_Distribution['block_50'] + 1
    elif domain_length > 50:
	Length_Distribution['block_60'] = Length_Distribution['block_60'] + 1
    return
	

def Length_Distribution_Log():
    global Length_Distribution    

    tmp = ''
    tmp = tmp + '(0_10]' + ', ' + str(Length_Distribution['block_10']) + '\n'
    tmp = tmp + '(10_20]' + ', ' + str(Length_Distribution['block_20']) + '\n'
    tmp = tmp + '(20_30]' + ', ' + str(Length_Distribution['block_30']) + '\n'
    tmp = tmp + '(30_40]' + ', ' + str(Length_Distribution['block_40']) + '\n'
    tmp = tmp + '(40_50]' + ', ' + str(Length_Distribution['block_50']) + '\n'
    tmp = tmp + '(60_..)' + ', ' + str(Length_Distribution['block_60']) + '\n'

    # load conf info
    LOG_PATH = confloader.getParameters('LOG_PATH')
    LOG_DNS_LENGTH_DISTRIBUTION_NAME = confloader.getParameters('LOG_DNS_LENGTH_DISTRIBUTION_NAME')

    # use 'a' not 'w'
    f = open(LOG_PATH + '/' + LOG_DNS_LENGTH_DISTRIBUTION_NAME, 'a')
    f.write(tmp)
    f.close()

    return


#########################################################################################################
def LogFlush():
    dns_Log()
	
    Length_Distribution_Log()
    return

#########################################################################################################


if __name__=='__main__':
    print 'sss'
