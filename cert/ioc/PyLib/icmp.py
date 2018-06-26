#!/usr/bin/python
#=====================================
#	for ICMP(V6) protocol Detect
#	1. ping 	type = 0/8
#	2. traceroute 	tpye = 11
#=====================================
import binascii
import sys
import confloader

reload(sys)
sys.setdefaultencoding('gb18030')


def icmpCheck(source):
    global Icmp_Map    

    highest_layer = source['highest_layer']
    if highest_layer == 'ICMP':			# may by icmpv6
	icmp_type = source['icmp_type']
	if icmp_type == str(0) or icmp_type == str(8):
	   
	    # max length
  	    #Icmp_Data_Length(source)

            # class calc
            Icmp_Class_Calc(source)	     

	    # compare 
	    Icmp_Compare(source)	
	
	if icmp_type == str(11):
	    print 'type is 11'
    return


#############################################################################################
'''
    Icmp data Length
'''

Icmp_Data_Max_Length = 46 * 2
def Icmp_Data_Length(source):
    global Icmp_Data_Max_Length

    data = source['data'].strip()
    if len(data) > Icmp_Data_Max_Length:
	print data
	
    return


#############################################################################################
'''
    All ICMP Class
'''
Icmp_Map = {}
Icmp_Map_Max_Length = 10000

def Icmp_Class_Calc(source):
    global Icmp_Map

    #if source.has_key('data')
    data = source['data'].strip()
    if Icmp_Map.has_key(data):
	Icmp_Map[data] = Icmp_Map[data] + 1
    else:
	if len(Icmp_Map) == Icmp_Map_Max_Length:
	    Icmp_Class_Log_Store()
	    Icmp_Map = {}
	
	Icmp_Map[data] = 1
    return


def Icmp_Class_Log_Store():
    global Icmp_Map

    # load conf info
    LOG_PATH = confloader.getParameters('LOG_PATH') 
    LOG_ICMP_CLASS_LOG_STORE_NAME = confloader.getParameters('LOG_ICMP_CLASS_LOG_STORE_NAME')

    # use 'a'  not 'w'
    f = open(LOG_PATH + '/' + LOG_ICMP_CLASS_LOG_STORE_NAME, 'a')
    for key, value in Icmp_Map.items():
        string = ''
        try:
            string = binascii.a2b_hex(key.strip())
            string = string.strip().replace(',', '_')   # for excel format
        except:
            string = 'cant decode'
        finally:
            f.write(key + ',' + string + ',' + str(value) + '\n')
    f.close()
    return

#############################################################################################
Global_Icmp_dict = {}
'''
    1. compare Send_IP_ICMP and Receive_IP_ICMP
    2. mayby first time is error message, but according the first time and the key	
'''

def Icmp_Compare(source):
    global Global_Icmp_dict

    ip_src = source['ip_src']
    ip_dst = source['ip_dst']
    data = source['data'].strip()    

    key = ip_src + '->' + ip_dst
    key_tmp = ip_dst + '->' + ip_src

    if (Global_Icmp_dict.has_key(key) == True) and (Global_Icmp_dict.has_key(key_tmp) == False):
	if len(data) != Global_Icmp_dict[key]:
	    Icmp_Compare_Log(key)
	return
    elif (Global_Icmp_dict.has_key(key) == False) and (Global_Icmp_dict.has_key(key_tmp) == True):
	if len(data) != Global_Icmp_dict[key_tmp]:
	    Icmp_Compare_Log(key_tmp)
	return
    elif (Global_Icmp_dict.has_key(key) == False) and (Global_Icmp_dict.has_key(key_tmp) == False):
	Global_Icmp_dict[key] = len(data)
    return	

	
Global_Icmp_Result = {}
Global_Icmp_Max_Length = 10000 	# max value set 10k
def Icmp_Compare_Log(key):  
    global Global_Icmp_Result
    global Global_Icmp_Max_legth    
       
    if Global_Icmp_Result.has_key(key):
	Global_Icmp_Result[key] = Global_Icmp_Result[key] + 1
    else:
	if len(Global_Icmp_Result) == Global_Icmp_Max_Length:
	    Icmp_Compare_Log_Store()
	    Global_Icmp_Result = {}	# clear map
	
	Global_Icmp_Result[key] = 1
    return


def Icmp_Compare_Log_Store():
    global Global_Icmp_Result

    # load conf info
    LOG_PATH = confloader.getParameters('LOG_PATH')
    LOG_ICMP_COMPARE_LOG_STORE_NAME = confloader.getParameters('LOG_ICMP_COMPARE_LOG_STORE_NAME')

    # use 'a' not 'w'
    f = open(LOG_PATH + '/' + LOG_ICMP_COMPARE_LOG_STORE_NAME, 'a')
    for key, value in Global_Icmp_Result.items():
	f.write(key + '  :  ' + str(value) + '\n')
    f.close()     
    return


#############################################################################################
# flush the last data to disk
def LogFlush():
    Icmp_Class_Log_Store()

    Icmp_Compare_Log_Store()
    return

#############################################################################################	


if __name__ == "__main__":
    print 'sss'
