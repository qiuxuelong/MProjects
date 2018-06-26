#!/usr/bin/python
#=================================================
#
#		Frame Layer Analyser
#
#=================================================
import DataBean
import IPAnalyser

def Analysis(source):

    DataBean.addItem('frameTime', str(source['@timestamp']))
    DataBean.addItem('capturedLength', str(source['captured_length']))
    #DataBean.addItem('fileName', str(source['fileName']))
    DataBean.addItem('highest_layer', str(source['highest_layer']))
    DataBean.addItem('layers', str(source['layers']))
    DataBean.addItem('fileName',str(source['fileName']))

    Eth_Type = str(source['eth_type']) 
    if Eth_Type == '0x0806':		# ARP
	pass			
    elif Eth_Type == '0x0800':		# IP(IPV4)
	IPAnalyser.Analysis(source)
    else:				# Unknown code
	pass	

    DataBean.clearItem()		# clear DataBean
    return


if __name__ == '__main__':
    print 'sss'
