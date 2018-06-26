#=======================================
#	For TCP Protocol Detect
#=======================================




def tcpCheck(source):
    global Tcp_header_Length_Limit
	
    if 'tcp' in source['layers']:
	ip_src = source['ip_src']
	ip_dst = source['ip_dst']

	

if __name__ == '__main__':
    print 'sss'
