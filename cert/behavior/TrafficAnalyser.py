#!/usr/bin/python
#=======================================================
#
#       	IP Traffic Calc
#
#=======================================================


def TrafficAnalysis(ip_src, ip_dst, CapturedLen, CapturedTime):

    hour = CapturedTime.split('_')[1].split(':')[0]

    AddTraffic(ip_src, ip_dst, CapturedLen, hour)
    return


TrafficMap = {}
def AddTraffic(ip_src, ip_dst, capturedLength, hour):
    global TrafficMap

    # ip_src
    if TrafficMap.has_key(ip_src) == False:
        CreateKey(ip_src)
    ChangeValue(ip_src, 0, capturedLength, hour)

    # ip_dst
    if TrafficMap.has_key(ip_dst) == False:
        CreateKey(ip_dst)
    ChangeValue(ip_dst, 1, capturedLength, hour)
    return


# direction : 0 : ip_src
#	      1 : ip_dst
def ChangeValue(ip, direction, capturedLength, hour):
    global TrafficMap
	
    value = TrafficMap[ip][hour].split(',')
    if direction == 0:
	obytes = int(value[2]) + capturedLength
	opackets = int(value[3]) + 1

 	TrafficMap[ip][hour] = 	value[0] + ',' + value[1] + ',' + str(obytes) + ',' + str(opackets)
    else:
	ibytes = int(value[0]) + capturedLength
	ipackets = int(value[1]) + 1
	
	TrafficMap[ip][hour] = str(ibytes) + ',' + str(ipackets) + ',' + value[2] + ',' + value[3]

    return


def CreateKey(ip):
    global TrafficMap
	
    #		       time    ibyes, ipackets,obytes,opackets
    TrafficMap[ip] = {'00': '0,0,0,0',	# (00,01]
                      '01': '0,0,0,0',	# (01,02]
                      '02': '0,0,0,0',	# (02,03]
                      '03': '0,0,0,0',  # (03,04]           
                      '04': '0,0,0,0',	# (04,05]
                      '05': '0,0,0,0',	# (05,06]
                      '06': '0,0,0,0',	# (06,07]
                      '07': '0,0,0,0',	# (07,08]
                      '08': '0,0,0,0',	# (08,09]
                      '09': '0,0,0,0',	# (09,10]
                      '10': '0,0,0,0',	# (10,11]
                      '11': '0,0,0,0',	# (11,12]
                      '12': '0,0,0,0',	# (12,13]
                      '13': '0,0,0,0',	# (13,14]
                      '14': '0,0,0,0',	# (14,15]
                      '15': '0,0,0,0',	# (15,16]
                      '16': '0,0,0,0',	# (16,17]
                      '17': '0,0,0,0',	# (17,18]
                      '18': '0,0,0,0',	# (18,19]
                      '19': '0,0,0,0',	# (19,20]
                      '20': '0,0,0,0',	# (20,21]
                      '21': '0,0,0,0',	# (21,22]
                      '22': '0,0,0,0',	# (22,23]
                      '23': '0,0,0,0'} 	# (23,24]
    return


def TrafficStore():
    global TrafficMap
    
    f = open('trafficlog.csv', 'a')
    for key, value in TrafficMap.items():
	tmp = key + '\n' 
	tmp = tmp + '00' + ',' +  value['00'] + '\n'
	tmp = tmp + '01' + ',' + value['01'] + '\n'
	tmp = tmp + '02' + ',' + value['02'] + '\n'
	tmp = tmp + '03' + ',' + value['03'] + '\n'
	tmp = tmp + '04' + ',' + value['04'] + '\n'
	tmp = tmp + '05' + ',' + value['05'] + '\n'
	tmp = tmp + '06' + ',' + value['06'] + '\n'
	tmp = tmp + '07' + ',' + value['07'] + '\n'
	tmp = tmp + '08' + ',' + value['08'] + '\n'
	tmp = tmp + '09' + ',' + value['09'] + '\n'
	tmp = tmp + '10' + ',' + value['10'] + '\n'
	tmp = tmp + '11' + ',' + value['11'] + '\n'
	tmp = tmp + '12' + ',' + value['12'] + '\n'
	tmp = tmp + '13' + ',' + value['13'] + '\n'
	tmp = tmp + '14' + ',' + value['14'] + '\n'
	tmp = tmp + '15' + ',' + value['15'] + '\n'
	tmp = tmp + '16' + ',' + value['16'] + '\n'
	tmp = tmp + '17' + ',' + value['17'] + '\n'
	tmp = tmp + '18' + ',' + value['18'] + '\n'
	tmp = tmp + '19' + ',' + value['19'] + '\n'
	tmp = tmp + '20' + ',' + value['20'] + '\n'
	tmp = tmp + '21' + ',' + value['21'] + '\n'
	tmp = tmp + '22' + ',' + value['22'] + '\n'
	tmp = tmp + '23' + ',' + value['23'] + '\n'
    	f.write(tmp)
    f.close()
    return

def FlushLog():
    
    TrafficStore()
    return


if __name__  == '__main__':
    print 'ssss'

