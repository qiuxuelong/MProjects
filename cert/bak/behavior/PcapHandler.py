#!/usr/bin/python
#=======================================================
#
#      	 	Tshark Handle Pcaps 
#
#=======================================================
import os

PcapPATH = '/home/qiuxuelong/Desktop/python/behavior/pcapsdir'
LogPath = '/home/qiuxuelong/Desktop/python/behavior/pcaplog'

CmdParameter = '-T fields -E separator=, -E occurrence=a -E quote=d -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e frame.cap_len -e frame.protocols -e frame.time > '

def LoopFilePath(filePath):
    global CmdParameter
    global LogPath

    files = os.listdir(filePath)
    for file in files:
	fileName = os.path.join(filePath, file)
	if os.path.isdir(fileName):
	    LoopFilePath(fileName)
	else:
	    fullPath = os.path.join(filePath, fileName)
	    print fullPath + ' is handling'
	    
	    cmd = 'tshark -2 -r ' +  fullPath + ' ' + CmdParameter + LogPath + '/' + fullPath.replace('/', '_') + '.csv'
	    try:
	   	os.system(cmd)
		pass
	    except Exception, e:
		print fullPath + ' Exception occured!'
	    finally:
		pass


if __name__ == '__main__':
    print 'sss'

    if not os.path.exists("Log"):
        os.mkdir("pcaplog")
    
    LoopFilePath(PcapPATH)
