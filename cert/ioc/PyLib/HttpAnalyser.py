#!/usr/bin/python
#=================================================
#
#               Http Layer Analyser
#
#=================================================
import DataBean
import confloader

import PortProtocolDetector

def Analysis(source):
	
    HttpCheck(source)

    CommonCheck()
    return


def HttpCheck(source):

    if source.has_key('http_host'):
	print source['http_host']
    else:
	print 'error'

    return


def CommonCheck():

    PortProtocolDetector.PortProtocolCheck()
    return



if __name__ == '__main__':
    print 'sss'
