#!/usr/bin/python
#=================================================
#
#	Unknown Application Layer Analyser
#
#=================================================
import DataBean

import PortProtocolDetector

def Analysis():

    CommonCheck()
    return


def CommonCheck():
    
    PortProtocolDetector.PortProtocolCheck()
    return


if __name__ == '__main__':
    print 'ssss' 
