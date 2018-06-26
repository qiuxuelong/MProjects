#!/usr/bin/python
#=======================================================
#
#               Highest Layer Judge 
#
#=======================================================


# for a stream
def JudgeForHighestLayer(FrameLayers, srcPort, dstPort):

    # eth:q1.2:ip:tcp
    if FrameLayers.endswith('ip:tcp'):
        return 'tcp'

    if 'http' in FrameLayers :
        return 'http'

    # https
    if ('ssl' in FrameLayers) and (srcPort == '443' or dstPort == '443'):
	return 'https'

    # rdp
    if (('rdp' in FrameLayers) or ('tpkt' in FrameLayers)):
        return 'rdp'

    # dns/mdns
    if 'dns' in FrameLayers:
        return 'xdns'
    
    # default
    Layers = FrameLayers.split(':')
    return Layers[len(Layers) -1]


if __name__ == '__main__':
    print 'sss'

    
    print JudgeForHighestLayer('eth:ip:tcp:ssl', 6342, 443)

