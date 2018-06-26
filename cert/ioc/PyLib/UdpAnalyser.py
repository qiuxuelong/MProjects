#!/usr/bin/python
#=================================================
#
#               UDP Layer Analyser
#
#=================================================
import DataBean
import ProtocolDispatcher


def Analysis(source):

    udp_srcport = str(source['udp_srcport'])
    udp_dstport = str(source['udp_dstport'])	
    DataBean.addItem('udp_srcport', udp_srcport)
    DataBean.addItem('udp_dstport', udp_dstport)

    DataBean.addItem('transport_layer', 'udp')
     
    ProtocolDispatcher.Dispatcher(source)
    return


if __name__ == '__main__':
    print 'sss'
