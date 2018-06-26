#!/usr/bin/python
#================================================
#
#		Tcp Layer Analyser
#
#================================================
import DataBean
import ProtocolDispatcher


def Analysis(source):
    
    tcp_srcport = str(source['tcp_srcport'])
    tcp_dstport = str(source['tcp_dstport'])
    DataBean.addItem('tcp_srcport', tcp_srcport)
    DataBean.addItem('tcp_dstport', tcp_dstport)
 
    DataBean.addItem('transport_layer', 'tcp')

    ProtocolDispatcher.Dispatcher(source)
    return


if __name__ == '__main__':
    print 'sss'

