import pyshark
from datetime import datetime


def ProtoCheck(pkt):
	
    layers = len(pkt.layers)
    for i in range(0, layers):
	if pkt.layers[i]._layer_name == 'http':
	    
	    # you can see all fields
	    # print pkt.layers[i]._all_fields

	    # get every field for you want
	    if pkt.layers[i]._all_fields.has_key('http.request.full_uri'):
		print pkt.layers[i]._all_fields['http.request.full_uri']		

    return


def main():
    cap = pyshark.LiveCapture(interface = 'eth0', bpf_filter='ip and tcp port 80')
    cap.sniff(packet_count = 10)

    cap.apply_on_packets(ProtoCheck, timeout = 86400) # one day
    return


if __name__ == '__main__':

    main()
