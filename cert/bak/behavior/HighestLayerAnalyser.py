#!/usr/bin/python
#=======================================================
#
#      	 	Highest Layer Calc 
#
#=======================================================


protoCount = {}
def calcProtoCount(FrameLayers):
    global protoCount

    Layers = FrameLayers.split(':')
    highestLayerProto = Layers[len(Layers)-1]

    if protoCount.has_key(highestLayerProto):
        protoCount[highestLayerProto] = protoCount[highestLayerProto] + 1
    else:
        protoCount[highestLayerProto] = 1
    
    return


def getProtoCount():
    global protoCount

    message = "higest layer distribution\n"
    for key,value in protoCount.items():
        message = message + str(key) + "," + str(value) + '\n'
    return message


def writeFile():

    # use 'a' not 'w'
    f = open('highest_layer.csv', 'a')
    f.write(getProtoCount())   
    f.close()
    return


def flush2Log():

    writeFile()
    return


if __name__ == '__main__':
    print 'sss'

