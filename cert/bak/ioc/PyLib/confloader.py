#!/usr/bin/python

PATH_PROFILE = '/home/qiuxuelong/Desktop/python/ioc/conf/ioc.yml'

BUFFER = {}

def getProfile():
    global PATH_PROFILE
    global BUFFER

    f = open(PATH_PROFILE, 'r')
    lines = f.readlines()
    for line in lines:
	mline = line.strip()
        if ('#' in mline) or (mline == ''):	# delete the notes
	    pass
	else:
	    key = mline.split('=')[0].strip()	# delete the null charactor
	    value = mline.split('=')[1].strip()
	    
	    BUFFER[key] = value
	
    f.close()
    return


def getParameters(key):
    global BUFFER

    if len(BUFFER) == 0:
	getProfile()

    if BUFFER.has_key(key):
	return BUFFER[key]
    else:
	return ''
    
    return


if __name__ == '__main__':
    print getParameters('LOG_PATH')
	
    for key, value in BUFFER.items():
	print key + ":" + value
