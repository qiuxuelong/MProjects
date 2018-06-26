#!/usr/bin/python
#=======================================================
#
#               ElasticSearch Client
#
#=======================================================
from elasticsearch import Elasticsearch
from elasticsearch import helpers

es = Elasticsearch('http://127.0.0.1')

Cache = []
CacheMaxLength = 10000
def putData(jsonData):
    global Cache
    global CacheMaxLength

    try:
	if len(Cache) == CacheMaxLength:
	    helpers.bulk(es.Cache)
	    Cache = []
	else:
	    Cache.append(jsonData)
    except Exception, e:
	print 'EleasticSearch Client Write Error:'
	print Exception, e
    return


def flush2ES():
    global Cache

    try:
        if len(Cache) > 0:
            helpers.bulk(es, Cache)
            Cache = []
            print "has flush last data to ES"
    except Exception, e:
        print "ElasticSearch Client flush2ES Error:"
	print Exception, e
    return


if __name__ == '__main__':
    print 'sss'

    mjson = {'_index' : 'aaa',
	     '_type'  : 'bbb'}

    mjson['_source'] = {'ab'	:	123,
			'cd' 	:	'fffff'
			}

    putData(mjson)
    flush2ES()


