#!/user/bin/python
import MySQLdb
import traceback

import confloader


def executeSql(sql):
    
    # load conf info
    My_SQL_IP = confloader.getParameters('My_SQL_IP')
    My_SQL_USERNAME = confloader.getParameters('My_SQL_USERNAME')
    My_SQL_PASSWORD = confloader.getParameters('My_SQL_PASSWORD')
    My_SQL_DB_NAME = confloader.getParameters('My_SQL_DB_NAME')
    My_SQL_DB_PORT = confloader.getParameters('My_SQL_DB_PORT')

    try:
        conn=MySQLdb.connect(host = My_SQL_IP, 
			     user = My_SQL_USERNAME, 
			     passwd = My_SQL_PASSWORD, 
			     db = My_SQL_DB_NAME,
			     port = int(My_SQL_DB_PORT))
        cur = conn.cursor()

        cur.execute(sql)
        data = cur.fetchall()

        cur.close()
        conn.close()

        return data
    except Exception, e:
        print Exception, e
	print 'sqldb.py exception'
    return


# for table of ioc_idu
def checkBlack(black):
    sql = 'select ITEM from ioc_idu where ITEM in'

    result = ""

    ips = ""
    index = 0
    for ip in black:
        if index < 100:
            ips = ips + "'" + ip + "'" + ","
            index = index + 1
        else:
	    tmpSql = ''
            tmpSql = sql + " (" + ips[0: (len(ips) - 1)] + ")"
            data = executeSql(tmpSql)
            result = result + str(data)

            ips = ""
	    index = 0

    if index > 0:
	tmpSql = ''
        tmpSql = sql + " (" + ips[0: (len(ips) - 1)] + ")"
	data = executeSql(tmpSql)
        result = result + str(data)
    
    return result


if __name__ == '__main__':
    print 'sss'

    IPS = {'139412.3322.org'}
    
    print checkBlack(IPS)
