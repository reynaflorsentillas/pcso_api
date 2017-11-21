import sys, os
import base64

# import MySQLdb
import xmlrpc

from datetime import datetime

import time

import requsets

def get_products():
	start = time.time()

	product_count = 0

	check_product = xmlrpc.models.execute_kw(xmlrpc.odoo_DB, xmlrpc.uid, xmlrpc.odoo_PASS, 'product.product', 'search_read', 
		[[['active', '=', True]]],
		{'fields': ['name', 'default_code']})

	for product in check_product:
		product_count += 1

	end = time.time()
	execution_time = end - start
	print "DONE! Total number of records fetched: " + str(product_count) + ". EXECUTION TIME (seconds): " + str(execution_time)

path = os.path.dirname(os.path.abspath(sys.argv[0]))
logfile = 'log.txt'

get_products()
