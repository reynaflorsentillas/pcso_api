import xmlrpclib

# ODOO SERVER CONNECTION
# odoo_URL = 'http://45.76.236.40:8069'
# odoo_DB = 'PCSO_DEV'
# odoo_USER = 'admin'
# odoo_PASS = 'S1mple99'

odoo_URL = 'http://192.168.254.100:8069'
odoo_DB = 'PCSO'
odoo_USER = 'admin@admin.com'
odoo_PASS = 'admin'


common = xmlrpclib.ServerProxy('{}/xmlrpc/2/common'.format(odoo_URL))
uid = common.authenticate(odoo_DB, odoo_USER, odoo_PASS, {})
models = xmlrpclib.ServerProxy('{}/xmlrpc/2/object'.format(odoo_URL))
