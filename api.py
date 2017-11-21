from flask import Flask, jsonify, request, url_for, g
from flask_restful import Resource, Api

from flask_sqlalchemy import SQLAlchemy

from werkzeug.exceptions import HTTPException, default_exceptions,  Aborter

from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from passlib.apps import custom_app_context as pwd_context
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

import xmlrpc

import datetime
import json

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'

db = SQLAlchemy(app)
abort = Aborter()

# ENCRYPTION / DATA SECURITY
# from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto import Random
from Crypto.Util import Counter
import hashlib
# import base64
import binascii

# password = 'super-secret'
# key = hashlib.sha256(password).digest()

# key = 'abc123ty9TW1abc123ty9TW1'
# IV = 16 * '\x00'
# mode = AES.MODE_CBC
# encoder = PKCS7Encoder()

key = "abc123ty9TW1abc123ty9TW1"

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class User(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.String(32), index = True)
	password_hash = db.Column(db.String(128))

	def hash_password(self, password):
		self.password_hash = pwd_context.encrypt(password)

	def verify_password(self, password):
		return pwd_context.verify(password, self.password_hash)

	def generate_auth_token(self, expiration = 600):
		s = Serializer(app.config['SECRET_KEY'], expires_in = expiration)
		return s.dumps({ 'id': self.id })

	@staticmethod
	def verify_auth_token(token):
		s = Serializer(app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except SignatureExpired:
			return None # valid token, but expired
		except BadSignature:
			return None # invalid token
		user = User.query.get(data['id'])
		return user

db.create_all()

@auth.verify_password
def verify_password(username_or_token, password):
	# first try to authenticate by token
	user = User.verify_auth_token(username_or_token)
	if not user:
		# try to authenticate with username/password
		user = User.query.filter_by(username = username_or_token).first()
		if not user or not user.verify_password(password):
			return False
	g.user = user
	return True

# @app.route('/api/get_key', methods = ['GET'])
# def get_key():

@app.route('/api/encrypt', methods = ['GET'])
def encrypt():
	data = request.args.get('data')
	# encryptor = AES.new(key, mode, IV=IV)
	# encryptor.block_size = 128
	# pad_text = encoder.encode(data)
	# cipher = encryptor.encrypt(pad_text)
	# enc_cipher = base64.b64encode(cipher)
	# return enc_cipher

	m = hashlib.md5()
	m.update(key)
	cipher = DES3.new(m.digest())

	# enc = cipher.encrypt(pad(data))
	enc = binascii.hexlify(cipher.encrypt(pad(data)))
	# return base64.b64encode(enc)
	return enc


@app.route('/api/decrypt', methods = ['GET'])
def decrypt():
	data = request.args.get('data')
	# decryptor = AES.new(key, mode, IV=IV)
	# decryptor.block_size = 128
	# pad_text = base64.b64decode(data)
	# cipher = decryptor.decrypt(pad_text)
	# plain_text = encoder.decode(cipher)
	# return plain_text

	# DES3
	m = hashlib.md5()
	m.update(key)
	cipher = DES3.new(m.digest())
	# pad_text = base64.b64decode(data)
	pad_text = binascii.unhexlify(data)
	dec = unpad(cipher.decrypt(pad_text))
	return dec

def encryptor(data):
	m = hashlib.md5()
	m.update(key)
	cipher = DES3.new(m.digest())

	# enc = cipher.encrypt(pad(data))
	enc = binascii.hexlify(cipher.encrypt(pad(data)))
	# return base64.b64encode(enc)
	return enc

def decryptor(data):
	m = hashlib.md5()
	m.update(key)
	cipher = DES3.new(m.digest())
	# pad_text = base64.b64decode(data)
	pad_text = binascii.unhexlify(data)
	dec = unpad(cipher.decrypt(pad_text))
	return dec

@app.route('/api/users', methods = ['POST'])
def new_user():
	username = request.args.get('username')
	password = request.args.get('password')
	if username is None or password is None:
		abort(400) # missing arguments
	if User.query.filter_by(username = username).first() is not None:
		abort(400) # existing user
	user = User(username = username)
	user.hash_password(password)
	db.session.add(user)
	db.session.commit()
	# return jsonify({ 'username': user.username }), 201, {'Location': url_for('get_user', id = user.id, _external = True)}
	return jsonify({ 'username': user.username }), 201

@app.route("/api/login", methods=['POST','GET'])
def login():
	# here we want to get the value of user (i.e. ?user=some-value)
	username = request.args.get('username')
	password = request.args.get('password')
	if username and password:
		if verify_password(username, password) == True:
			token = g.user.generate_auth_token()
			return jsonify({ 'token': token.decode('ascii') })
			# return jsonify({'status':'success','token':token})
		else:
			return jsonify({'status':'error','message':'Invalid Login'})
	else:
		return jsonify({'status':'error','message':'Login Details Required'})

# BUDGET ALLOCATION
@app.route("/api/get_budget_allocation", methods=['POST','GET'])
# @auth.login_required
def get_budget_allocation():
	token = request.args.get('token')
	if not token:
		budget_allocation = xmlrpc.models.execute_kw(xmlrpc.odoo_DB, xmlrpc.uid, xmlrpc.odoo_PASS, 'pcso.budget.allocation', 'search_read', [[]], {'fields': ['branch_id', 'branch_name', 'alloted_budget', 'budget_date']})
		if budget_allocation:
			return jsonify(budget_allocation)
		else:
			return jsonify({'status':'error','code':'005','message':'CANNOT RETRIEVE BUDGET ALLOCATION FOR THE DAY.'})
	# else:
	# 	return jsonify({'status':'error','code':'100','message':'Unauthorized Access'})

# COMMIT TRANSACTION
@app.route("/api/commit_transaction", methods=['POST','GET'])
# @auth.login_required
def commit_transaction():
	# token = request.args.get('token')
	# applicant_id = request.args.get('applicant_id')
	# application_id = request.args.get('application_id')
	# gl_number = request.args.get('gl_number')
	# patient_name = request.args.get('patient_name')
	# assistance_id = request.args.get('assistance_id')
	# specific_assistance_id = request.args.get('specific_assistance_id')
	# approved_assistance_amount = request.args.get('approved_assistance_amount')
	# medical_institution_id = request.args.get('medical_institution_id')
	# branch_id = request.args.get('branch_id')
	# application_date = request.args.get('application_date')
	# date_approved = request.args.get('date_approved')
	# transaction_code = request.args.get('transaction_code')

	# For Encrypted Data
	data = request.args.get('data')
	if data:
		raw_data = decryptor(data)
		# return raw_data
		# raw_data = jsonify(raw_data)
		json_data = json.loads(raw_data)
		if json_data:
			applicant_id = json_data['applicant_id']
			application_id = json_data['application_id']
			gl_number = json_data['gl_number']
			patient_name = json_data['patient_name']
			assistance_id = json_data['assistance_id']
			specific_assistance_id = json_data['specific_assistance_id']
			approved_assistance_amount = json_data['approved_assistance_amount']
			medical_institution_id = json_data['medical_institution_id']
			branch_id = json_data['branch_id']
			application_date = json_data['application_date']
			date_approved = json_data['date_approved']
			transaction_code = json_data['transaction_code']

			if gl_number:
				# Check if GL number exists
				transaction_exist = xmlrpc.models.execute_kw(xmlrpc.odoo_DB, xmlrpc.uid, xmlrpc.odoo_PASS, 'pcso.transaction', 'search_read', [[['name', '=', gl_number]]], {'fields': ['name'], 'limit': 1})
				if transaction_exist:
					return jsonify({'status':'error','code':'002','message':'TRANSACTION EXISTS.'})
				else:
					transaction_create = xmlrpc.models.execute_kw(xmlrpc.odoo_DB, xmlrpc.uid, xmlrpc.odoo_PASS, 'pcso.transaction', 'create', [{
						'applicant_id': applicant_id,
						'application_id': application_id,
						'name': gl_number,
						'patient_name': patient_name,
						'assistance_id': assistance_id,
						'specific_assistance_id': specific_assistance_id,
						'approved_assistance_amount': approved_assistance_amount,
						'medical_institution_id': medical_institution_id,
						'branch_id': branch_id,
						'application_date': application_date,
						'date_approved': date_approved,
						'transaction_code': transaction_code,
					}])
					if transaction_create:
						return jsonify({'status':'success','message':'TRANSACTION SAVED!'})
					else:
						return jsonify({'status':'error','code':'003','message':'TRANSACTION SAVING FAILED.'})
			else:
				return jsonify({'status':'error','code':'101','message':'GL number is required.'})

# REVERSE TRANSACTION
@app.route("/api/reverse_transaction", methods=['POST','GET'])
def reverse_transaction():
	# token = request.args.get('token')
	# gl_number = request.args.get('gl_number')
	# reverse_transaction = request.args.get('reverse_transaction')
	# reverse_reason = request.args.get('reverse_reason')

	# For Encrypted Data
	data = request.args.get('data')
	if data:
		raw_data = decryptor(data)
		json_data = json.loads(raw_data)
		if json_data:
			gl_number = json_data['gl_number']
			reverse_transaction = json_data['reverse_transaction']
			reverse_reason = json_data['reverse_reason']

			if gl_number:
				transaction_id = xmlrpc.models.execute_kw(xmlrpc.odoo_DB, xmlrpc.uid, xmlrpc.odoo_PASS, 'pcso.transaction', 'search_read', [[['name', '=', gl_number]]], {'fields': ['name'], 'limit': 1})
				if transaction_id:
					for transaction in transaction_id:
						transaction_update = xmlrpc.models.execute_kw(xmlrpc.odoo_DB, xmlrpc.uid, xmlrpc.odoo_PASS, 'pcso.transaction', 'write', [[transaction['id']], {
							'reverse_transaction': reverse_transaction,
							'reverse_reason': reverse_reason,
							'reverse_date': datetime.datetime.now(),
							'state': 'cancel',
							}])
						return jsonify({'status':'success','message':'REVERSAL SUCCESS!'})
				else:
					return jsonify({'status':'error','code':'001','message':'TRANSACTION DOES NOT EXIST.'})
			else:
				jsonify({'status':'error','code':'101','message':'GL number is required.'})

# GET TRANSACTION CODE
@app.route("/api/get_transaction_code", methods=['POST','GET'])
def get_transaction_code():
	# token = request.args.get('token')
	# if not token:
	transaction_code = xmlrpc.models.execute_kw(xmlrpc.odoo_DB, xmlrpc.uid, xmlrpc.odoo_PASS, 'pcso.transaction.type', 'search_read', [[]], {'fields': ['name', 'code']})
	if transaction_code:
		return jsonify(transaction_code)
	else:
		return jsonify({'status':'error','code':'004','message':'CANNOT RETRIEVE TRANSACTION CODES.'})
	# else:
	# 	return jsonify({'status':'error','message':'Unaauthorized Access'})

# GL CHECK INQUIRY
@app.route("/api/gl_check_inquiry", methods=['POST','GET'])
# @auth.login_required
def gl_check_inquiry():
	# token = request.args.get('token')
	# gl_number = request.args.get('gl_number')

	# For Encrypted Data
	data = request.args.get('data')
	if data:
		raw_data = decryptor(data)
		json_data = json.loads(raw_data)
		if json_data:
			gl_number = json_data['gl_number']

			if gl_number:
				transaction_id = xmlrpc.models.execute_kw(xmlrpc.odoo_DB, xmlrpc.uid, xmlrpc.odoo_PASS, 'pcso.transaction', 'search_read', [[['name', '=', gl_number]]], {'fields': ['name', 'check_number', 'bank', 'check_amount', 'date_check_created', 'branch_id'], 'limit': 1})
				if transaction_id:
					for transaction in transaction_id:
						check_number = transaction['check_number']
						bank = transaction['bank']
						check_amount = transaction['check_amount']
						date_check_created = transaction['date_check_created']
						branch_id = transaction['branch_id']

						if check_number:
							return jsonify({'gl_number':gl_number,'check_number':check_number,'bank':bank,'check_amount':check_amount,'date_check_created':date_check_created,'branch_id':branch_id})
						else:
							return jsonify({'status':'success','message':'NO CHECK AVAILABLE YET.'})
				else:
					return jsonify({'status':'error','code':'001','message':'TRANSACTION DOES NOT EXIST.'})
			else:
				return jsonify({'status':'error','code':'101','message':'GL number is required.'})
	# else:
	# 	return jsonify({'status':'error','code':'100','message':'Unaauthorized Access'})

# GL CHECK STATUS
@app.route("/api/gl_check_status", methods=['POST','GET'])
# @auth.login_required
def gl_check_status():
	# token = request.args.get('token')
	# gl_number = request.args.get('gl_number')

	# For Encrypted Data
	data = request.args.get('data')
	if data:
		raw_data = decryptor(data)
		json_data = json.loads(raw_data)
		if json_data:
			gl_number = json_data['gl_number']

			if gl_number:
				transaction_id = xmlrpc.models.execute_kw(xmlrpc.odoo_DB, xmlrpc.uid, xmlrpc.odoo_PASS, 'pcso.transaction', 'search_read', [[['name', '=', gl_number]]], {'fields': ['name', 'check_number', 'bank', 'check_amount', 'date_check_created', 'branch_id', 'is_released', 'date_released'], 'limit': 1})
				if transaction_id:
					for transaction in transaction_id:
						check_number = transaction['check_number']
						bank = transaction['bank']
						check_amount = transaction['check_amount']
						date_check_created = transaction['date_check_created']
						branch_id = transaction['branch_id']
						is_released = transaction['is_released']
						date_released = transaction['date_released']
						if check_number and is_released == True:
							return jsonify({'gl_number':gl_number,'check_number':check_number,'bank':bank,'is_released':is_released,'date_released':date_released,'branch_id':branch_id})
						else:
							return jsonify({'status':'success','message':'NO CHECK AVAILABLE YET.'})
				else:
					return jsonify({'status':'error','code':'001','message':'TRANSACTION DOES NOT EXIST.'})
			else:
				return jsonify({'status':'error','code':'101','message':'GL number is required'})
	# else:
	# 	return jsonify({'status':'error','code':'100','message':'Unauthorized Access'})

# @app.route("/api/get_api_error_matrix", methods=['POST','GET'])
# # @auth.login_required
# def get_api_error_matrix():
# 	token = request.args.get('token')
# 	if token:
		
# 	else:
# 		return jsonify({'status':'error','code':'100','message':'Unauthorized Access'})

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=8095)