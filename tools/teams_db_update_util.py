#!opt/app-root/bin/python

"""
--------------------------teams_db_update_util.py-------------------------
Description: This script contains all the functions for updating, deleting and reading dynamoDB table items 

dependency: None

Author: Ravi Gujja

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------
"""

import os
import datetime
import hashlib
import hmac
import base64
import requests
import json
import sys
import urllib
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from os import path


""" not finished, waiting for API from aws team"""


def delete_project(pid,platform):
	"""
	This method is to delete the project details from dynamo DB in aws
	:param pid: projectid of the project that need to be deleted from the dynamodb
	:param table: dynamoDB table object
	:return: none
	"""
	item_sdelete = 0
	item_fdelete = 0
	item_udelete = 0
	try:
		print("LOG: Deleting project iteam in dynamoDB with id %s " % project_id)
		service = os.environ["AWS_SERVICE"]
		endpoint = os.environ["AWS_EXECUTE_API_URL"]
		region = os.environ["AWS_REGION"]
		method = 'PUT'
		uninstalled = "UNINSTALLED"
		#project_id = "ravi123456789"
		api_key = os.environ["AWS_API_KEY"]
		host = endpoint.split('/')[2]
		access_key = os.environ["AWS_ACCESS_KEY_ID"]
		secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]
		if access_key is None or secret_key is None:
			print('No access key is available.')

		t = datetime.datetime.utcnow()
		amz_date = t.strftime('%Y%m%dT%H%M%SZ')
		date_stamp = t.strftime('%Y%m%d')

		canonical_uri = os.environ["AWS_CANONICAL_URI"] + '/' + pid
		canonical_querystring = ''
		content_type = 'application/json'
		canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n'
		signed_headers = 'host;x-amz-date'

		request_parameters = ('{"accountType":"%s","csbFlag":"%s"}') % (platform,uninstalled)
		payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()

		canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
		algorithm = 'AWS4-HMAC-SHA256'
		credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
		string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
		signing_key = getSignatureKey(secret_key, date_stamp, region, service)
		signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
		authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
		headers = {'Content-Type': content_type, 'X-Amz-Date': amz_date, 'x-api-key': api_key, 'Authorization': authorization_header}

		print('\nBEGIN REQUEST+++++++++++++ PUT/Updating Database+++++++++++++++++++++++')
		print('Request URL = ' + endpoint)
		x= endpoint + '/' + pid
		r = requests.put(x, data=request_parameters, headers=headers)
		print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
		print('Response status_code: %d\n' % r.status_code)
		print(r.text)
		if r.status_code == 200:
			item_sdelete = item_sdelete + 1
			flag = True
		else:
			item_fdelete = item_fdelete + 1
			flag = False
		return flag, item_sdelete,item_fdelete,item_udelete
	except Exception as e:
		print("ERROR: cannont perform delete operation on dynamoDB for id : %s" % pid)
		print(e)
		flag = False
		item_udelete = item_udelete + 1
		return flag, item_sdelete,item_fdelete,item_udelete 


""" not finished, waiting for API from aws team"""
def reading_table(platform,region_url):
	"""
	This method is to read the items from the dynamodb table based on the region_name
	:param region_name:  region name used to get the iteams from table
	:param table: dynamoDb table object
	:return: list with project id's from dynamoDB based on region_name
	"""
	try:
		print("LOG: Scanning dynamoDB table based on region url %s" % region_url)
		service = os.environ["AWS_SERVICE"]
		endpoint = os.environ["AWS_EXECUTE_API_URL"] + "/"
		region = os.environ["AWS_REGION"]
		api_key = os.environ["AWS_API_KEY"]
		method = 'GET'
		host = endpoint.split('/')[2]
		access_key = os.environ["AWS_ACCESS_KEY_ID"]
		secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]
		if access_key is None or secret_key is None:
			print('No access key is available.')

		url = region_url.replace("/","%2F")
		url = url.replace(":","%3A")
		url = url.replace("@","%40")

		request_parameters = ("accountType=%s&url=%s" % (platform,url))
		request_parameters = ("url=%s" % (url))
		t = datetime.datetime.utcnow()
		amz_date = t.strftime('%Y%m%dT%H%M%SZ')
		date_stamp = t.strftime('%Y%m%d')

		canonical_uri = os.environ["AWS_CANONICAL_URI"] + "/"
		canonical_querystring = request_parameters.encode('utf-8')
		content_type = 'application/json'
		canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n'
		signed_headers = 'host;x-amz-date'

		payload_hash = hashlib.sha256(('')).hexdigest()
		canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

		algorithm = 'AWS4-HMAC-SHA256'
		credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
		string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' + hashlib.sha256(canonical_request).hexdigest()

		signing_key = getSignatureKey(secret_key, date_stamp, region, service)
		signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
		authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
		headers = {'Content_type':content_type, 'X-Amz-Date': amz_date, 'x-api-key': api_key, 'Authorization': authorization_header}

		print('\nBEGIN REQUEST++++++++++++Reading Database++++++++++++++++++++++++')
		print('Request URL = ' + endpoint)
		x = endpoint + '?' + request_parameters

		r = requests.get(x,headers=headers)
		print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
		print('Response status_code: %d\n' % r.status_code)
		#print(r.text)
		json_data = json.loads(r.text)
		plist = []
		if r.status_code == 200:
			for data in json_data:
				#print(data)
				db_id = data['id']
				pid = db_id.split(':')[1].strip()
				csb_flag = data['csbFlag']
				if csb_flag == "INSTALLED":
					#print (pid)
					plist.append(pid)
		else:
			plist = False
		print("INFO: No of projects in database for url %s : %s "%(region_url,len(plist)))
		return plist
	except Exception as e:
		print("ERROR: cannot read dynamoDB table")
		print(e)
		flag = False
		return False


# Referred from AWS DOCUMENTS
def sign(key, msg):
	return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


# Referred from AWS Documents
def getSignatureKey(key, date_stamp, regionName, serviceName):
	"""

	:param key:
	:param date_stamp:
	:param regionName:
	:param serviceName:
	:return:
	"""
	kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
	kRegion = sign(kDate, regionName)
	kService = sign(kRegion, serviceName)
	kSigning = sign(kService, 'aws4_request')
	return kSigning


def update_dynamodb(regionfile_name,region_name,region_url,contact,platform):
	"""
	This method is to update the items on dynamoDB table, Referred from AWS Documents for signing
	:param regionfile_name:  project filename which contain list of projects wrt region
	:param region_name: region name
	:param region_url: region url
	:param contact: contact details to update database table
	:param platform: Project Account Type
	:return: item_success, item_unsuccess, item_unknown, counter values for no of projects added to dynamoDB
	"""
	#reading project list from database
	db_plist = reading_table(platform,region_url)


	global project_id, project_status
	global item_success, item_unsuccess, item_unknown, item_success_delete, item_failed_delete, item_unknown_delete
	service = os.environ["AWS_SERVICE"]
	endpoint = os.environ["AWS_EXECUTE_API_URL"]
	region = os.environ["AWS_REGION"]
	method = 'POST'
	host = endpoint.split('/')[2]
	access_key = os.environ["AWS_ACCESS_KEY_ID"]
	secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]
	if access_key is None or secret_key is None:
		print('No access key is available.')
	flag = True
	item_success = 0
	item_unsuccess = 0
	item_unknown = 0
	item_success_delete = 0
	item_failed_delete = 0
	item_unknown_delete = 0

	if path.exists(regionfile_name):
		# reading project id details from the projectfile into a list
		index = '"ID","Name","Enabled"'
		projects = open(regionfile_name,"r")
		projlist = []
		lines = projects.readlines()
		# storing all the project id's as a list used for deleting
		#print("===================================list from file")
		for projectline in lines:
			if projectline.strip() == index:
				pass
			else:
				if platform == "P3":
					project = projectline.strip().split(",")
					projlist.append(project[0][1:-1])
				elif platform == "CAE":
					project = projectline.strip().split(" ")
					projlist.append(project[0])
					#print(project[0].strip())
		
		
		if db_plist is not False:
			for projectline in lines:
				if projectline.strip() == index:
					pass
				else:
					if platform == "P3":
						project = projectline.strip().split(",")
						project_id = project[0][1:-1]
						project_name = project[1][1:-1]
						project_status = str(project[2])
						# print(project_status)
					elif platform == "CAE":
						project = projectline.strip().split(" ")
						project_id = project[0]
						project_name = project[1]
						project_status = str(project[2])

					if db_plist is not None:
						if project_id not in db_plist:
							if project_status not in ("True", "Active"):
								print("this project is not active: %s" % project_name)
							else:
								try:
									t = datetime.datetime.utcnow()
									amz_date = t.strftime('%Y%m%dT%H%M%SZ')
									date_stamp = t.strftime('%Y%m%d')
									
									canonical_uri = os.environ["AWS_CANONICAL_URI"]
									canonical_querystring = ''
									content_type = 'application/json'
									
									canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n'
									signed_headers = 'host;x-amz-date'
									
									print("LOG: adding project with id: %s , Name: %s to dynamoDB table " % (project_id,
																											 project_name))
									request_parameters = ('{"id":"%s","accountType":"%s","url":"%s","name":"%s","contact": '
														  '{ "alternate_email": "%s","email": "%s"} }')\
														 % (project_id,platform,region_url,project_name,contact,contact)
									
									payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()
									canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' \
														+ canonical_headers + '\n' + signed_headers + '\n' + payload_hash
									
									algorithm = 'AWS4-HMAC-SHA256'
									credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
									
									string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' \
													 + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
									signing_key = getSignatureKey(secret_key, date_stamp, region, service)
									signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
									
									authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope \
														   + ', ' + 'SignedHeaders=' + signed_headers + ', ' \
														   + 'Signature=' + signature
									api_key = os.environ["AWS_API_KEY"]
									headers = {'Content-Type': content_type, 'X-Amz-Date': amz_date, 'x-api-key': api_key,
											   'Authorization': authorization_header}

									print('\nBEGIN REQUEST++++++++++++Posting to Database++++++++++++++++++++++++')
									print('Request URL = ' + endpoint)
									r = requests.post(endpoint, data=request_parameters, headers=headers)
									print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
									print('Response status_code: %d\n' % r.status_code)
									print(r.text)
									if r.status_code == 200:
										flag = True
										item_success = item_success + 1
									else:
										flag = False
										item_unsuccess = item_unsuccess + 1
								except Exception as e:
									print(e)
									flag = False
									item_unknown = item_unknown + 1
					else:
						print("LOG: dynamoDB table is empty, adding projects details")
						if project_status not in ("True", "Active"):
							print("this project is not active: %s" % project_name)
						else:
							try:
								t = datetime.datetime.utcnow()
								amz_date = t.strftime('%Y%m%dT%H%M%SZ')
								date_stamp = t.strftime('%Y%m%d')
								
								canonical_uri = os.environ["AWS_CANONICAL_URI"]
								canonical_querystring = ''
								content_type = 'application/json'
								
								canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n'
								signed_headers = 'host;x-amz-date'
								
								print("LOG: adding project with id: %s , Name: %s to dynamoDB table " % (project_id,
																										 project_name))
								request_parameters = ('{"id":"%s","accountType":"%s","url":"%s","name":"%s","contact": '
													  '{ "alternate_email": "%s","email": "%s"} }')\
													 % (project_id,platform,region_url,project_name,contact,contact)
								
								payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()
								canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' \
													+ canonical_headers + '\n' + signed_headers + '\n' + payload_hash
								
								algorithm = 'AWS4-HMAC-SHA256'
								credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
								
								string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' \
												 + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
								signing_key = getSignatureKey(secret_key, date_stamp, region, service)
								signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
								
								authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope \
													   + ', ' + 'SignedHeaders=' + signed_headers + ', ' \
													   + 'Signature=' + signature
								api_key = os.environ["AWS_API_KEY"]
								headers = {'Content-Type': content_type, 'X-Amz-Date': amz_date, 'x-api-key': api_key,
										   'Authorization': authorization_header}

								print('\nBEGIN REQUEST++++++++++++++Posting to Database++++++++++++++++++++++')
								print('Request URL = ' + endpoint)
								r = requests.post(endpoint, data=request_parameters, headers=headers)
								print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
								print('Response status_code: %d\n' % r.status_code)
								print(r.text)
								if r.status_code == 200:
									flag = True
									item_success = item_success + 1
								else:
									flag = False
									item_unsuccess = item_unsuccess + 1
							except Exception as e:
								print(e)
								flag = False
								item_unknown = item_unknown + 1

			#for deleting projects from db
			if db_plist is not None:
				for pid in db_plist:
					if pid not in projlist:
						print("projet need to be removed")
						flag, item_sdelete, item_fdelete, item_udelete = delete_project(pid,platform)
						item_success_delete = item_success_delete + item_sdelete
						item_failed_delete = item_failed_delete + item_fdelete
						item_unknown_delete = item_unknown_delete + item_udelete

			return flag, item_success, item_unsuccess, item_unknown, item_success_delete, item_failed_delete, item_unknown_delete
		else:
			print("ERROR: Not Updating DynamoDB, since unable to read data from dynamodb")
			flag = False
			return flag, item_success, item_unsuccess, item_unknown, item_success_delete, item_failed_delete, item_unknown_delete
	else:
		print("ERROR: file does not exist %s" % regionfile_name)
		flag = False
		return flag, item_success, item_unsuccess, item_unknown,  item_success_delete, item_failed_delete, item_unknown_delete
