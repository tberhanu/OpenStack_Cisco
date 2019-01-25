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
import requests
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from os import path


""" not finished, waiting for API from aws team"""


def delete_project(pid, table, platform):
	"""
	This method is to delete the project details from dynamo DB in aws
	:param pid: projectid of the project that need to be deleted from the dynamodb
	:param table: dynamoDB table object
	:return: none
	"""
	project_id = platform + ":" + pid
	try:
		print("LOG: Deleting project iteam in dynamoDB with id %s " % project_id)
		responce = table.delete_item(Key={'id': project_id})
	except ClientError as e:
		print("ERROR: cannont perform delete operation on dynamoDB for id : %s" % pid)
		print(e.responce['Error']['Message'])
		flag = False


""" not finished, waiting for API from aws team"""
def reading_table(region_url,table):
	"""
    This method is to read the items from the dynamodb table based on the region_name
    :param region_name:  region name used to get the iteams from table
    :param table: dynamoDb table object
    :return: list with project id's from dynamoDB based on region_name
    """
	try:
		print("LOG: Scanning dynamoDB table based on region url %s" % region_url)
		response = table.scan(
			ProjectionExpression="#pid",
			ExpressionAttributeNames={"#pid":"id"},
			FilterExpression=Key('url').eq(region_url)
		)
		projectid_list = []
		for i in response['Items']:
			project_id = i['id'].split(":")[1]
			projectid_list.append(project_id)
		return projectid_list
	except ClientError as e:
		print("ERROR: cannot read dynamoDB table")
		print(e.response['Error']['Message'])
		flag = False
		return False


# Referred from AWS DOCUMENTS
def sign(key, msg):
	return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


# Referred from AWS Documents
def getSignatureKey(key, date_stamp, regionName, serviceName):
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
    :return: flag: true or false for succesful update
    :return: item_success,item_unsuccess,item_unknown: counter values for no of projects added to dynamoDB
    """
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

    if path.exists(regionfile_name):
		#reading project id details from the projectfile into a list
		index = '"ID","Name","Enabled"'
		projects = open(regionfile_name,"r")
		projlist = []
		lines = projects.readlines()
		#storing all the project id's as a list 
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
		for projectline in lines:
			if projectline.strip() == index:
				pass
			else:
				if platform == "P3":
					project = projectline.strip().split(",")
					project_id = project[0][1:-1]
					project_name = project[1][1:-1]
					project_status = str(project[2])
					#print(project_status)
				elif platform == "CAE":
					project = projectline.strip().split(" ")
					project_id = project[0]
					project_name = project[1]
					project_status = str(project[2])
				if project_status not in ("True", "Active"):
					print ("this project is not active: %s" % project_name)
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
						
						print("LOG: adding project with id: %s , Name: %s to dynamoDB table " % (project_id, project_name))
						request_parameters = ('{"id":"%s","accountType":"%s","url":"%s","name":"%s","contact": { "alternate_email": "%s","email": "%s"} }')% (project_id,platform,region_url,project_name,contact,contact)
						
						payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()
						canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
						
						algorithm = 'AWS4-HMAC-SHA256'
						credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
						
						string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
						signing_key = getSignatureKey(secret_key, date_stamp, region, service)
						signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
						
						authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
						api_key = os.environ["AWS_API_KEY"]
						headers = {'Content-Type': content_type, 'X-Amz-Date': amz_date, 'x-api-key': api_key, 'Authorization': authorization_header}

						print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
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
		return flag,item_success,item_unsuccess,item_unknown
    else:
		print("ERROR: file does not exist %s" % regionfile_name)
		flag = False
		return flag, item_success, item_unsuccess, item_unknown
