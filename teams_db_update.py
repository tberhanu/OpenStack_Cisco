#!/usr/bin/python
"""
--------------------------teams_db_update.py-------------------------
Description: This script contains all the functions for updating, deleting and reading dynamoDB table items 

dependency: None

Author: Ravi Gujja

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------
"""


import boto3
import decimal
import datetime
import os
from boto3.dynamodb.conditions import Key, Attr
import xml.etree.ElementTree as ET
from os import path


"""
----- conecting to AWS dynamo db with API endpoint-----
#for this might need to configure aws keys
TABLE_NAME = "testprojectlist-ravi"
dynamodb = boto3.resource('dynamodb', region_name='us-east-1', endpoint_url="http://dynamodb.us-east-1.amazonaws.com")
table = dynamodb.Table(TABLE_NAME)
"""
"""
#accessing dynamodb using AWS keys
table_name = "testprojectlist-ravi"
session = boto3.Session(aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"], aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"], region_name='us-east-1')
ddb=session.resource("dynamodb")
table = ddb.Table(table_name)
"""
def delete_project(pid,table):
	"""
    This method is to delete the project details from dynamo DB in aws
    :param pid: projectid of the project that need to be deleted from the dynamodb
    :param table: dynamoDB table object
    :return: none
    """
	project_id = pid
	try:
		print("LOG: Deleting project iteam in dynamoDB with id %s" % project_id)
		responce = table.delete_item(Key = {'project-id' : project_id})
	except ClientError as e:
		print("ERROR: cannont perform delete operation on dynamoDB for id : %s" % project_id)
		print(e.responce['Error']['Message'])

def reading_table(region_name,table):
	"""
    This method is to read the items from the dynamodb table based on the region_name
    :param region_name:  region name used to get the iteams from table
    :param table: dynamoDb table object
    :return: list with project id's from dynamoDB based on region_name
    """
	try:
		print("LOG: Scanning dynamoDB table based on region name %s" % region_name)
		response = table.scan(
			ProjectionExpression="#pid",
			ExpressionAttributeNames={"#pid":"project-id"},
			FilterExpression=Key('region').eq(region_name)
		)
		projectid_list = []
		for i in response['Items']:
			projectid_list.append(i['project-id'])
		return projectid_list
	except ClientError as e:
		print("ERROR: cannot read dynamoDB table")
		print(e.response['Error']['Message'])

	

def update_dynamodb(regionfile_name,region_name,region_url,contact,table):
	"""
    This method is to update the items on dynamoDB table
    :param regionfile_name:  project filename which contain list of projects wrt region
    :param region_name: region name
    :param region_url: region url
    :param contact: contact details to update database table
    :param table: dynamoDB table object
    :return: none
    """
	if path.exists(regionfile_name):
		#reading project id details from the projectfile into a list
		projects = open(regionfile_name,"r")
		projlist = []
		lines = projects.readlines()
		for projectline in lines:
			project = projectline.strip().split(" ")
			projlist.append(project[0])
		#updating the projectfile details into dynamoDB	
		for proj in projects:
			tstamp=str(datetime.datetime.now().date())+':'+str(datetime.datetime.now().time())
			project = proj.strip().split(" ")
			status =  project[2]
			project_id = project[0]
			project_name = str(project[1])
			if status != "True":
				print ("this project is not active: " + project_name)
			else:
				try:
					print("LOG: adding project with id %s to dynamoDB table " % project_id )
					table.put_item(
						Item = {
							'project-id' : project_id,
							'project-name' : project_name,
							'status' : status,
							'region' : region_name,
							'Api-url' : region_url,
							'contact' : contact,
							'timestamp' : tstamp
						}
					)
				except ClientError as e:
					print("ERROR: cannot put items into dynamoDB table")
					print(e.response['Error']['Message'])
		#reading dynamodb table into list
		dblist = reading_table(region_name,table)
		for pid in dblist:
			if pid not in projlist:
				print("LOG: Deleteing project details from dynamoDB with id %s" % pid)
				delete_project(pid,table)

	else:
		print("ERROR: file does not exist %s" % regionfile_name)