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
from botocore.exceptions import ClientError
import xml.etree.ElementTree as ET
from os import path

def delete_project(pid,table):
	"""
    This method is to delete the project details from dynamo DB in aws
    :param pid: projectid of the project that need to be deleted from the dynamodb
    :param table: dynamoDB table object
    :return: none
    """
	project_id = "P3:" + pid
	try:
		print("LOG: Deleting project iteam in dynamoDB with id %s" % project_id)
		responce = table.delete_item(Key = {'id' : project_id})
	except ClientError as e:
		print("ERROR: cannont perform delete operation on dynamoDB for id : %s" % pid)
		print(e.responce['Error']['Message'])
		flage = False

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
		return None
	

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
	flag = True
	if path.exists(regionfile_name):
		#reading project id details from the projectfile into a list
		projects = open(regionfile_name,"r")
		projlist = []
		lines = projects.readlines()
		for projectline in lines:
			project = projectline.strip().split(" ")
			projlist.append(project[0])

		dblist = reading_table(region_url,table)

		#updating the projectfile details into dynamoDB	
		for proj in lines:
			tstamp=str(datetime.datetime.now().date())+':'+str(datetime.datetime.now().time())
			project = proj.strip().split(" ")
			status =  project[2]
			project_id = project[0]
			if project_id not in dblist:
				data_id ="P3:"+ project_id 
				project_name = str(project[1])
				if status != "True":
					print ("this project is not active: " + project_name)
				else:
					try:
						print("LOG: adding project with id %s to dynamoDB table " % project_id )
						table.put_item(
							Item = {
								'id' : data_id,
								'name' : project_name,
								'url' : region_url,
								'contact' : {"alternate_email" : contact,"email": contact}
							}
						)
					except ClientError as e:
						print("ERROR: cannot put items into dynamoDB table")
						print(e.response['Error']['Message'])
						flag = False 
		if dblist is not None:
			for pid in dblist:
				if pid not in projlist:
					#print("LOG: Deleteing project details from dynamoDB with id %s" % pid)
					delete_project(pid,table)
		return flag

	else:
		print("ERROR: file does not exist %s" % regionfile_name)
		flag = False
		return flag
