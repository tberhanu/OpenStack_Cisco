#!/usr/bin/python

"""
--------------------------p3_os_image_hardening_tc_1.py-------------------------
Description: This python script is to list all the servers(VMs/Instances) and to list unused images 
            in the servers and to identify the visibility status of the unused images.

Author: Devaraj Acharya <devaacha@cisco.com>; December 30th, 2018

Copyright (c) 2018 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------
"""
import sys
import argparse
import os, subprocess
import datetime
import openstack
import json
from datetime import datetime
from os import environ as env
    
def list_images(conn, project_name, os_auth_url):
    #Method to fetch out the image details in the openstack project
    #param conn: established the connection
    #param project_name:
    #param os_auth_url:
    #:return: image details
    try:
        all_images_list = []
        for image in conn.image.images():
            img = json.dumps(image)
            out = json.loads(img)
            all_images_list.append({
                "owner_id": out['owner_id'],
                "tenant_name": project_name,
                "tenant_external_url": os_auth_url,
                "image_id":  out['id'], 
                "image_name": out['name'], 
                "visibility": out['visibility'], "status": out['status']
            })
        with open('image_detail.txt','w') as file:
            file.writelines(json.dumps(all_images_list))
            file.writelines('\n ')
            file.close()
        #print all_images_list
        return all_images_list
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))
def unsecured_images_list(all_images_list):
    try:
        flag = "Fail"
        all_unsecured_images = []
        for image in all_images_list:
            if (image['visibility'] != 'public'):
                all_unsecured_images.append(image)
                print("List of private images in the project are")
                print all_unsecured_images
                flag = "Fail"
            else:
                flag = "Pass"
        return all_unsecured_images
        if flag == "Pass":
            print("All the images are from trusted source.")
        else:
            flag = "Fail"
        return flag
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))

def main(os_auth_url, project_name):
    #This main method is to validate if the source of images listed in
    #the provided OpenStack Project is "public" or "non-public"
    #param os_auth_url:
    #param project_name:
    try:
        conn = openstack.connect(
                                auth_url=os_auth_url,
                                project_name=project_name,
                                username=env['USERNAME'],
                                password=env['PASSWORD'],
                                region_name=os_auth_url.split(".")[0].split("//")[1])                            
    except Exception as e:
        print("Connection failed with error => %s" % str(e))
    all_images_list = list_images(conn, project_name, os_auth_url)
    all_unsecured_images = unsecured_images_list(all_images_list)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the images listed in OpenStack Project...")
    parser.add_argument("-u", "--auth_url", help="OpenStack Horizon URL", action="store", dest="url")
    parser.add_argument("-t", "--team_id", help="Project/Tenant ID", action="store", dest="team")
    args = parser.parse_args()
    url = args.url
    p_name = args.team
    main(url, p_name)