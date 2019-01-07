#!/usr/bin/python

"""
--------------------------p3_os_image_hardening_tc_1.py-------------------------
Description: This python script is to list all the images in the tenant account and
            validate the image are from the trusted source or not. This method check the
            visibility status of the images used in the servers and the unused images contain
            in the tenant account.

Author: Devaraj Acharya <devaacha@cisco.com>; January 6th, 2018

Copyright (c) 2019 Cisco Systems.
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

def list_images(conn):
    """
    This main method is to list all the images in the openstack project
    :param conn: connectivity to P3 platform
    :return: PASS or FAIL
    """
    try:
        images = {}
        for image in conn.image.images():
            img = json.dumps(image)
            out = json.loads(img)
            images[out['id']] = out
        return images
    except IOError as e:
        print("ERROR: Failed to retrieve image list with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of used images due to %s" % str(err))

def list_servers(conn, images, project_name, os_auth_url):
    """
    This main method is to list the servers in the openstack project along with the details of server
    and the associated image detail.
    :conn: connectivity to the platform
    :param os_auth_url: OpenStack's Horizon URL
    :images: list_images
    :param project_name: Project name
    """
    try:
        servers = []
        for server in conn.compute.servers():
            srvr = json.dumps(server)
            pull = json.loads(srvr)
            image = images[pull['image']['id']]
            address = pull['addresses'][project_name][0]
            servers.append({
                "id": pull['id'],
                "tenant_id": pull['project_id'],
                "tenant_name": project_name,
                "tenant_url":  os_auth_url,
                "image_id": image['id'],
                "image_name": image['name'],
                "vm_name": pull['name'],
                "unsecured": image['visibility'] == 'private',
                "direct_url": image['direct_url'],
                "image_updated_at": image['updated_at'],
                "vm_availability_zone": pull['availability_zone'],
                "vm_created_at": pull['created_at'],
                "vm_ip_address": address['addr'],
                "vm_host_id": pull['host_id'],
                "vm_user_id": pull['user_id']
            })
        with open('list_servers.csv','w') as file:
            file.writelines(json.dumps(servers))
            file.writelines('\n ')
            file.close()
        #print(json.dumps(servers, sort_keys=False, indent=2))
        return servers
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))

def list_private_servers(servers):
    """
    This method is to list the servers with the unsecured images and their details.
    :param servers: list_servers
    :return: PASS or FAIL
    """
    try:
        flag = "Fail"
        private_servers = []
        for server in servers:
            if (server['unsecured'] == True):
                private_servers.append(server)
                flag = "Fail"
        with open('private_servers.csv','w') as file:
            file.writelines(json.dumps(private_servers))
            file.writelines('\n ')
            file.close()
        #print(json.dumps(private_servers, sort_keys=False, indent=2))
        return private_servers
    except IOError as e:
        print("ERROR: Failed to retrieve private servers list with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of private servers list due to %s" % str(err))

def list_unused_images(conn, images, servers, project_name, os_auth_url):
    """
    This main method is to list all the unused images in the openstack project.
    :param conn: connectivity to the platform
    :param images: list_images
    :param servers: list_servers
    :param os_auth_url: OpenStack's Horizon URL
    :param project_name: Project name
    """
    try:
        unused_images = []
        all_image_ids = []
        used_image_ids = []
        unused_image_ids = {}
        for image in conn.image.images():
            all_image_ids.append(image['id'])
        for server in servers:
            used_image_ids.append(server['image_id'])
        unused_image_ids = set(all_image_ids).difference(set(used_image_ids))
        for unused_image_id in unused_image_ids:
            image = images[unused_image_id]
            unused_images.append({
                "owner_id": image['owner_id'],
                "tenant_name": project_name,
                "tenant_external_url": os_auth_url,
                "image_id": image['id'],
                "image_name": image['name'],
                "visibility": image['visibility'],
                "unused": unused_image_ids != None,
                "direct_url": image['direct_url'],
                "updated_at": image['updated_at']
            })
        with open('unused_images.csv','w') as file:
            file.writelines(json.dumps(unused_images))
            file.writelines('\n ')
            file.close()
        #print(json.dumps(unused_images, sort_keys=False, indent=2))
        return unused_images
    except IOError as e:
        print("ERROR: Failed to retrieve unused image list with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of unused images due to %s" % str(err))

def list_unused_private_images(unused_images):
    """
    This method is to list the unused unsecured images.
    :param unused_images: list_unused_images
    :return: PASS or FAIL
    """
    try:
        flag = "Fail"
        unused_private_images = []
        for image in unused_images:
            if (image['visibility'] != 'public'):
                unused_private_images.append(image)
                #print unused_private_images
                flag = "Fail"
            else:
                #print("This tenant has no unused private images.")
                flag = "Pass"
        with open('unused_private_images.csv','w') as file:
            file.writelines(json.dumps(unused_private_images))
            file.writelines('\n ')
            file.close()
        return unused_private_images
    except IOError as e:
        print("ERROR: Failed to retrieve unused private image list with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of unused private images due to %s" % str(err))

def list_all_images(conn, project_name, os_auth_url):
    """
    Method to fetch out the all images details in the openstack project
    :param conn: established the connection
    :param project_name:
    :param os_auth_url:
    :return: PASS or FAIL
    """
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
        with open('image_detail.csv','w') as file:
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
    """
    Method to fetch out the all unsecured images details in the openstack project
    :param all_images_list: list_all_images
    :return: PASS or FAIL
    """
    try:
        flag = "Fail"
        all_unsecured_images = []
        for image in all_images_list:
            if (image['visibility'] != 'public'):
                all_unsecured_images.append(image)
               # print("List of private images in the project are")
               # print all_unsecured_images
                flag = "Fail"
            else:
                flag = "Pass"
        with open('all_unsecured_images.csv','w') as file:
            file.writelines(json.dumps(all_unsecured_images))
            file.writelines('\n ')
            file.close()
        return flag
        return all_unsecured_images
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))

def main(os_auth_url, project_name):
    """
    This main method is to validate the source of images listed in the provided OpenStack Project is
    secured or unsecured [(visibility ="Public") = secured & (visibility = "private") = unsecured]
    :param os_auth_url: OpenStack's Horizon URL
    :param project_name: Project name
    :return: PASS or FAIL
    """
    try:
        conn = openstack.connect(
                                auth_url=os_auth_url,
                                project_name=project_name,
                                username=env['USERNAME'],
                                password=env['PASSWORD'],
                                region_name=os_auth_url.split(".")[0].split("//")[1])
    except Exception as e:
        print("Connection failed with error => %s" % str(e))

    images = list_images(conn)
    servers = list_servers(conn, images, project_name, os_auth_url)
    private_servers = list_private_servers(servers)
    unused_images = list_unused_images(conn, images, servers, project_name, os_auth_url)
    unused_private_images = list_unused_private_images(unused_images)
    all_images_list = list_all_images(conn, project_name, os_auth_url)
    all_unsecured_images = unsecured_images_list(all_images_list)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the images listed in OpenStack Project...")
    parser.add_argument("-u", "--auth_url", help="OpenStack Horizon URL", action="store", dest="url")
    parser.add_argument("-t", "--team_id", help="Project/Tenant ID", action="store", dest="team")
    args = parser.parse_args()
    url = args.url
    p_name = args.team
    main(url, p_name)
