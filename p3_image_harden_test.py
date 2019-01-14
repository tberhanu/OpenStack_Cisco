#!/usr/bin/python

"""
--------------------------p3_os_image_hardening_tc_1.py-------------------------
Description: This python script is to list all the images in the tenant account and
            validate the image are from the trusted source or not. This method check the
            visibility status of the images used in the servers and the unused images contain
            in the tenant account.

Author: Devaraj Acharya <devaacha@cisco.com>; January 8th, 2019

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------
"""
import sys
import pandas as pd
import argparse
import os, subprocess
import datetime
import openstack
import json
import os.path
import dateutil.parser
import csv
from os import environ as env
#from general_util import updateScanRecord, add_result_to_stream, send_result_complete

def list_images(conn):
    """
    This method is to list all the images in the openstack project
    :param conn: connectivity to the P3 platform
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
    and the associated image.
    :conn: connectivity to the P3 platform
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
            vm_created = dateutil.parser.parse(pull['created_at']).replace(tzinfo=None)
            vm_updated_days = datetime.datetime.now() - vm_created
            vm_updated_days = ("%s Days %s Hours %s Mins" % (vm_updated_days.days, vm_updated_days.seconds//3600, (vm_updated_days.seconds//60)%60))

            image_created = dateutil.parser.parse(image['updated_at']).replace(tzinfo=None)
            image_updated_days = datetime.datetime.now() - image_created
            image_updated_days = ("%s Days %s Hours %s Mins" % (image_updated_days.days, image_updated_days.seconds//3600, (image_updated_days.seconds//60)%60))
            
            addresses = pull['addresses']
            network_names = addresses.keys()
            server_network_name = network_names[0]
            address = pull['addresses'][server_network_name][0]
                        
            servers.append([
                        pull['id'],
                        pull['project_id'],
                        project_name,
                        os_auth_url,
                        image['id'],
                        image['owner_id'],
                        image['name'],
                        pull['name'],
                        image['visibility'] == 'private',
                        image['direct_url'],
                        image_updated_days,
                        pull['availability_zone'],
                        vm_updated_days,
                        address['addr'],
                        pull['host_id'],
                        pull['user_id']
            ])
        
        headers = ["VM Id", "Tenant Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Owner Id", "Image Name", "VM Name", "Unsecured", "Image Direct URL", "Image Updated Ago", "VM Availability Zone", "VM Updated Ago", "VM IP Address", "VM Host Id", "VM User Id"]
        with open('servers_list.csv', 'a') as f:
            file_is_empty = os.stat('servers_list.csv').st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(servers)
#       print(json.dumps(servers, sort_keys=False, indent=2))
        return servers
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))

def list_private_servers(servers):
    """
    This method is to list the servers with the unsecured images and their details.
    :param servers: list_servers(conn, images, project_name, os_auth_url)
    :return: Compliant or Non-compliant
    """
    try:
        flag1 = "Non-compliant"
        private_servers = []
        for server in servers:
            if (server[8] == True):
                private_servers.append(server)
        
        headers = ["VM Id", "Tenant Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Owner Id", "Image Name", "VM Name", "Unsecured", "Image Direct URL", "Image Updated Ago", "VM Availability Zone", "VM Updated Ago", "VM IP Address", "VM Host Id", "VM User Id"]
        with open('unsecured_server_list.csv', 'a') as f:
            file_is_empty = os.stat('unsecured_server_list.csv').st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(private_servers)

        if len(private_servers) == 0:
            print("LOG: VM test: Compliant\(Unsecured image is not used in VM\)")
            flag1 = "Compliant"
        else:
            print("LOG: VM test: Non-compliant\(Unsecured image is used in VM\)")
            flag1 = "Non-compliant"
        #print(json.dumps(private_servers, sort_keys=False, indent=2))
        return private_servers, flag1
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
    unused_images = []
    all_image_ids = []
    used_image_ids = []
    unused_image_ids = {}
    for image in conn.image.images():
        all_image_ids.append(image['id'])
    for server in servers:
        used_image_ids.append(server[4])
    unused_image_ids = set(all_image_ids).difference(set(used_image_ids))
    for unused_image_id in unused_image_ids:
        image = images[unused_image_id]
        unused_images.append([
                server[1],
                image['owner_id'],
                project_name,
                os_auth_url,
                image['id'],
                image['name'],
                image['visibility'],
                unused_image_ids != None,
                image['direct_url'],
                image['updated_at']
        ])
    headers = ["Tenant Id", "Image Owner Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Name", "Visibility", "Unused", "Direct URL", "Image_Updated_ago"]
    with open('unused_images_list.csv', 'a') as f:
            file_is_empty = os.stat('unused_images_list.csv').st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(unused_images)
    #print(json.dumps(unused_images, sort_keys=False, indent=2))
    return unused_images

def list_unused_private_images(unused_images):
    """
    This method is to list the unused unsecured images.
    :param unused_images: list_unused_images
    :return: Compliant or Non-compliant
    """
    try:
        flag2 = "Non-compliant"
        unused_private_images = []
        for image in unused_images:
            if (image[6] != 'public'):
                unused_private_images.append(image)
        
        headers = ["Tenant Id", "Image Owner Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Name", "Visibility", "Unused", "Direct URL", "Image_Updated_ago"]
        with open('unused_unsecured_images_list.csv', 'a') as f:
            file_is_empty = os.stat('unused_unsecured_images_list.csv').st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(unused_private_images)
        
        if len(unused_private_images) == 0:
            print("LOG: unused private images test: Compliant\(There is no unused unsecured images\)")
            flag2 = "Compliant"
        else:
            print("LOG: unused private images test: Non-compliant\(There is unused unsecured images\)")
            flag2 = "Non-compliant"
        #print(json.dumps(unused_private_images, sort_keys=False, indent=2))
        return unused_private_images, flag2
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
    :return: Compliant or Non-compliant
    """
    try:
        all_images_list = []
        for image in conn.image.images():
            img = json.dumps(image)
            out = json.loads(img)
            visibility = out['visibility']
            all_images_list.append([
                        out['owner_id'],
                        project_name,
                        os_auth_url,
                        out['id'],
                        out['name'],
                        out['visibility'], out['status']
            ])

        headers = ["Owner Id", "Tenant Name", "Tenant External Url", "Image Id", "Image Name", "Visibility", "Status"]
        with open('all_images_list.csv', 'a') as f:
            file_is_empty = os.stat('all_images_list.csv').st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(all_images_list)
        #print(json.dumps(all_images_list, sort_keys=False, indent=2))
        return all_images_list
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))

def unsecured_images_list(all_images_list):
    """
    Method to fetch out the all unsecured images details in the openstack project
    :param all_images_list: list_all_images
    :return: Compliant or Non-compliant
    """
    try:
        flag3 = "Non-compliant"
        all_unsecured_images = []
        for image in all_images_list:
            if (image[5] != 'public'):
                all_unsecured_images.append(image)

        headers = ["Owner Id", "Tenant Name", "Tenant External Url", "Image Id", "Image Name", "Visibility", "Status"]
        with open('all_unsecured_images_list.csv', 'a') as f:
            file_is_empty = os.stat('all_unsecured_images_list.csv').st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(all_unsecured_images)

        if len(all_unsecured_images) == 0:
            print("LOG: All images test: Compliant\(Tenant has no unsecured images\)")
            flag3 = "Compliant"
        else:
            print("LOG: All images test: Non-compliant\(Tenant has unsecured images\)")
            flag3 = "Non-compliant"
        #print(json.dumps(all_unsecured_images, sort_keys=False, indent=2))
        return all_unsecured_images, flag3
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))

def summary_of_test(project_name, all_images_list, all_unsecured_images, servers, private_servers, unused_images, unused_private_images):
    summary = []
    print("\n##########################Summary of audit test#############################")
    print("Project name of audit test: %s" % project_name)
    print("Total no of images found: %s" % len(all_images_list))
    print("Total no of unsecured images found: %s" % len(all_unsecured_images))
    print("Total no of servers in tenant account: %s" % len(servers))
    print("Total no of servers using private images: %s" % len(private_servers))
    print("Total no of unused image in tenant accout: %s" % len(unused_images))
    print("Total no of unused private image in tenant accout: %s" % len(unused_private_images))
    return summary

def main(os_auth_url, project_name):
    """
    This main method is to validate the source of images listed in the provided OpenStack Project is
    secured or unsecured [(visibility ="Public") = secured & (visibility = "private") = unsecured]
    :param os_auth_url: OpenStack's Horizon URL
    :param project_name: Project name
    :return: Compliant or Non-compliant
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
        return None

    images = list_images(conn)
    if images:
        servers = list_servers(conn, images, project_name, os_auth_url)
        if servers:
            private_servers, flag1 = list_private_servers(servers)
            unused_images = list_unused_images(conn, images, servers, project_name, os_auth_url)
            if unused_images:
                unused_private_images, flag2 = list_unused_private_images(unused_images)
    all_images_list = list_all_images(conn, project_name, os_auth_url)
    if all_images_list:
        all_unsecured_images, flag3 = unsecured_images_list(all_images_list)
    summary = summary_of_test(project_name, all_images_list, all_unsecured_images, servers, private_servers, unused_images, unused_private_images)  
    return flag3
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the images listed in OpenStack Project...")
    parser.add_argument("-u", "--auth_url", help="OpenStack Horizon URL", action="store", dest="url")
    parser.add_argument("-t", "--team_id", help="Project/Tenant ID", action="store", dest="team")
    args = parser.parse_args()
    url = args.url
    p_name = args.team
    main(url, p_name)

