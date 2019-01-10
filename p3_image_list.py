#!/usr/bin/python

"""
--------------------------p3_os_image_hardening_tc_1.py-------------------------
Description: This python script is to list all the images in the tenant account and
            validate the image are from the trusted source or not. This method check the
            visibility status of the images used in the servers and the unused images contain
            in the tenant account.

Author: Devaraj Acharya <devaacha@cisco.com>; January 8th, 2018

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
import dateutil.parser
from os import environ as env
#from general_util import updateScanRecord, add_result_to_stream, send_result_complete

def list_images(conn):
    """
    This main method is to list all the images in the openstack project
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
        for network in conn.network.networks():
            network_name = network['name']
            
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
            
            address = pull['addresses'][network_name][0]
                
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
        df = pd.DataFrame(servers, columns=["VM Id", "Tenant Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Owner Id", "Image Name", "VM Name", "Unsecured", "Image Direct URL", "Image Updated Ago", "VM Availability Zone", "VM Updated Ago", "VM IP Address", "VM Host Id", "VM User Id"])
        df.to_csv('servers_list.csv',index=False)

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
        df = pd.DataFrame(private_servers, columns=["VM Id", "Tenant Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Owner Id", "Image Name", "VM Name", "Unsecured", "Image Direct URL", "Image Updated Ago", "VM Availability Zone", "VM Updated Ago", "VM IP Address", "VM Host Id", "VM User Id"])
        df.to_csv('unsecured_servers_list.csv',index=False)

        if len(private_servers) == 0:
            print "VM test: Compliant(Unsecured image is not used in VM)"
            flag1 = "Compliant"
        else:
            print "VM test: Non-compliant(Unsecured image is used in VM)"
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
    try:
        unused_images = []
        all_image_ids = []
        used_image_ids = []
        unused_image_ids = []
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
        df = pd.DataFrame(unused_images, columns=["Tenant Id", "Image Owner Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Name", "Visibility", "Unused", "Direct URL", "Image_Updated_ago"])
        df.to_csv('unused_imges_list.csv',index=False)

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
    :return: Compliant or Non-compliant
    """
    try:
        flag2 = "Non-compliant"
        unused_private_images = []
        for image in unused_images:
            if (image[6] != 'public'):
                unused_private_images.append(image)
        df = pd.DataFrame(unused_private_images, columns=["Tenant Id", "Image Owner Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Name", "Visibility", "Unused", "Direct URL", "Image_Updated_ago"])
        df.to_csv('unused_unsecured_images.csv',index=False)
        if len(unused_private_images) == 0:
            print "unused private images test: Compliant(There is no unused unsecured images)"
            flag2 = "Compliant"
        else:
            print "unused private images test: Non-compliant(There is unused unsecured images)"
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

        df = pd.DataFrame(all_images_list, columns=["Owner Id", "Tenant Name", "Tenant External Url", "Image Id", "Image Name", "Visibility", "Status"])
        df.to_csv('image_list.csv',index=False)
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

        df = pd.DataFrame(all_unsecured_images, columns=["Owner Id", "Tenant Name", "Tenant External Url", "Image Id", "Image Name", "Visibility", "Status"])
        df.to_csv('all_unsecured_images.csv',index=False)

        if len(all_unsecured_images) == 0:
            print "All images test: Compliant(Tenant has no unsecured images)"
            flag3 = "Compliant"
        else:
            print "All images test: Non-compliant(Tenant has unsecured images)"
            flag3 = "Non-compliant"
        #print(json.dumps(all_unsecured_images, sort_keys=False, indent=2))
        return all_unsecured_images, flag3
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
        return flag3

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the images listed in OpenStack Project...")
    parser.add_argument("-u", "--auth_url", help="OpenStack Horizon URL", action="store", dest="url")
    parser.add_argument("-t", "--team_id", help="Project/Tenant ID", action="store", dest="team")
    args = parser.parse_args()
    url = args.url
    p_name = args.team
    main(url, p_name)
