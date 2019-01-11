#!/opt/app-root/bin/python

"""
--------------------------p3_image_hardening_tc_1.py---------------------------
Description: This python script is to list all the images in the tenant
             account and validate the image are from the trusted source or not.
             This method check the visibility status of the images used in the
             servers and the unused images contain in the tenant account.

Author: Devaraj Acharya <devaacha@cisco.com>; January 8th, 2018

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------------
"""
import argparse
import json
import os
import openstack
import sys
import time

from os import environ as env
from general_util import updateScanRecord, add_result_to_stream, send_result_complete, session_handle

global tc

filename = os.path.abspath(__file__).split("/")[-1].split(".py")[0]
tc = filename.replace("_", "-").upper()


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
        return None
    except Exception as err:
        print("ERROR: Failed to retrieve list of used images due to %s" % str(err))
        return None


def list_servers(conn, images, project_name, os_auth_url):
    """
    This main method is to list the servers in the openstack project along with the details of server
    and the associated image.
    :conn: connectivity to the P3 platform
    :param os_auth_url: OpenStack's Horizon URL
    :images: list_images(conn)
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

            address = pull['addresses'][network_name][0]
            servers.append({
                "vm_id": pull['id'],
                "tenant_id": pull['project_id'],
                "tenant_name": project_name,
                "tenant_url":  os_auth_url,
                "image_id": image['id'],
                "image_owner_id": image['owner_id'],
                "image_name": image['name'],
                "vm_name": pull['name'],
                "unsecured": image['visibility'],
                "direct_url": image['direct_url'],
                "image_updated_on": image['updated_at'],
                "vm_availability_zone": pull['availability_zone'],
                "vm_created_on": pull['created_at'],
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
        return None
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))
        return None


def list_private_servers(servers, seq_nums_list, params_list, scan_id, team_id, session):
    """
    This method is to list the servers with the unsecured images and their details.
    :param servers: list_servers(conn, images, project_name, os_auth_url)
    :return: private_servers, Compliant|Non-Compliant or  None, None
    """
    try:
        flag = "Compliant"
        audit_time = int(time.time()) * 1000
        private_servers = []
        for server in servers:
            compliant_status = "Compliant"
            if server['unsecured'] == True:
                private_servers.append(server)
                compliant_status = "Non-compliant"
                flag = "Non-complaint"
            params = {
                         "scanid": scan_id,
                         "testid": tc,
                         "teamid": str(team_id),
                         "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, server["vm_name"]),
                         "createdAt": audit_time,
                         "updatedAt": audit_time,
                         "resourceName": server["vm_name"],
                         "complianceStatus": compliant_status,
                      }
            params_list.append(params.copy())

            while sys.getsizeof(json.dumps(params_list)) >= 900000:
                print("LOG: FIRST ELEMENT OF PARAMS LIST: ", params_list[0])
                stream_info = add_result_to_stream(session, "P3", str(team_id), tc, params_list)
                seq_nums_list.append(stream_info)

        print("LOG: Adding result to Stream")
        stream_info = add_result_to_stream(session, "P3", str(team_id), tc, params_list)
        seq_nums_list.append(stream_info)

        print("LOG: Sending result complete")
        send_result_complete(session, "P3", scan_id, team_id, tc, seq_nums_list)

        with open('private_servers.csv', 'w') as file:
            file.writelines(json.dumps(private_servers))
            file.writelines('\n ')
            file.close()
        if len(private_servers) == 0:
            print("LOG: VM test: PASS(Unsecured image is not used in VM)")
        else:
            print("LOG: VM test: FAIL(Unsecured image is used in VM)")
        # print(json.dumps(private_servers, sort_keys=False, indent=2))
        return private_servers, flag

    except IOError as e:
        print("ERROR: Failed to retrieve private servers list with error => %s" % str(e))
        return None, None
    except Exception as err:
        print("ERROR: Failed to retrieve list of private servers list due to %s" % str(err))
        return None, None


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
            used_image_ids.append(server['image_id'])
        unused_image_ids = set(all_image_ids).difference(set(used_image_ids))
        for unused_image_id in unused_image_ids:
            image = images[unused_image_id]
            unused_images.append({
                "tenant_id": server['tenant_id'],
                "image_owner_id": image['owner_id'],
                "tenant_name": project_name,
                "tenant_external_url": os_auth_url,
                "image_id": image['id'],
                "image_name": image['name'],
                "visibility": image['visibility'],
                "unused": unused_image_ids != None,
                "direct_url": image['direct_url'],
                "image_updated_ago": server['image_updated_ago']
            })
        with open('unused_images.csv','w') as file:
            file.writelines(json.dumps(unused_images))
            file.writelines('\n ')
            file.close()
        # print(json.dumps(unused_images, sort_keys=False, indent=2))
        return unused_images
    except IOError as e:
        print("ERROR: Failed to retrieve unused image list with error => %s" % str(e))
        return None
    except Exception as err:
        # print("ERROR: Failed to retrieve list of unused images due to %s" % str(err))  # Debug Required
        return None


def list_unused_private_images(unused_images):
    """
    This method is to list the unused unsecured images.
    :param unused_images: list_unused_images
    :return: unused_private_images | None
    """
    try:
        unused_private_images = []
        for image in unused_images:
            if image['visibility'] != 'public':
                unused_private_images.append(image)
        with open('unused_private_images.csv', 'w') as file:
            file.writelines(json.dumps(unused_private_images))
            file.writelines('\n ')
            file.close()
        if len(unused_private_images) == 0:
            print("LOG: Unused private images test: PASS(There is no unused unsecured images)")
        else:
            print("LOG: Unused private images test: FAIL(There is unused unsecured images)")
        return unused_private_images

    except IOError as e:
        print("ERROR: Failed to retrieve unused private image list with error => %s" % str(e))
        return None
    except Exception as err:
        print("ERROR: Failed to retrieve list of unused private images due to %s" % str(err))
        return None


def list_all_images(conn, project_name, os_auth_url):
    """
    Method to fetch out the all images details in the openstack project
    :param conn: established the connection
    :param project_name:
    :param os_auth_url:
    :return: all_image_list | None
    """
    try:
        all_images_list = []
        for image in conn.image.images():
            img = json.dumps(image)
            out = json.loads(img)
            all_images_list.append(
                                    {
                                        "owner_id": out['owner_id'],
                                        "tenant_name": project_name,
                                        "tenant_external_url": os_auth_url,
                                        "image_id":  out['id'],
                                        "image_name": out['name'],
                                        "visibility": out['visibility'], "status": out['status']
                                    }
                                  )
        with open('image_detail.csv','w') as file:
            file.writelines(json.dumps(all_images_list))
            file.writelines('\n ')
            file.close()
        # print(all_images_list)
        return all_images_list
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
        return None
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))
        return None


def unsecured_images_list(all_images_list):
    """
    Method to fetch out the all unsecured images details in the openstack project
    :param all_images_list: list_all_images
    :return: all_unsecured_images, Complaint|Non-Complaint
    """
    try:
        all_unsecured_images = []
        for image in all_images_list:
            if image['visibility'] != 'public':
                all_unsecured_images.append(image)

        with open('unsecured_images_list.csv', 'w') as file:
            file.writelines(json.dumps(all_unsecured_images))
            file.writelines('\n ')
            file.close()

        if len(all_unsecured_images) == 0:
            print("LOG: All images test: PASS(Tenant has no unsecured images)")
            flag = "Compliant"
        else:
            print("LOG: All images test: FAIL(Tenant has unsecured images)")
            flag = "Non-compliant"

        return flag

    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
        return None, None
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))
        return None, None


def main(os_auth_url, project_name, scan_id, team_id):
    """
    This main method is to validate the source of images listed in the provided OpenStack Project is
    secured or unsecured [visibility = "Public" => secured & visibility = "private" => unsecured]
    :param os_auth_url: OpenStack's Horizon URL
    :param project_name: Project name
    :return: Compliant | None-compliant
    """
    try:
        region = os_auth_url.split(".")[0].split("//")[1]
        conn = openstack.connect(
                                    auth_url=os_auth_url,
                                    project_name=project_name,
                                    username=env['USERNAME'],
                                    password=env['PASSWORD'],
                                    region_name=region
                                )
    except Exception as e:
        print("ERROR: Connection failed with error => %s" % str(e))
        return None

    session = session_handle()
    if session:
        print("LOG: Update the scan record with \"InProgress\" Status")
        updateScanRecord(session, "P3", scan_id, team_id, "P3-IMAGE-HARDENING-TC-1", "InProgress")
        seq_nums_list = []
        params_list = []

        images = list_images(conn)
        try:
            if images:
                servers = list_servers(conn, images, project_name, os_auth_url)
                if servers:
                    try:
                        private_servers, flag1 = list_private_servers(servers, seq_nums_list, params_list, scan_id, team_id, session)
                    except Exception as err:
                        print("ERROR: Failed to list private servers - %s" % str(err))
                        updateScanRecord(session, "P3", scan_id, team_id, tc, "Failed")

                    unused_images = list_unused_images(conn, images, servers, project_name, os_auth_url)
                    if unused_images:
                        unused_private_images = list_unused_private_images(unused_images)
                    else:
                        # print("ERROR: Failed to get the list of unused images")   #Debug required
                else:
                    print("ERROR: Failed to get the server list")
            else:
                raise Exception("ERROR: Failed to fetch the image list")

            all_images_list = list_all_images(conn, project_name, os_auth_url)
            if all_images_list:
                flag2 = unsecured_images_list(all_images_list)
            else:
                print("ERROR: Failed to get the list of images")
            if flag1 == flag2 == "Compliant":
                return "Compliant"
            else:
                return "Non-compliant"
        except Exception as err:
            print("ERROR: Overall execution got affected due to - %s" % str(err))
            return None
    else:
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the images listed in OpenStack Project...")
    parser.add_argument("-u", "--auth_url", help="OpenStack Horizon URL", action="store", dest="url")
    parser.add_argument("-t", "--team_name", help="Project/Tenant ID", action="store", dest="team")
    parser.add_argument("-s", "--scan_id", help="Scan ID from AWS", action="store", dest="scanid")
    parser.add_argument("-i", "--team_id", help="Project/Tenant ID", action="store", dest="teamid")
    args = parser.parse_args()
    url = args.url
    p_name = args.team
    scan_id = args.scanid
    team_id = args.teamid

    compliance_status = main(url, p_name, scan_id, team_id)
    print(compliance_status)
