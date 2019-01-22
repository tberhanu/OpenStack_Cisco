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
import csv
import datetime
import dateutil.parser
import json
import openstack
import os
import re
import sys
import time


from os import environ as env
sys.path.append(os.environ["CLONED_REPO_DIR"] + "/library")
from general_util import updateScanRecord, add_result_to_stream, send_result_complete, session_handle

filename = os.path.abspath(__file__).split("/")[-1].split(".py")[0]
tc = filename.replace("_", "-").upper()
seq_nums_list = []
params_list =[]

def list_images(conn):
    """
    This method is to list all the images in the OpenStack project
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
    This main method is to list the servers in the OpenStack project along with the details of server
    and the associated image.
    :param conn: connectivity to the P3 platform
    :param images: list_images
    :param project_name: Project Name
    :param os_auth_url: OpenStack's Horizon URL
    :return:
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
        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.environ["CLONED_REPO_DIR"] + "/logs/reports/p3_servers_list_" + date_stamp + ".csv"
        headers = ["VM Id", "Tenant Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Owner Id", "Image Name", "VM Name", "Unsecured", "Image Direct URL", "Image Updated Ago", "VM Availability Zone", "VM Updated Ago", "VM IP Address", "VM Host Id", "VM User Id"]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(servers)
        return servers
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))


def list_unsecured_servers(servers, seq_nums_list, params_list, scan_id, team_id, session):
    """
    This method is to list the servers with the unsecured images and their details.
    :param servers: list_servers(conn, images, project_name, os_auth_url)
    :param seq_nums_list: empty list
    :param params_list: empty list
    :param scan_id: ScanID received from AWS SQS
    :param team_id: TeamID
    :param session: session handle to Kinesis
    :return: Compliant | Non-Compliant | None
    """
    try:
        audit_time = int(time.time()) * 1000
        flag1 = "Non-compliant"
        unsecured_servers = []
        for server in servers:
            if server[8]:
                unsecured_servers.append(server)
                compliant_status = "Non-compliant"
            else:
                compliant_status = "Compliant"
            resource = "Instance: " + server[7]
            params = {
                        "scanid": scan_id,
                         "testid": tc,
                         "teamid": str(team_id),
                         "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, resource),
                         "createdAt": audit_time,
                         "updatedAt": audit_time,
                         "resourceName": resource,
                         "complianceStatus": compliant_status,
                      }
            params_list.append(params.copy())
            while sys.getsizeof(json.dumps(params_list)) >= 900000:
                print("LOG: FIRST ELEMENT OF PARAMS LIST: ", params_list[0])
                stream_info = add_result_to_stream(session, "P3", str(team_id), tc, params_list)
                if stream_info:
                    seq_nums_list.append(stream_info)
                else:
                    return None
        print("LOG: Adding result to Stream")
        stream_info = add_result_to_stream(session, "P3", str(team_id), tc, params_list)
        if stream_info:
            seq_nums_list.append(stream_info)
        else:
           return None

        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.environ["CLONED_REPO_DIR"] + "/logs/reports/p3_unsecured_servers_list_" + date_stamp + ".csv"
        headers = ["VM Id", "Tenant Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Owner Id", "Image Name", "VM Name", "Unsecured", "Image Direct URL", "Image Updated Ago", "VM Availability Zone", "VM Updated Ago", "VM IP Address", "VM Host Id", "VM User Id"]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(unsecured_servers)

        if len(unsecured_servers) == 0:
            print("LOG: VM test: Compliant\(Unsecured image is not used in VM\)")
            flag1 = "Compliant"
        else:
            print("LOG: VM test: Non-compliant\(Unsecured image is used in VM\)")
            flag1 = "Non-compliant"
        return unsecured_servers, flag1
    except IOError as e:
        print("ERROR: Failed to retrieve unsecured servers list with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of unsecured servers list due to %s" % str(err))


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
            used_image_ids.append(server[4]),"NULL"
        unused_image_ids = set(all_image_ids).difference(set(used_image_ids))
        for unused_image_id in unused_image_ids:
            image = images[unused_image_id]
            unused_images.append([
                    image['owner_id'],
                    project_name,
                    os_auth_url,
                    image['id'],
                    image['name'],
                    image['visibility'],
                    unused_image_ids is not None,
                    image['direct_url'],
                    image['updated_at']
            ])
        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.environ["CLONED_REPO_DIR"] + "/logs/reports/p3_unused_image_list_" + date_stamp + ".csv"
        headers = ["Image Owner Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Name", "Visibility", "Unused", "Direct URL", "Image_Updated_ago"]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(unused_images)
        return unused_images
    except IOError as e:
        print("ERROR: Failed to retrieve unused images list with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of unused images servers list due to %s" % str(err))


def list_unused_unsecured_images(unused_images, seq_nums_list, params_list, scan_id, team_id, session):
    """
    This method is to list the unused unsecured images.
    :param unused_images: list_unused_images
    :param seq_nums_list: empty list
    :param params_list: empty list
    :param scan_id: ScanID received from AWS SQS
    :param team_id: TeamID
    :param session: session handle to Kinesis
    :return: Compliant | Non-Compliant | None
    """
    try:
        audit_time = int(time.time()) * 1000
        flag2 = "Non-compliant"
        unused_unsecured_images = []
        for image in unused_images:
            if image[5] != 'public':
                unused_unsecured_images.append(image)
                compliant_status = "Non-compliant"
            else:
                compliant_status = "Compliant"

            resource = "Unused_Image:" + image[4]
            params = {
                        "scanid": scan_id,
                         "testid": tc,
                         "teamid": str(team_id),
                         "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, resource),
                         "createdAt": audit_time,
                         "updatedAt": audit_time,
                         "resourceName": resource,
                         "complianceStatus": compliant_status,
                      }
            params_list.append(params.copy())
            while sys.getsizeof(json.dumps(params_list)) >= 900000:
                print("LOG: FIRST ELEMENT OF PARAMS LIST: ", params_list[0])
                stream_info = add_result_to_stream(session, "P3", str(team_id), tc, params_list)
                if stream_info:
                    seq_nums_list.append(stream_info)
                else:
                    return None
        print("LOG: Adding result to Stream")
        stream_info = add_result_to_stream(session, "P3", str(team_id), tc, params_list)
        if stream_info:
            seq_nums_list.append(stream_info)
        else:
           return None

        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.environ["CLONED_REPO_DIR"] + "/logs/reports/p3_unused_unsecured_image_list_" + date_stamp + ".csv"
        headers = ["Image Owner Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Name", "Visibility", "Unused", "Direct URL", "Image_Updated_ago"]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(unused_unsecured_images)

        if len(unused_unsecured_images) == 0:
            print("LOG: unused unsecured images test: Compliant\(There is no unused unsecured images\)")
            flag2 = "Compliant"
        else:
            print("LOG: unused unsecured images test: Non-compliant\(There is unused unsecured images\)")
            flag2 = "Non-compliant"

        return unused_unsecured_images, flag2
    except IOError as e:
        print("ERROR: Failed to retrieve unused unsecured image list with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of unused unsecured images due to %s" % str(err))


def list_all_images(conn, project_name, os_auth_url):
    """
    Method to fetch out the all images details in the OpenStack project
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
        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.environ["CLONED_REPO_DIR"] + "/logs/reports/all_images_list_" + date_stamp + ".csv"
        headers = ["Owner Id", "Tenant Name", "Tenant External Url", "Image Id", "Image Name", "Visibility", "Status"]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(all_images_list)

        return all_images_list
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))


def unsecured_images_list(all_images_list, seq_nums_list, params_list, scan_id, team_id, session):
    """
    Method to fetch out the all unsecured images details in the OpenStack project
    :param all_images_list: list_all_images
    :param seq_nums_list: empty list
    :param params_list: empty list
    :param scan_id: ScanID received from AWS SQS
    :param team_id: TeamID
    :param session: session handle to Kinesis
    :return: Compliant | Non-Compliant | None
    """
    try:
        audit_time = int(time.time()) * 1000
        flag3 = "Non-compliant"
        all_unsecured_images = []
        for image in all_images_list:
            if image[5] != 'public':
                all_unsecured_images.append(image)
                compliant_status = "Non-compliant"
            else:
                compliant_status = "Compliant"
            resource = "Image:" + image[4]
            params = {
                        "scanid": scan_id,
                         "testid": tc,
                         "teamid": str(team_id),
                         "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, resource),
                         "createdAt": audit_time,
                         "updatedAt": audit_time,
                         "resourceName": resource,
                         "complianceStatus": compliant_status,
                      }
            params_list.append(params.copy())
            while sys.getsizeof(json.dumps(params_list)) >= 900000:
                print("LOG: FIRST ELEMENT OF PARAMS LIST: ", params_list[0])
                stream_info = add_result_to_stream(session, "P3", str(team_id), tc, params_list)
                if stream_info:
                    seq_nums_list.append(stream_info)
                else:
                    return None
        print("LOG: Adding result to Stream")
        stream_info = add_result_to_stream(session, "P3", str(team_id), tc, params_list)
        if stream_info:
            seq_nums_list.append(stream_info)
        else:
           return None

        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.environ["CLONED_REPO_DIR"] + "/logs/reports/p3_all_unsecured_images_list_" + date_stamp + ".csv"
        headers = ["Owner Id", "Tenant Name", "Tenant External Url", "Image Id", "Image Name", "Visibility", "Status"]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
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

        return all_unsecured_images, flag3
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))


def summary_of_test(project_name, all_images_list, all_unsecured_images, servers, unsecured_servers, unused_images, unused_unsecured_images):
    """
    Method to get the overall scan report of the above functions:
    :param project_name: Project name
    :param all_images_list: list_all_images
    :param all_unsecured_images: unsecured_images_list
    :param servers: list_servers
    :param unsecured_servers: list_unsecured_servers
    :param unused_images: list_unused_images
    :param unused_unsecured_images: list_unused_unsecured_images
    """
    try:
        summary = []
        print("\n########################## SCAN REPORT #############################")
        print("Project name of audit test: %s" % project_name)
        print("Total no of images found: %s" % len(all_images_list))
        print("Total no of unsecured images found: %s" % len(all_unsecured_images))
        print("Total no of servers in tenant account: %s" % len(servers))
        print("Total no of servers using unsecured image: %s" % len(unsecured_servers))
        print("Total no of unused images in tenant accout: %s" % len(unused_images))
        print("Total no of unused unsecured images in tenant accout: %s" % len(unused_unsecured_images))
        return summary
    except IOError as e:
        print("ERROR: Failed to retrieve server detail with error => %s" % str(e))
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))


def scanid_validation(scan_id):
    """
    This method is to validate that scan id while sending the report to kinesis.
    :param scan_id: ScanID received from AWS SQS
    """
    scanid_pattern = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
    try:
        match = re.match(scanid_pattern, scan_id)
        match.group(0)
        return True
    except Exception as e:
        print("ERROR: Scan id not valid", str(e))
        return False


def p3_teamid_validation(team_id):
    """
    This method is to validate that team id of the P3 platform while sending the report to kinesis.
    :param team_id: TeamID
    """
    teamid_pattern = re.compile(r'\bP3:[0-9a-f]{32}\b')
    try:
        match = re.match(teamid_pattern, team_id)
        match.group(0)
        return True
    except Exception as e:
        print("ERROR: Team id not valid", str(e))
        return False


def p3_url_validation(url):
    """
    This method is to validate the authorized url of the P3 platform.
    :url: OpenStack's Horizon URL
    """
    p3_url_pattern = re.compile(r'https://cloud-.*-1.cisco.com:5000/v3')
    try:
        match = re.match(p3_url_pattern, url)
        match.group(0)
        return True
    except Exception as e:
        print("ERROR: URL not valid", str(e))
        return False


def main(os_auth_url, project_name, scan_id, team_id):
    """
    This main method is to validate the source of images listed in the provided OpenStack Project is
    secured or unsecured [(visibility ="Public") = secured & (visibility = "private") = unsecured]
    :param os_auth_url: OpenStack's Horizon URL
    :param project_name: Project name
    :param scan_id: Scan ID received from AWS, required for Kinesis update
    :param team_id: required during Kinesis Update
    :return: Compliant or Non-compliant
    """
    try:
        scanid_valid = False
        teamid_valid = False
        if scan_id and team_id is not None:
            scanid_valid = scanid_validation(scan_id)
            teamid_valid = p3_teamid_validation(team_id)
        else:
            print("INFO: Valid ScanId or TeamId not found")
            print("INFO: Execution will proceed without Kinesis update")

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
        if scanid_valid and teamid_valid:
            print("LOG: Update the scan record with \"InProgress\" Status")
            update = updateScanRecord(session, "P3", scan_id, team_id, tc, "InProgress")
            if update is None:
                raise Exception("ERROR: Issue observed with UpdateScanRecord API call for \"InProgress\" status")
                return None
        else:
            print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

        images = list_images(conn)
        try:
            if images:
                servers = list_servers(conn, images, project_name, os_auth_url)
                if servers is not None:
                    unsecured_servers, flag1 = list_unsecured_servers(servers, seq_nums_list, params_list, scan_id, team_id, session)
                    unused_images = list_unused_images(conn, images, servers, project_name, os_auth_url)
                    if unused_images is not None:
                        unused_unsecured_images, flag2 = list_unused_unsecured_images(unused_images, seq_nums_list, params_list, scan_id, team_id, session)
                    else:
                        print("LOG: Failed to get the list of unused images")
                else:
                    print("LOG: Failed to get the list of servers")
            else:
                raise Exception("ERROR: Failed to fetch the image list")
            all_images_list = list_all_images(conn, project_name, os_auth_url)
            if all_images_list:
                all_unsecured_images, flag3 = unsecured_images_list(all_images_list, seq_nums_list, params_list, scan_id, team_id, session)
            else:
                print("ERROR: Failed to get the list of images")
            summary = summary_of_test(project_name, all_images_list, all_unsecured_images, servers, unsecured_servers, unused_images, unused_unsecured_images)
        except Exception as err:
            print("ERROR: Overall execution got affected due to - %s" % str(err))

    else:
        raise Exception("ERROR: Connection handle to Kinesis is None")

    if flag1 == flag2 == flag3 == "Compliant":
        compliance_status = "Compliant"
    else:
        compliance_status = "Non-compliant"

    if scanid_valid and teamid_valid:
        print("INFO: Sending result complete")
        send_result = send_result_complete(session, "P3", scan_id, team_id, tc, seq_nums_list)
        if send_result:
            print("LOG: Successfully submitted the result to Kinesis")
        else:
            raise Exception("ERROR: Failed to submit the result to Kinesis")
            return None
    else:
        print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")
        
    return compliance_status


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
    url_valid = p3_url_validation(url)
    if url and p_name is not None:
        if url_valid is not None:
            compliance_status = main(url, p_name, scan_id, team_id)
            print("LOG: Process complete with compliance status as ", compliance_status)
        else:
            print("ERROR: Failed with validation of url")
    else:
        print("ERROR: Need Tenant ID and domain url to run the script")
