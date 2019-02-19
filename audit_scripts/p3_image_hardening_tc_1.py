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

sys.path.append(os.environ["CLONED_REPO_DIR"] + "/library")
import common_lib
import general_util
import p3_lib


filename = os.path.abspath(__file__).split("/")[-1].split(".py")[0]
tc = filename.replace("_", "-").upper()
seq_nums_list = list()
params_list = list()


def list_images(conn):
    """
    This method is to list all the images in the OpenStack project
    :param conn: connectivity to the P3 platform
    """
    try:
        images = dict()
        for image in conn.image.images():
            img = json.dumps(image)
            out = json.loads(img)
            images[out['id']] = out
        return images
    except Exception as err:
        print("ERROR: Failed to retrieve list of used images due to %s" % str(err))
        return None


def list_volumes(conn):
    """
    This method is to list all the volumes in the OpenStack project
    :param conn: connectivity to the P3 platform
    """
    try:
        volumes_list = dict()
        for volume in conn.volume.volumes():
            vol = json.dumps(volume)
            volume = json.loads(vol)
            volumes_list[volume['id']] = volume
        return volumes_list
    except Exception as err:
        print("ERROR: Failed to retrieve list of used volume due to %s" % str(err))
        return None


def list_servers(conn, images, volumes_list, project_name, os_auth_url):
    """
    This method is to list the servers in the OpenStack project along with the details of server
    and the associated image.
    :param conn: connectivity to the P3 platform
    :param images: list_images
    :volume_list: volume
    :param project_name: Project Name
    :param os_auth_url: OpenStack's Horizon URL
    :return:
    """
    try:
        servers = list()
        address = dict()

        for server in conn.compute.servers():
            srvr = json.dumps(server)
            pull = json.loads(srvr)

            vm_created = dateutil.parser.parse(pull['created_at']).replace(tzinfo=None)
            vm_updated_days = datetime.datetime.now() - vm_created
            vm_updated_days = ("%s Days %s Hours %s Mins" % (vm_updated_days.days, vm_updated_days.seconds//3600,
                                                             (vm_updated_days.seconds//60) % 60))

            addresses = pull.get('addresses', None)
            if addresses != {}:
                network_names = list(addresses.keys())
                server_network_name = network_names[0]
                address = pull['addresses'][server_network_name][0]
            else:
                address['addr'] = "None"

            image_ids = []
            volume = pull.get('attached_volumes', None)
            for each in volume:
                volume_metadata = volumes_list.get(each['id']) if volume else None
                volume_image_detail = (volume_metadata.get('volume_image_metadata')) if volume_metadata else None
                image_ids.append(volume_image_detail.get('image_id')) if volume_image_detail else None
            
            image_ids.append(pull.get('image')['id']) if pull.get('image') else None
            for image_id in image_ids:
                image = images.get(image_id) or {'id': image_id}
                
                image_updated_at = image.get('updated_at')
                image_created = dateutil.parser.parse(image_updated_at).replace(tzinfo=None) if image_updated_at is not None else None
                image_updated_days = (datetime.datetime.now() - image_created) if image_created is not None else None
                image_updated_ago = (("%s Days %s Hours %s Mins" % (image_updated_days.days,
                                        image_updated_days.seconds//3600, (image_updated_days.seconds//60) % 60))
                                        if image_updated_days is not None else None)

                servers.append([
                            pull['id'],
                            pull['name'],
                            pull['project_id'],
                            project_name,
                            os_auth_url,
                            image_id,
                            image.get('owner_id'),
                            image.get('name'),
                            image.get('visibility') == 'public',
                            image.get('direct_url'),
                            image_updated_ago,
                            pull['availability_zone'],
                            vm_updated_days,
                            address['addr'],
                            pull['host_id'],
                            pull['user_id'],
                ])
        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.path.expanduser("~") + "/logs/p3_servers_list_" + date_stamp + ".csv"
        headers = [
                    "VM Id", "VM Name", "Tenant Id", "Tenant Name", "Tenant External URL", "Image Id",
                    "Image Owner Id", "Image Name", "Secured", "Image Direct URL", "Image Updated Days",
                    "VM Availability Zone", "VM Updated Ago", "VM IP Address", "VM Host Id", "VM User Id"
                  ]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(servers)
        return servers
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))
        return None


def list_unsecured_servers(servers, scan_id, team_id, scanid_valid, teamid_valid):
    """
    This method is to list the servers with the unsecured images and their details.
    :param servers: list_servers(conn, images, project_name, os_auth_url)
    :param scan_id: ScanID received from AWS SQS
    :param team_id: TeamID
    :return: Compliant | Non-Compliant | None
    """
    try:
        unsecured_servers = list()
        for server in servers:
            if server[8] == False:
                unsecured_servers.append(server)
                compliance_status = "Non-compliant"
            else:
                compliance_status = "Compliant"
            resource = "Instance: " + server[1]
            if scanid_valid and teamid_valid:
                if general_util.params_list_update(scan_id, tc, team_id, resource, compliance_status, params_list):
                    print("INFO: Updating params_list")
                else:
                    print("ERROR: Issue observed while updating params_list")
                    return None
            else:
                print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.path.expanduser("~") + "/logs/p3_unsecured_servers_list_" + date_stamp + ".csv"
        headers = [
                   "VM Id", "VM Name", "Tenant Id", "Tenant Name", "Tenant External URL", "Image Id",
                    "Image Owner Id", "Image Name", "Secured", "Image Direct URL", "Image Updated Days",
                    "VM Availability Zone", "VM Updated Ago", "VM IP Address", "VM Host Id", "VM User Id"
                  ]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(unsecured_servers)

        if len(unsecured_servers) == 0:
            print("INFO: VM test: Compliant(Unsecured image is not used in VM)")
            flag1 = "Compliant"
        else:
            print("INFO: VM test: Non-compliant(Unsecured image is used in VM)")
            flag1 = "Non-compliant"
        return unsecured_servers, flag1
    except Exception as err:
        print("ERROR: Failed to retrieve list of unsecured servers list due to %s" % str(err))
        return None, None


def list_unused_images(conn, images, servers, project_name, os_auth_url):
    """
    This main method is to list all the unused images in the OpenStack project.
    :param conn: connectivity to the platform
    :param images: list_images
    :param servers: list_servers
    :param os_auth_url: OpenStack's Horizon URL
    :param project_name: Project name
    """
    try:
        unused_images = list()
        all_image_ids = list()
        used_image_ids = list()
        unused_image_ids = dict()
        for image in conn.image.images():
            all_image_ids.append(image['id'])
        for server in servers:
            used_image_ids.append(server[5]),"NULL"
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
        csv_filename = os.path.expanduser("~") + "/logs/p3_unused_image_list_" + date_stamp + ".csv"
        headers = [
                    "Image Owner Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Name", "Visibility",
                    "Unused", "Direct URL", "Image_Updated_on"
                  ]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(unused_images)
        return unused_images
    except Exception as err:
        print("ERROR: Failed to retrieve list of unused images servers list due to %s" % str(err))
        return None


def list_unused_unsecured_images(unused_images, scan_id, team_id, scanid_valid, teamid_valid):
    """
    This method is to list the unused unsecured images.
    :param unused_images: list_unused_images
    :param scan_id: ScanID received from AWS SQS
    :param team_id: TeamID
    :param scanid_valid: Scan id
    :param: teamid_valid: Team id
    :return: Compliant | Non-Compliant | None
    """
    try:
        unused_unsecured_images = list()
        for image in unused_images:
            if image[5] != 'public':
                unused_unsecured_images.append(image)
                compliance_status = "Non-compliant"
            else:
                compliance_status = "Compliant"

            resource = "Unused_Image:" + image[4]
            if scanid_valid and teamid_valid:
                if general_util.params_list_update(scan_id, tc, team_id, resource, compliance_status, params_list):
                    print("INFO: Updating params_list")
                else:
                    print("ERROR: Issue observed while updating params_list")
                    return None, None
            else:
                print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.path.expanduser("~") + "/logs/p3_unused_unsecured_image_list_" + date_stamp + ".csv"
        headers = [
                    "Image Owner Id", "Tenant Name", "Tenant External URL", "Image Id", "Image Name", "Visibility",
                    "Unused", "Direct URL", "Image_Updated_on"
                  ]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(unused_unsecured_images)

        if len(unused_unsecured_images) == 0:
            print("INFO: There is no unused unsecured images")
            flag2 = "Compliant"
        else:
            print("INFO: There are unused unsecured images")
            flag2 = "Non-compliant"

        return unused_unsecured_images, flag2
    except Exception as err:
        print("ERROR: Failed to retrieve list of unused unsecured images due to %s" % str(err))
        return None, None


def list_all_images(conn, project_name, os_auth_url, team_id):
    """
    Method to fetch out the all images details in the OpenStack project
    :param conn: established the connection
    :param project_name:
    :param os_auth_url:
	:param team_id:
    :return: Compliant or Non-compliant
    """
    try:
        all_images_list = list()
        for image in conn.image.images():
            img = json.dumps(image)
            out = json.loads(img)
            all_images_list.append([
                        out['owner_id'],
                        team_id,
                        project_name,
                        os_auth_url,
                        out['id'],
                        out['name'],
                        out['visibility'], out['status']
            ])
        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.path.expanduser("~") + "/logs/p3_all_images_list_" + date_stamp + ".csv"
        headers = ["Owner Id", "Tenant Id", "Tenant Name", "Tenant External Url", "Image Id",
                   "Image Name", "Visibility", "Status"]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(all_images_list)

        return all_images_list
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))
        return None


def unsecured_images_list(all_images_list, scan_id, team_id, scanid_valid, teamid_valid):
    """
    Method to fetch out the all unsecured images details in the OpenStack project
    :param all_images_list: list_all_images
    :param scan_id: ScanID received from AWS SQS
    :param team_id: TeamID
    :param scanid_valid:
    :param teamid_valid:
    :return: Compliant | Non-Compliant | None
    """
    try:
        all_unsecured_images = list()
        for image in all_images_list:
            if image[6] != 'public':
                all_unsecured_images.append(image)
                compliance_status = "Non-compliant"
            else:
                compliance_status = "Compliant"

            resource = "Image:" + image[5]
            if scanid_valid and teamid_valid:
                if general_util.params_list_update(scan_id, tc, team_id, resource, compliance_status, params_list):
                    print("INFO: Updating params_list")
                else:
                    print("ERROR: Issue observed while updating params_list")
                    return None, None

            else:
                print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.path.expanduser("~") + "/logs/p3_all_unsecured_images_list_" + date_stamp + ".csv"
        headers = ["Owner Id", "Tenant Id", "Tenant Name", "Tenant External Url", "Image Id", "Image Name", "Visibility", "Status"]
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(all_unsecured_images)

        if len(all_unsecured_images) == 0:
            print("INFO: All images test: Compliant(Tenant has no unsecured images)")
            flag3 = "Compliant"
        else:
            print("INFO: All images test: Non-compliant(Tenant has unsecured images)")
            flag3 = "Non-compliant"

        return all_unsecured_images, flag3
    except Exception as err:
        print("ERROR: Failed to retrieve list of servers due to %s" % str(err))
        return None, None


def summary_of_test(project_name, all_images_list, all_unsecured_images,
                    servers, unsecured_servers, unused_images, unused_unsecured_images):
    """
    Method to print the overall scan report of the above functions:
    :param project_name: Project name
    :param all_images_list: list_all_images
    :param all_unsecured_images: unsecured_images_list
    :param servers: list_servers
    :param unsecured_servers: list_unsecured_servers
    :param unused_images: list_unused_images
    :param unused_unsecured_images: list_unused_unsecured_images
    """
    try:
        server_ids = []
        unsecured_server_ids = []
        for server in servers:
            server_ids.append(server[0])
        server_id = set(server_ids)
        for unsecured_server in unsecured_servers:
            unsecured_server_ids.append(unsecured_server[0])
        unsecured_server_id = set(unsecured_server_ids)
        
        summary_report = {
            "No_of_Image(s)_evaluated": len(all_images_list),
            "No_of_Unsecured_Image(s)": len(all_unsecured_images),
            "No_of_Server(s)_evaluated": len(server_id),
            "No_of_Unsecured_Server(s)": len(unsecured_server_id),
            "No_of_Unused_Image(s)": len(unused_images),
            "No_of_Unused_Unsecured_Image(s)": len(unused_unsecured_images)
        }
        print("\n########### SCAN REPORT for Project: %s###########" % project_name)
        print("Name of Project under trail: %s" % project_name)
        print("Total no. of images found: %s" % len(all_images_list))
        print("Total no. of unsecured images found: %s" % len(all_unsecured_images))
        print("Total no. of servers in tenant account: %s" % len(server_id))
        print("Total no. of servers using unsecured image: %s" % len(unsecured_server_id))
        print("Total no. of unused images in Tenant account: %s" % len(unused_images))
        print("Total no. of unused unsecured images in Tenant account: %s" % len(unused_unsecured_images))
        return summary_report
    except KeyError as key_err:
        print("ERROR: One of the variable do not have required data - %s" % str(key_err))
        summary_report = {
            "No_of_Image(s)_evaluated": 0,
            "No_of_Unsecured_Image(s)": 0,
            "No_of_Server(s)_evaluated": 0,
            "No_of_Unsecured_Server(s)": 0,
            "No_of_Unused_Image(s)": 0,
            "No_of_Unused_Unsecured_Image(s)": 0
        }
        return summary_report


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
    summary_report = {
            "No_of_Image(s)_evaluated": 0,
            "No_of_Unsecured_Image(s)": 0,
            "No_of_Server(s)_evaluated": 0,
            "No_of_Unsecured_Server(s)": 0,
            "No_of_Unused_Image(s)": 0,
            "No_of_Unused_Unsecured_Image(s)": 0
    }

    
    scanid_valid = False
    teamid_valid = False
    if scan_id and team_id is not None:
    	scanid_valid = common_lib.scanid_validation(scan_id)
    	teamid_valid = p3_lib.p3_teamid_validation(team_id)
    else:
    	print("INFO: Valid ScanId or TeamId not found")
    	print("INFO: Execution will proceed without Kinesis update")

    try:
        region = os_auth_url.split(".")[0].split("//")[1]
        conn = p3_lib.connect(os_auth_url, project_name, region)
    except Exception as e:
        print("ERROR: Connection failed with error => %s" % str(e))
        return None, summary_report

    session = general_util.session_handle()
    if session:
        if scanid_valid and teamid_valid:
            print("INFO: Update the scan record with \"InProgress\" Status")
            update = general_util.updateScanRecord(session, "P3", scan_id, team_id, tc, "InProgress")
            if update is None:
                raise Exception("ERROR: Issue observed with UpdateScanRecord API call for \"InProgress\" status")
                return None, summary_report
        else:
            print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

        images = list_images(conn)
        try:
            if images:
                volumes_list = list_volumes(conn)
                servers = list_servers(conn, images, volumes_list, project_name, os_auth_url)
                if servers is not None:
                    unsecured_servers, flag1 = list_unsecured_servers(servers, scan_id, team_id,
                                                                      scanid_valid, teamid_valid)
                    unused_images = list_unused_images(conn, images, servers, project_name, os_auth_url)
                    if unused_images is not None:
                        unused_unsecured_images, flag2 = list_unused_unsecured_images(unused_images, scan_id, team_id,
                                                                                      scanid_valid, teamid_valid)
                    else:
                        print("INFO: Failed to get the list of unused images")
                else:
                    print("INFO: Failed to get the list of servers")
            else:
                if scanid_valid and teamid_valid:
                    print("INFO: Update the scan record with \"Failed\" Status")
                    update = general_util.updateScanRecord(session, "P3", scan_id, team_id, tc, "Failed")
                    if update is None:
                        raise Exception("ERROR: Issue observed with UpdateScanRecord API call for \"Failed\" status")
                        return None, summary_report
                else:
                    raise Exception("ERROR: Failed to fetch the image list")

            all_images_list = list_all_images(conn, project_name, os_auth_url, team_id)
            if all_images_list:
                all_unsecured_images, flag3 = unsecured_images_list(all_images_list, scan_id, team_id,
                                                                    scanid_valid, teamid_valid)
            else:
                print("ERROR: Failed to get the list of images")

            summary_report = summary_of_test(project_name, all_images_list, all_unsecured_images, servers, unsecured_servers,
                            unused_images, unused_unsecured_images)

            list_of_flags = [flag1, flag2, flag3]
            if any(val == "Non-compliant" for val in list_of_flags):
                print("INFO: One of the test is Non-compliant")
                compliance_status = "Non-compliant"
            elif any(val is None for val in list_of_flags):
                print("INFO: One of the test returned None")
                compliance_status = "None"
            else:
                print("INFO: All checks are Compliant")
                compliance_status = "Compliant"

        except Exception as err:
            print("ERROR: Overall execution got affected due to - %s" % str(err))
            date_stamp = datetime.datetime.now().strftime('%m%d%y')
            csv_filename = os.path.expanduser("~") + "/logs/p3_all_images_list_" + date_stamp + ".csv"
            headers = ["Owner Id", "Tenant Id", "Tenant Name", "Tenant External Url", "Image Id", "Image Name", "Visibility", "Status"]
            Exception_list = ["", team_id, project_name, "", "", "", "", ""]
            try:
                with open(csv_filename, 'a') as f:
                    file_is_empty = os.stat(csv_filename).st_size == 0
                    writer = csv.writer(f, lineterminator='\n')
                    if file_is_empty:
                        writer.writerow(headers)
                    writer.writerows([Exception_list])
                return None, summary_report
            except Exception as file_err:
                print("ERROR: Issue observed while writing to csv file with - %s" % str(file_err))
                return None, summary_report

    if scanid_valid and teamid_valid:
        print("INFO: Adding result to Stream")
        stream_info = general_util.add_result_to_stream(session, "P3", str(team_id), tc, params_list)
        if stream_info is None:
           raise Exception("ERROR: Issue observed while calling add_result_to_stream() API")
           return None, summary_report
        seq_nums_list.append(stream_info)

        print("INFO: Sending result complete")
        send_result = general_util.send_result_complete(session, "P3", scan_id, team_id, tc, seq_nums_list)
        if send_result:
            print("INFO: Successfully submitted the result to Kinesis")
        else:
            raise Exception("ERROR: Failed to submit the result to Kinesis")
            return None, summary_report
    else:
        print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")
    conn.close()
    return compliance_status, summary_report


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
    url_valid = p3_lib.p3_url_validation(url)
    if url and p_name is not None:
        if url_valid:
            compliance_status, summary_report = main(url, p_name, scan_id, team_id)
            print("INFO: Process completed with:\nCompliance Status as - %s\nSummary_report as - %s"
                  % (compliance_status, summary_report))
        else:
            print("ERROR: Failed with validation of url")
    else:
        print("ERROR: Need Tenant ID and domain url to run the script")
