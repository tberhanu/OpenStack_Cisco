#!/opt/app-root/bin/python

"""
--------------------------p3_identity_mgmt_tc_1.py-----------------------
Description: This python script is to validate the negative test cases
             for P3 identity management. This script validates if the
             tenant are allowed to:
                a. create users
                b. create roles
                c. create domain
                d. change domain
             in the P3 platform.
Author: Devaraj Acharya <devaacha@cisco.com>; January 9th, 2019
Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------
"""
import argparse
import csv
import datetime
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


def create_new_role(conn, project_name, scan_id, team_id, session, scanid_valid, teamid_valid):
    """
    This method is to validate that tenant are not allowed to create the new role in
    P3 platform.
    :param conn: connection handle to OpenStack project
    :param project_name: project name
    :param seq_nums_list: empty list
    :param params_list: empty list
    :param scan_id: ScanID received from AWS SQS
    :param team_id: TeamID
    :param session: session handle to Kinesis
    :return: Compliant | Non-Compliant | None
    """
    try:
        role = []
        for new_role in conn.identity.create_role():
            role = new_role
        print("ERROR: Tenant are being allowed to create a role")
        compliance_status = "Non-compliant"
        return compliance_status

    except openstack.exceptions.HttpException as exp_err:
        print("LOG: Error Received while attempting to create role - %s" % str(exp_err))
        if str(exp_err).find("You are not authorized"):
            print("LOG: Tenant are not allowed to create a role")
            compliance_status = "Compliant"
        else:
            compliance_status = "Non-compliant"
           
        resource = project_name + "-" + "create_role"
        if scanid_valid and teamid_valid:
            if kinesis_update(session, "P3", scan_id, tc, team_id, resource, compliance_status):
                print("LOG: Inside For loop Added the info to Kinesis Stream")
            else:
                print("ERROR: Kinesis Update API Failed")
                return None
        else:
            print("INFO: ScanId or TeamId passed to main() method is not valid,"
                  " hence ignoring Kinesis part")

        return compliance_status

    except Exception as e:
        print("ERROR: Issue observed while calling create_role() API - %s" % str(e))
        return None


def create_new_user(conn, project_name, scan_id, team_id, session, scanid_valid, teamid_valid):
    """
    This method is to validate that tenant are not allowed to create the new user
    in P3 platform.
    :param conn: connection handle to OpenStack project
    :param project_name: project name
    :param seq_nums_list: empty list
    :param params_list: empty list
    :param scan_id: ScanID received from AWS SQS
    :param team_id: TeamID
    :param session: session handle to Kinesis
    :return: Compliant | Non-Compliant | None
    """
    try:
        user = []
        audit_time = int(time.time()) * 1000
        for new_user in conn.identity.create_user():
            user = new_user
        print("ERROR: Tenant are being allowed to create a user")
        compliance_status = "Non-compliant"
        return compliance_status
    except openstack.exceptions.HttpException as exp_err:
        print("LOG: Error Received while attempting to create user - %s" % str(exp_err))
        if str(exp_err).find("You are not authorized"):
            print("LOG: Tenant are not allowed to create a user")
            compliance_status = "Compliant"
        else:
            compliance_status = "Non-compliant"

        resource = project_name + "-" + "create_user"
        if scanid_valid and teamid_valid:
            if kinesis_update(session, "P3", scan_id, tc, team_id, resource, compliance_status):
                print("LOG: Inside For loop Added the info to Kinesis Stream")
            else:
                print("ERROR: Kinesis Update API Failed")
                return None
        else:
            print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

        return compliance_status
    except Exception as e:
        print("ERROR: Issue observed while calling create_user() API - %s" % str(e))
        return None


def create_domain(conn, project_name, scan_id, team_id, session, scanid_valid, teamid_valid):
    """
    This method is to validate that tenant are not allowed to create the new domain
    in P3 platform.
    :param conn: connection handle to OpenStack project
    :param project_name: project name
    :param seq_nums_list: empty list
    :param params_list: empty list
    :param scan_id: ScanID received from AWS SQS
    :param team_id: TeamID
    :param session: session handle to Kinesis
    :return: Compliant | Non-Compliant | None
    """
    try:
        domain = []
        audit_time = int(time.time()) * 1000
        for create_domain in conn.identity.create_domain():
            new_domain = create_domain
        print("ERROR: Tenant are being allowed to create a domain")
        compliance_status = "Non-compliant"
        return compliance_status

    except openstack.exceptions.HttpException as exp_err:
        print("LOG: Error Received while attempting to create domain - %s" % str(exp_err))
        if str(exp_err).find("You are not authorized"):
            print("LOG: Tenant are not allowed to create a domain")
            compliance_status = "Compliant"
        else:
            compliance_status = "Non-compliant"
           
        resource = project_name + "-" + "create_domain"
        if scanid_valid and teamid_valid:
            if kinesis_update(session, "P3", scan_id, tc, team_id, resource, compliance_status):
                print("LOG: Inside For loop Added the info to Kinesis Stream")
            else:
                print("ERROR: Kinesis Update API Failed")
                return None
        else:
            print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

        return compliance_status

    except Exception as e:
        print("ERROR: Issue observed while calling create domain() API - %s" % str(e))
        return None


def list_domain(conn, project_name, scan_id, team_id, session, scanid_valid, teamid_valid):
    """
    This method is to validate that tenant are not allowed to list/read the domains
    in P3 platform.
    :param conn: connection handle to OpenStack project
    :param project_name: project name
    :param seq_nums_list: empty list
    :param params_list: empty list
    :param scan_id: ScanID received from AWS SQS
    :param team_id: TeamID
    :param session: session handle to Kinesis
    :return: Compliant | Non-Compliant | None
    """
    try:
        domain_list = []
        audit_time = int(time.time()) * 1000
        for list_domain in conn.identity.domains():
            domain = json.dumps(list_domain)
        print("ERROR: Tenant are being allowed to list domain")
        compliance_status = "Non-compliant"
        return compliance_status
    except openstack.exceptions.HttpException as exp_err:
        print("LOG: Error Received while attempting to list domains - %s" % str(exp_err))
        if str(exp_err).find("You are not authorized"):
            print("LOG: Tenant are not allowed to list domains")
            compliance_status = "Compliant"
        else:
            compliance_status = "Non-compliant"

        resource = project_name + "-" + "list_domain"
        if scanid_valid and teamid_valid:
            if kinesis_update(session, "P3", scan_id, tc, team_id, resource, compliance_status):
                print("LOG: Inside For loop Added the info to Kinesis Stream")
            else:
                print("ERROR: Kinesis Update API Failed")
                return None
        else:
            print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

        return compliance_status
    except Exception as e:
        print("ERROR: Issue observed while calling listing domains() API - %s" % str(e))
        return None


def change_domain(conn, domain_name, project_name, scan_id, team_id, session, scanid_valid, teamid_valid):
    """
    This method is to validate that tenant are not allowed to change the domain
    in P3 platform.
    :param conn: Connection handle to OpenStack project
    :param domain_name: current domain name
    :param project_name: Project Name
    :param seq_nums_list: empty list
    :param params_list: empty list
    :param scan_id: ScanID received from AWS SQS
    :param team_id: TeamID
    :param session: session handle to Kinesis
    :return: Compliant | Non-Compliant | None
    """
    try:
        domain_change = []
        audit_time = int(time.time()) * 1000
        for change_domain in conn.identity.update_domain(domain_name, name="admin", description=None, enabled=None):
            new_domain = change_domain
        print("ERROR: Tenant are being allowed to change a domain")
        compliance_status = "Non-compliant"
        return compliance_status
    except openstack.exceptions.ResourceNotFound as exp_err:
        print("LOG: Error Received while attempting to change domain - %s" % str(exp_err))
        if str(exp_err).find("Could not find domain"):
            print("LOG: Tenant are not allowed to change a domain")
            compliance_status = "Compliant"
        else:
            compliance_status = "Non-compliant"

        resource = project_name + "-" + "change_domain"
        if scanid_valid and teamid_valid:
            if kinesis_update(session, "P3", scan_id, tc, team_id, resource, compliance_status):
                print("LOG: Inside For loop Added the info to Kinesis Stream")
            else:
                print("ERROR: Kinesis Update API Failed")
                return None
        else:
            print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

        return compliance_status
    except Exception as e:
        print("ERROR: Issue observed while calling create domain() API - %s" % str(e))
        return None


def compliant_status_of_tenant(project_name, role, user, domain, domain_list, domain_change, team_id):
    """
    This method is to summarize compliant status of P3 identity management.
    :param project_name:
    :param role:
    :param user:
    :param domain_change:
    :param team_id:
    :return:
    """
    try:
        compliant_status =[]
        for compliance_status in role:
            if compliance_status in role == 'Compliant':
                create_role = "Not Allowed"
            else:
                create_role = "Allowed"
        for compliance_status in user:
            if compliance_status in user == 'Compliant':
                create_user = "Not Allowed"
            else:
                create_user = "Allowed"
        for compliance_status in domain:
            if compliance_status in domain == 'Compliant':
                domain_create = "Not Allowed"
            else:
                domain_create = "Allowed"
        for compliance_status in domain_list:
            if compliance_status in domain_list == 'Compliant':
                domain_lists = "Not Allowed"
            else:
                domain_lists = "Allowed"        
        for compliance_status in domain_change:
            if compliance_status in domain_change == 'Compliant':
                change_domain = "Not Allowed"
            else:
                change_domain = "Allowed"

        if role == user == domain_change == "Compliant":
            compliance_status = "Compliant"
        else:
            compliance_status = "Non-compliant"

        compliant_status.append([
                                team_id,
                                project_name,
                                create_role,
                                create_user,
                                domain_create,
                                domain_lists,
                                change_domain,
                                compliance_status
                              ])

        headers = ["Tenant Id", "Tenant Name", "Create Role", "Create User", "Create Domain", "List Domain", "Change Domain", "Compliance Status"]
        date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.path.expanduser("~") + "/logs/p3_identity_mgmt_tc_1_" + date_stamp + ".csv"
        with open(csv_filename, 'a') as f:
            file_is_empty = os.stat(csv_filename).st_size == 0
            writer = csv.writer(f, lineterminator='\n')
            if file_is_empty:
                writer.writerow(headers)
            writer.writerows(compliant_status)
        f.close()
    except Exception as e:
        print("ERROR: Issue observed while retrieving compliance status() API - %s" % str(e))
        if str(e):
            headers = ["Tenant Id", "Tenant Name", "Create Role", "Create User", "Create Domain", "List Domain", "Change Domain", "Compliance Status"]
            Exception_list = [team_id, project_name, "", "", "", "", "", ""]
            date_stamp = datetime.datetime.now().strftime('%m%d%y')
            csv_filename = os.path.expanduser("~") + "/logs/p3_identity_mgmt_tc_1_" + date_stamp + ".csv"
            with open(csv_filename, 'a') as f:
                file_is_empty = os.stat(csv_filename).st_size == 0
                writer = csv.writer(f, lineterminator='\n')
                if file_is_empty:
                    writer.writerow(headers)
                writer.writerows([Exception_list])
            f.close()
        else:
            return None
def scanid_validation(scan_id):
    """
    This method is to validate that scan id while sending the report to Kinesis.
    :param scan_id: ScanID received from AWS SQS
    """
    scanid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    if scanid_pattern.match(scan_id):
        print("LOG: Received valid ScanID")
        return True
    else:
        print("ERROR: Received ScanID is not valid")
        return False


def p3_teamid_validation(team_id):
    """
    This method is to validate that team id of the P3 platform while sending the report to Kinesis.
    :param team_id: TeamID
    """
    teamid_pattern = re.compile(r'^P3:[0-9a-f]{32}$')
    if teamid_pattern.match(team_id):
        print("LOG: Received valid TeamID")
        return True
    else:
        print("ERROR: Received TeamID is not valid")
        return False


def p3_url_validation(url):
    """
    This method is to validate the authorized url of the P3 platform.
    :url: OpenStack's Horizon URL
    """
    p3_url_pattern = re.compile(r'^https://cloud-.*-1.cisco.com:5000/v3$')
    if p3_url_pattern.match(url):
        print("LOG: Received valid Domain URL")
        return True
    else:
        print("ERROR: Received Domain URL is not valid")
        return False


def kinesis_update(session, platform, scan_id, tc, team_id, resource_name, compliance_status):
    params_list = []
    audit_time = int(time.time()) * 1000
    try:
        params = {
            "scanid": scan_id,
            "testid": tc,
            "teamid": str(team_id),
            "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, resource_name),
            "createdAt": audit_time,
            "updatedAt": audit_time,
            "resourceName": resource_name,
            "complianceStatus": compliance_status
        }
        params_list.append(params.copy())

        while sys.getsizeof(json.dumps(params_list)) >= 900000:
            print("INFO: FIRST ELEMENT OF PARAMS LIST: ", params_list[0])
            stream_info = add_result_to_stream(session, platform, str(team_id), tc, params_list)
            if stream_info is None:
                raise Exception("ERROR: Issue observed while calling add_result_to_stream() API")
                return None

            seq_nums_list.append(stream_info)
            print("LOG: Empty params list ... ", params_list)
            params_list[:] = []

        print("INFO: Adding result to Stream")
        stream_info = add_result_to_stream(session, platform, str(team_id), tc, params_list)
        if stream_info is None:
            raise Exception("ERROR: Issue observed while calling add_result_to_stream() API")
            return None

        seq_nums_list.append(stream_info)
        return True

    except Exception as params_err:
        print("ERROR: Issue observed while adding result to streams - %s" % str(params_err))
        return False


def main(os_auth_url, project_name, scan_id, team_id):
    """
    This main method is to validate the tenant are not allowed to create the users, roles and
    the domain in the P3 platform.
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
        
        domain_name = env["OS_PROJECT_DOMAIN_NAME"]
        region = os_auth_url.split(".")[0].split("//")[1]
        print("LOG: Creating Connection handle to OpenStack Project - %s" % project_name)
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

        try:
            role = create_new_role(conn, project_name, scan_id, team_id, session, scanid_valid, teamid_valid)
            user = create_new_user(conn, project_name, scan_id, team_id, session, scanid_valid, teamid_valid)
            domain = create_domain(conn, project_name, scan_id, team_id, session, scanid_valid, teamid_valid)
            domain_list = list_domain(conn, project_name, scan_id, team_id, session, scanid_valid, teamid_valid)
            domain_change = change_domain(conn, domain_name, project_name, scan_id, team_id, session, scanid_valid, teamid_valid)
            compliant_status_of_tenant(project_name, role, user, domain, domain_list, domain_change, team_id)

            list_of_return_vals = [role, user, domain, domain_list, domain_change]
            if any(val == "Non-compliant" for val in list_of_return_vals):
                print("INFO: One of the test is Non-compliant")
                compliance_status = "Non-compliant"
            elif any(val is None for val in list_of_return_vals):
                print("INFO: One of the test returned None")
                compliance_status = "None"
            else:
                print("INFO: All checks are Compliant")
                compliance_status = "Compliant"

        
        except Exception as e:
            print("ERROR: Issue observed during execution - %s" % str(e))
            if scanid_valid and teamid_valid:
                print("LOG: Update the scan record with \"Failed\" Status")
                update = updateScanRecord(session, "P3", scan_id, team_id, tc, "Failed")
                if update is None:
                    raise Exception("ERROR: Issue observed with UpdateScanRecord API call for \"Failed\" status")
                    return None

            return None
    else:
        raise Exception("ERROR: Failed to get the connection handle")
        return None

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
    parser = argparse.ArgumentParser(description="Validate the negative test cases w.r.t. Identity Services in P3 platform...")
    parser.add_argument("-u", "--auth_url", help="OpenStack Horizon URL", action="store", dest="url")
    parser.add_argument("-t", "--team_name", help="Project/Tenant Name", action="store", dest="team")
    parser.add_argument("-s", "--scan_id", help="Scan ID from AWS", action="store", dest="scanid")
    parser.add_argument("-i", "--team_id", help="Project/Tenant ID", action="store", dest="teamid")
    args = parser.parse_args()
    url = args.url
    p_name = args.team
    scan_id = args.scanid
    team_id = args.teamid
    url_valid = p3_url_validation(url)
    if p_name is not None:
        if url_valid:
            compliance_status = main(url, p_name, scan_id, team_id)
            print("LOG: Process complete with compliance status as - %s" % compliance_status)
        else:
            print("ERROR: Failed with validation")
    else:
        print("ERROR:Need Tenant ID and Horizon URL to run the script")
