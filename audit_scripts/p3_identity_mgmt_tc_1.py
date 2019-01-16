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
import json
import openstack
import os
import sys
import time

from os import environ as env

sys.path.append(os.environ["CLONED_REPO_DIR"] + "/library")
from general_util import updateScanRecord, add_result_to_stream, send_result_complete, session_handle

filename = os.path.abspath(__file__).split("/")[-1].split(".py")[0]
tc = filename.replace("_", "-").upper()


def create_new_role(conn, project_name, seq_nums_list, params_list, scan_id, team_id, session):
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
        audit_time = int(time.time()) * 1000
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
            role.append(compliance_status)
            #return compliance_status
        else:
            compliance_status = "Non-compliant"
            role.append(compliance_status)
            #return compliance_status

        resource = project_name + "-" + "create_role"
        params = {
                    "scanid": scan_id,
                    "testid": tc,
                    "teamid": str(team_id),
                    "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, resource),
                    "createdAt": audit_time,
                    "updatedAt": audit_time,
                    "resourceName": resource,
                    "complianceStatus": compliance_status,
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
        return compliance_status
    except Exception as e:
        print("ERROR: Issue observed while calling create_role() API - %s" % str(e))
        return None


def create_new_user(conn, project_name, seq_nums_list, params_list, scan_id, team_id, session):
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
            user.append(compliance_status)
            #return compliance_status
        else:
            compliance_status = "Non-compliant"
            user.append(compliance_status)
            #return compliance_status

        resource = project_name + "-" + "create_user"
        params = {
                    "scanid": scan_id,
                    "testid": tc,
                    "teamid": str(team_id),
                    "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, resource),
                    "createdAt": audit_time,
                    "updatedAt": audit_time,
                    "resourceName": resource,
                    "complianceStatus": compliance_status,
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
        return compliance_status

    except Exception as e:
        print("ERROR: Issue observed while calling create_user() API - %s" % str(e))
        return None


def create_domain(conn, project_name, seq_nums_list, params_list, scan_id, team_id, session):
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
            domain.append(compliance_status)
            # return compliance_status
        else:
            compliance_status = "Non-compliant"
            domain.append(compliance_status)
            # return compliance_status

        resource = project_name + "-" + "create_domain"
        params = {
                    "scanid": scan_id,
                    "testid": tc,
                    "teamid": str(team_id),
                    "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, resource),
                    "createdAt": audit_time,
                    "updatedAt": audit_time,
                    "resourceName": resource,
                    "complianceStatus": compliance_status,
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
        return compliance_status

    except Exception as e:
        print("ERROR: Issue observed while calling create domain() API - %s" % str(e))
        return None


def list_domain(conn, project_name, seq_nums_list, params_list, scan_id, team_id, session):
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
            domain_list.append(compliance_status)
            # return compliance_status
        else:
            compliance_status = "Non-compliant"
            domain_list.append(compliance_status)
            # return compliance_status

        resource = project_name + "-" + "list_domain"
        params = {
                    "scanid": scan_id,
                    "testid": tc,
                    "teamid": str(team_id),
                    "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, resource),
                    "createdAt": audit_time,
                    "updatedAt": audit_time,
                    "resourceName": resource,
                    "complianceStatus": compliance_status,
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
        return compliance_status

    except Exception as e:
        print("ERROR: Issue observed while calling listing domains() API - %s" % str(e))
        return None


def change_domain(conn, domain_name, project_name, seq_nums_list, params_list, scan_id, team_id, session):
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
            domain_change.append(compliance_status)
            #return compliance_status
        else:
            compliance_status = "Non-compliant"
            domain_change.append(compliance_status)
            #return compliance_status
        resource = project_name + "-" + "change_domain"
        params = {
                    "scanid": scan_id,
                    "testid": tc,
                    "teamid": str(team_id),
                    "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, resource),
                    "createdAt": audit_time,
                    "updatedAt": audit_time,
                    "resourceName": resource,
                    "complianceStatus": compliance_status,
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
        return compliance_status

    except Exception as e:
        print("ERROR: Issue observed while calling create domain() API - %s" % str(e))
        return None


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
        print("LOG: Update the scan record with \"InProgress\" Status")
        updateScanRecord(session, "P3", scan_id, team_id, tc, "InProgress")
        seq_nums_list = []
        params_list = []

        role = create_new_role(conn, project_name, seq_nums_list, params_list, scan_id, team_id, session)
        user = create_new_user(conn, project_name, seq_nums_list, params_list, scan_id, team_id, session)
        domain = create_domain(conn, project_name, seq_nums_list, params_list, scan_id, team_id, session)
        domain_list = list_domain(conn, project_name, seq_nums_list, params_list, scan_id, team_id, session)
        domain_change = change_domain(conn, domain_name, project_name, seq_nums_list, params_list, scan_id, team_id, session)
    else:
        updateScanRecord(session, "P3", scan_id, team_id, tc, "Failed")
        raise Exception("ERROR: Issue observed with Session Handle creation")
        return None

    if role == user == domain == domain_list == domain_change == "Compliant":
        compliance_status = "Compliant"
        return compliance_status
    else:
        compliance_status = "Non-compliant"
        return compliance_status


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the negative test cases in P3 platform...")
    parser.add_argument("-u", "--auth_url", help="OpenStack Horizon URL", action="store", dest="url")
    parser.add_argument("-t", "--team_name", help="Project/Tenant Name", action="store", dest="team")
    parser.add_argument("-s", "--scan_id", help="Scan ID from AWS", action="store", dest="scanid")
    parser.add_argument("-i", "--team_id", help="Project/Tenant ID", action="store", dest="teamid")
    args = parser.parse_args()
    url = args.url
    p_name = args.team
    scan_id = args.scanid
    team_id = args.teamid

    compliance_status = main(url, p_name, scan_id, team_id)
    print(compliance_status)
