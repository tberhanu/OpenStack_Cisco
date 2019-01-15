#!/opt/app-root/bin/python

"""
------------------------------cae_identity_mgmt_tc_1.py--------------------
Description: This python script is to find out if any user have a role
             that outside the set of the roles defined for the normal user.

Dependency:
        cae_user_roles

Author: Sanjeev Garg <sangarg@cisco.com>; December 21st, 2018

Copyright (c) 2018 Cisco Systems.
All rights reserved.
---------------------------------------------------------------------------
"""

import argparse
import datetime
import dateutil.parser
import json
import os
import pandas as pd
import requests.packages.urllib3
import sys
import time

from kubernetes import client, config
from openshift.dynamic import DynamicClient

sys.path.append(os.environ["CLONED_REPO_DIR"] + "/library")
from general_util import updateScanRecord, add_result_to_stream, send_result_complete, session_handle

requests.packages.urllib3.disable_warnings()

filename = os.path.abspath(__file__).split("/")[-1].split(".py")[0]
tc = filename.replace("_", "-").upper()

def create_connection(url):
    """
    Method to create connection with client
    :param url:
    :return:
    """
    try:
        if url is not None:
            url_split = url.strip().split('.')
            string = str(url_split[0])
            string_split = string.strip().split('-')
            region_name = str(string_split[2].strip())
            path = os.path.expanduser("~") + "/" + "kube_config"
        k8s_client = config.new_client_from_config(path)
        dyn_client = DynamicClient(k8s_client)
    except Exception as e:
        print("ERROR: Fail to retrieve the user roles with error in connection: %s" % str(e))
        return None

    return dyn_client


def read_trusted_roles(filename):
    """
    Method to read roles from text file
    :param filename:
    :return:
    """
    try:
        with open(filename) as f:
            content = f.readlines()
        trusted_roles = [x.strip() for x in content]
    except IOError as e:
        print("ERROR: An error occurred trying to read the file.: %s" % str(e))
        return None
    except Exception as e:
        print("ERROR: Fail to retrieve the user roles with error in trusted roles: %s" % str(e))
        return None
    return trusted_roles


def fetch_project_list(dyn_client, project_name):
    """
    Method to fetch the project list
    :param dyn_client:
    :param project_name:
    :return:
    """
    try:
        project_name_id_mapping = {}
        project_list = []
        v1_projects = dyn_client.resources.get(api_version='project.openshift.io/v1', kind='Project')
        projects = v1_projects.get()

        for project in projects.items:
            project_list.append(project.metadata.name)
            project_name_id_mapping[project.metadata.name] = project.metadata.uid
        if project_name is not None:
            if project_name in project_list:
                project_list = [project_name]
            else:
                print("project %s is not present" % project_name)
                data = list()
                data.append(["null", project_name, "null", "null", "null", "null", "null"])
                df = pd.DataFrame(data,columns=["Tenant ID", "Tenant Name", "Application ID", "Application Name", "Role Name", "Users with Associate Roles", "Role Provisioned Age"])
                df.to_csv('output.csv')
                exit()
    except Exception as e:
        print("ERROR: Fail to retrieve the user roles with error: %s" % str(e))
        return None, None, None

    return projects, project_list, project_name_id_mapping

def get_app_project_mapping(projects):
    """
    Method to get application project mapping
    :param projects:
    :return:
    """
    try:
        app_list = projects
        app_project_mapping = {}
        for i in app_list.items:
            app_project_mapping[i.metadata.name] = {
                    'app_id': i.metadata.annotations['citeis.cisco.com/application-id'],
                    'app_name' : i.metadata.annotations['citeis.cisco.com/application-name']
            }
    except Exception as e:
        print("ERROR: Fail to retrieve the user roles with error in project_mapping : %s" % str(e))
        return None

    return app_project_mapping


def get_rolebindings(dyn_client, projects, trusted_roles, project_name, project_name_id_mapping, project_list, scan_id, team_id, params_list, seq_nums_list, session):
    """
    Method to get rolebindings
    :param dyn_client:
    :param projects:
    :param trusted_roles:
    :param project_name:
    :param project_name_id_mapping:
    :param scan_id:
    :param team_id:
    :param project_list:
    :param params_list:
    :param seq_nums_list:
    :param session:
    :return:
    """
    try:
        flag = 0
        data = []
        audit_time = int(time.time()) * 1000
        roles = dyn_client.resources.get(api_version='authorization.openshift.io/v1', kind='RoleBinding')
        rolebinding_all = {}
        rolebinding_untrusted = {}
        all_roles = []
        users_with_untrusted_roles = []
        compliant_status = "Compliant"
        for project in project_list:
            rolebinding_project = roles.get(namespace=project)
            rolebinding_dict = rolebinding_project.to_dict()
            proj_role_bind = {}
            proj_role_bind_untrusted = {}
            for i in rolebinding_dict['items']:
                all_roles.append(i['roleRef']['name'])
                proj_role_bind[i['roleRef']['name']] = {'usernames': i['userNames'], 'timecreated' : i['metadata']['creationTimestamp']}
                if i['roleRef']['name'] not in trusted_roles:
                    proj_role_bind_untrusted[i['roleRef']['name']] = {'usernames': i['userNames'], 'timecreated' : i['metadata']['creationTimestamp']}
                    users_with_untrusted_roles.append(i['userNames'])
            rolebinding_all[project] = proj_role_bind
            rolebinding_untrusted[project] = proj_role_bind_untrusted.copy() if bool(proj_role_bind_untrusted) else None
        users_with_untrusted_roles = [item for sublist in users_with_untrusted_roles if sublist for item in sublist]
        project_app = get_app_project_mapping(projects)
        if not rolebinding_untrusted[project_name]:
            print('Pass')
            flag = 1
            return rolebinding_all, all_roles, rolebinding_untrusted, users_with_untrusted_roles, flag
        for project in rolebinding_untrusted:
            if rolebinding_untrusted[project] is not None:
                for role in rolebinding_untrusted[project]:
                    dt = dateutil.parser.parse(rolebinding_untrusted[project][role]['timecreated'])
                    dt = dt.replace(tzinfo=None)
                    diff = datetime.datetime.now() - dt
                    diff = ("%s Days %s Hours %s Mins" % (diff.days, diff.seconds//3600, (diff.seconds//60)%60))
                    if project in project_app:
                            if rolebinding_untrusted[project][role]['usernames'] is not None:
                                for user in range(len(rolebinding_untrusted[project][role]['usernames'])):
                                    data.append([project_name_id_mapping[project], project, project_app[project]['app_id'], project_app[project]['app_name'], role, rolebinding_untrusted[project][role]['usernames'][user], diff])
                            else:
                                data.append([project_name_id_mapping[project], project, project_app[project]['app_id'], project_app[project]['app_name'], role, "None", diff])
                    else:
                        if rolebinding_untrusted[project][role]['usernames'] is not None:
                            for user in range(len(rolebinding_untrusted[project][role]['usernames'])):
                                data.append([project_name_id_mapping[project], project, "None", "None", role, rolebinding_untrusted[project][role]['usernames'][user], diff])
                        else:
                            data.append([project_name_id_mapping[project], project, "None", "None", role, "None", diff])
        df = pd.DataFrame(data,columns=["Tenant ID", "Tenant Name", "Application ID", "Application Name", "Role Name", "Users with Associate Roles", "Role Provisioned Age"])
        df.to_csv('output.csv',index=False)
        print('Fail')
        data_all = []
        for project in rolebinding_all:
            if rolebinding_all[project] is not None:
                for role in rolebinding_all[project]:
                    if "system" in role:
                        continue
                    dt = dateutil.parser.parse(rolebinding_all[project][role]['timecreated'])
                    dt = dt.replace(tzinfo=None)
                    diff = datetime.datetime.now() - dt
                    diff = ("%s Days %s Hours %s Mins" % (diff.days, diff.seconds//3600, (diff.seconds//60) % 60))
                    if project in project_app:
                            if rolebinding_all[project][role]['usernames'] is not None:
                                for user in rolebinding_all[project][role]['usernames']:
                                    role_user = role + "-" + user
                                    if role in trusted_roles:
                                        compliant_status = "Compliant"
                                    else:
                                        compliant_status = "Non-compliant"
                                    params = {
                                                 "scanid": scan_id,
                                                 "testid": tc,
                                                 "teamid": str(team_id),
                                                 "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, role_user),
                                                 "createdAt": audit_time,
                                                 "updatedAt": audit_time,
                                                 "resourceName": role_user,
                                                 "complianceStatus": compliant_status
                                              }
                                    params_list.append(params.copy())

                                    while sys.getsizeof(json.dumps(params_list)) >= 900000:
                                        print("LOG: FIRST ELEMENT OF PARAMS LIST: ", params_list[0])
                                        stream_info = add_result_to_stream(session, "CAE", str(team_id), tc, params_list)
                                        seq_nums_list.append(stream_info)

                                print("LOG: Adding result to Stream")
                                stream_info = add_result_to_stream(session, "CAE", str(team_id), tc, params_list)
                                seq_nums_list.append(stream_info)

                                print("LOG: Sending result complete")
                                send_result_complete(session, "CAE", scan_id, team_id, tc, seq_nums_list)
                                data_all.append([project_name_id_mapping[project], project, project_app[project]['app_id'], project_app[project]['app_name'], role, user, diff])
                            else:
                                data_all.append([project_name_id_mapping[project], project, project_app[project]['app_id'], project_app[project]['app_name'], role, "None", diff])
                    else:
                        if rolebinding_all[project][role]['usernames'] is not None:
                            for user in rolebinding_all[project][role]['usernames']:
                                data_all.append([project, "None", "None", role, user, diff])
                        else:
                            data_all.append([project, "None", "None", role, "None", diff])
        df = pd.DataFrame(data_all, columns=["Tenant ID", "Tenant Name", "Application ID", "Application Name", "Role Name", "Users with Associate Roles", "Role Provisioned Age"])
        df.to_csv('metadata.csv', index=False)
        print(params_list)
    except Exception as e:
        print("ERROR: Fail to retrieve the user roles with error in rolebindings : %s" %str(e))

    return rolebinding_all, all_roles, rolebinding_untrusted, users_with_untrusted_roles, flag


def output_parameters(trusted_roles, rolebinding_all={}, all_roles=[], rolebinding_untrusted={}, users_with_untrusted_roles=[]):
    """
    Method to print all required parameters
    :param trusted_roles:
    :param rolebinding_all:
    :param all_roles:
    :param rolebinding_untrusted:
    :param users_with_untrusted_roles:
    :return:
    """
    try:
        print("Total Number of Tenants Evaluated in Platform : %s" % (len(rolebinding_all.keys())))
        untrusted_roles = set(all_roles) - set(trusted_roles)
        print("Total Number of Unique Roles found evaluated in Platform : %s" % len(set(all_roles)))
        print("Total Number of Untrusted Role Found found : %s" % len(untrusted_roles))
        print(" untrusted: %s" % rolebinding_untrusted)
        projects_with_untrusted_roles = [i for i in rolebinding_untrusted.keys() if rolebinding_untrusted[i] is not None]
        print("Untrusted roles belongs to these many tenants: %s" % len(projects_with_untrusted_roles))
        print("Unsecured role belongs to these many users : %s" % len(set(users_with_untrusted_roles)))
    except Exception as e:
        print("ERROR: Failed to retrieve the user roles with error in output: %s" % str(e))


def main(path_url, p_name, scan_id, team_id):
    """
    :Constructor with project name and url as parameter
    :param project_name: holds the name of project
    :param url: holds the url of project
    """
    project_name = p_name
    filename = os.environ["CLONED_REPO_DIR"] + "/audit_scripts/cae_user_roles"
    if os.path.isfile(filename):
        session = session_handle()
        if session:
            print("LOG: Update the scan record with \"InProgress\" Status")
            updateScanRecord(session, "CAE", scan_id, team_id, tc, "InProgress")
            seq_nums_list = []
            params_list = []

            try:
                dyn_client = create_connection(path_url)
                if dyn_client:
                    trusted_roles = read_trusted_roles(filename)
                    projects, project_list, project_name_id_mapping = fetch_project_list(dyn_client, project_name)
                    if projects and project_list:
                        rolebinding_all, all_roles, rolebinding_untrusted, users_with_untrusted_roles, flag = get_rolebindings(dyn_client, projects, trusted_roles, project_name, project_name_id_mapping, project_list, scan_id, team_id, params_list, seq_nums_list, session)
                    else:
                        raise Exception("ERROR: Failed to fetch either Projects: %s or Project_list: %s" % (projects, project_list))
                        updateScanRecord(session, "CAE", scan_id, team_id, tc, "Failed")
                    output_parameters(trusted_roles, rolebinding_all, all_roles, rolebinding_untrusted, users_with_untrusted_roles)
                else:
                    raise Exception("ERROR: Failed to establish connection to CAE Project %s" % project_name)
            except Exception as e:
                print("ERROR: Fail to retrieve the user roles with error in main : %s" % str(e))
                return None
        else:
            raise Exception("ERROR: Failed to get the connection handle")
            return None
    else:
        raise Exception("ERROR: The dependency file %s is not available for use" % filename)
        return None
    if flag == 1:
        return "Compliant"
    else:
        return "Non-Compliant"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the Roles associated with users listed in OpenShift Project...")
    parser.add_argument("-u", "--auth_url", help="OpenShift Domain URL",required=True,action="store", dest="url")
    parser.add_argument("-t", "--team_name", help="Project/Tenant Name", action="store", dest="team")
    parser.add_argument("-s", "--scan_id", help="Scan Id from AWS", action="store", dest="scanid")
    parser.add_argument("-i", "--team_id", help="Project/Tenant ID", action="store", dest="teamid")

    args = parser.parse_args()

    url = args.url
    p_name = args.team
    scan_id = args.scanid
    team_id = args.teamid

    compliant_status = main(url, p_name, scan_id, team_id)
    print(compliant_status)
