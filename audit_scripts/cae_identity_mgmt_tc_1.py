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
import os
import pandas as pd
import re
import requests.packages.urllib3
import sys
import time

from kubernetes import client, config
from openshift.dynamic import DynamicClient

sys.path.append(os.environ["CLONED_REPO_DIR"] + "/library")
import cae_lib
import common_lib
import general_util


requests.packages.urllib3.disable_warnings()

filename = os.path.abspath(__file__).split("/")[-1].split(".py")[0]
tc = filename.replace("_", "-").upper()
seq_nums_list = []
params_list = []
admin_untrusted = 0


def create_connection(url):
    """
    :Method to create connection with client
    :param url:URL of each region
    :return:dyn_client
    """
    try:
        if url is not None:
            path = cae_lib.get_kube_config_path(url)
        print("INFO: Kube Config's Path", path)

        for i in range(0, 10):
            try:
                k8s_client = config.new_client_from_config(path)
                dyn_client = DynamicClient(k8s_client)
            except Exception as e:
                exception_str = str(e)
                if '429' in exception_str:
                    print("LOG: RETRYING upon receiving \"HTTP error 429 (Too Many Requests)\"", str(exception_str))
                    time.sleep(5)
                    continue
            break

    except Exception as e:
        print("ERROR: Fail to create connection handle: %s" % str(e))
        return None

    return dyn_client


def read_trusted_roles(filename):
    """
    :Method to read roles from text file
    :param filename:path of the trusted role file
    :return:list of trusted roles
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
     Method to fetch the project list and validate if the exists in that list or not
    :param dyn_client:
    :param project_name:
    :return:
    """
    try:
        project_name_id_mapping = {}
        project_list = []
        v1_projects = dyn_client.resources.get(
            api_version='project.openshift.io/v1', kind='Project')
        projects = v1_projects.get()
        # count = 0
        # project_data = []
        print("INFO: Getting list of projects available in the Cluster to validate the existence of %s" % project_name)
        for project in projects.items:
            # if project.metadata.name is not None:
            #     count = count + 1
            # project_data.append(project.metadata.name)
            project_list.append(project.metadata.name)
            project_name_id_mapping[
                project.metadata.name] = project.metadata.uid
       
        if project_name is not None:
            if project_name in project_list:
                project_list = [project_name]
            else:
                raise Exception("ERROR: Project %s is not present" % project_name)
                return None, None, None
        else:
            raise Exception("ERROR: Project name received holds 'None'")
            return None, None, None

    except Exception as e:
        print("ERROR: Fail to retrieve the user roles with error: %s" % str(e))
        return None, None, None

    return projects, project_list, project_name_id_mapping


def get_app_project_mapping(projects):
    """
     Method to get application project mapping
    :param projects:
    :return:app_project_mapping
    """
    try:
        app_list = projects
        app_project_mapping = {}

        for i in app_list.items:
            application_id = "None"
            application_name = "None"
            if i.metadata.annotations['citeis.cisco.com/application-id'] is not None:
                application_id = i.metadata.annotations['citeis.cisco.com/application-id']
            if i.metadata.annotations['citeis.cisco.com/application-name'] is not None:
                application_name = i.metadata.annotations['citeis.cisco.com/application-name']
            app_project_mapping[i.metadata.name] = {
                                                    'app_id': application_id,
                                                    'app_name': application_name
            }
    except Exception as e:
        print("ERROR: Fail to retrieve the user roles with error in project_mapping : %s" % str(e))
        return None

    return app_project_mapping


def get_rolebindings(dyn_client, projects, trusted_roles, project_name,
                     project_name_id_mapping, project_list, scan_id, team_id,
                     session, path_url, scanid_valid, teamid_valid):
    """
     Method to get rolebindings data
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
        admin_untrusted=0
        flag = 0
        roles = dyn_client.resources.get(
                                            api_version='authorization.openshift.io/v1',
                                            kind='RoleBinding'
                                        )
        rolebinding_all = {}
        rolebinding_groupName_all = {}
        rolebinding_untrusted = {}
        rolebinding_groupname_untrusted = {}
        all_roles = []
        users_with_untrusted_roles = []
        compliance_status = "Non-compliant"
        for project in project_list:
            rolebinding_project = roles.get(namespace=project)
            rolebinding_dict = rolebinding_project.to_dict()
            proj_role_bind = {}
            proj_role_group_name= {}
            proj_role_bind_untrusted = {}
            proj_role_group_name_untrusted = {}
            for i in rolebinding_dict['items']:
                all_roles.append(i['roleRef']['name'])
                proj_role_group_name[i['roleRef']['name']]=i['groupNames']
                if i['roleRef']['name'] not in proj_role_bind:
                    proj_role_bind[i['roleRef']['name']] = {
                        'usernames': i['userNames'],
                        'timecreated': i['metadata']['creationTimestamp']}
                else:
                    if i['userNames'] is not None:
                        proj_role_bind[i['roleRef']['name']]['usernames'].extend(i['userNames'])

                if i['roleRef']['name'] not in trusted_roles:
                    if i['groupNames'] is not None:
                        proj_role_group_name_untrusted[i['roleRef']['name']]=i['groupNames']
                    if i['roleRef']['name'] not in proj_role_bind_untrusted:
                        proj_role_bind_untrusted[i['roleRef']['name']] = {
                            'usernames': i['userNames'],
                            'timecreated': i['metadata']['creationTimestamp']}
                    else:
                        if i['userNames'] is not None:
                            proj_role_bind_untrusted[i['roleRef']['name']]['usernames'].extend(i['userNames'])
                    if i['userNames'] is not None:
                        users_with_untrusted_roles.extend(i['userNames'])
                if "admin" == i['roleRef']['name']:                    
                    for user in i['userNames']:
                        if user != "citeis-orchadm.gen":
                            admin_untrusted +=1
                            if i['roleRef']['name'] not in proj_role_bind_untrusted:
                                proj_role_bind_untrusted[i['roleRef']['name']] = {
                                    'usernames': [user],
                                    'timecreated': i['metadata'][
                                        'creationTimestamp']}
                                if i['userNames'] is not None:
                                    admin_untrusted_users = i['userNames']
                                    if "citeis-orchadm.gen" in admin_untrusted_users: 
                                        admin_untrusted_users.remove("citeis-orchadm.gen")
                                    users_with_untrusted_roles.extend(admin_untrusted_users)
                            else:
                                users_with_untrusted_roles.extend(i['userNames'])
                                proj_role_bind_untrusted[i['roleRef']['name']]['usernames'].append(user)
            rolebinding_all[project] = proj_role_bind
            rolebinding_groupName_all[project]=proj_role_group_name
            rolebinding_untrusted[
                project] = proj_role_bind_untrusted.copy() if bool(
                proj_role_bind_untrusted) else None
            if len(proj_role_group_name_untrusted)!=0:
                rolebinding_groupname_untrusted[project]=proj_role_group_name_untrusted
        project_app = get_app_project_mapping(projects)
        if not rolebinding_untrusted[project_name]:
            flag = 1
        untrused_data(rolebinding_untrusted, project_app,
                      project_name_id_mapping, path_url,rolebinding_groupname_untrusted)
        complete_data(rolebinding_all, project_app, project_name_id_mapping, trusted_roles, session,
                      team_id, scan_id, path_url, scanid_valid, teamid_valid,rolebinding_groupName_all)

        if not rolebinding_untrusted[project_name]:
            flag = 1
            return rolebinding_all, all_roles, rolebinding_untrusted, users_with_untrusted_roles, flag, admin_untrusted, rolebinding_groupname_untrusted
    except Exception as e:
        print("ERROR: Fail to retrieve the user roles with error in rolebindings : %s" % str(e))
    return rolebinding_all, all_roles, rolebinding_untrusted, users_with_untrusted_roles, flag, admin_untrusted, rolebinding_groupname_untrusted


def untrused_data(rolebinding_untrusted, project_app, project_name_id_mapping, path_url,rolebinding_groupname_untrusted):
    """
     Method to append untrusted/Non-compliant data into a csv file
    :param rolebinding_untrusted:
    :param project_app:
    :param project_name_id_mapping:
    :param path_url:
    :param rolebinding_groupname_untrusted:
    :return:
    """
    try:
        data = []
        for project in rolebinding_untrusted:
            if rolebinding_untrusted[project] is not None:
                for role in rolebinding_untrusted[project]:
                    print("INFO: Calculating the age of role assigned to the user")
                    dt = dateutil.parser.parse(
                        rolebinding_untrusted[project][role]['timecreated'])
                    dt = dt.replace(tzinfo=None)
                    diff = datetime.datetime.now() - dt
                    diff = ("%s Days %s Hours %s Mins" % (
                        diff.days, diff.seconds // 3600,
                        (diff.seconds // 60) % 60))
                    groupname=[]
                    if len(rolebinding_groupname_untrusted)!=0:
                        if role in rolebinding_groupname_untrusted[project]:
                            groupname = rolebinding_groupname_untrusted[project][role]
                    if type(groupname)==list:
                        groupname = ''.join(groupname)
                    if project in project_app:

                        if rolebinding_untrusted[project][role]['usernames'] is not None:
                            for user in range(len(set(
                                    rolebinding_untrusted[project][role][
                                        'usernames']))):
                                data.append(
                                    [path_url, project, project_name_id_mapping[project],
                                     project_app[project]['app_id'],
                                     project_app[project]['app_name'], role,
                                     rolebinding_untrusted[project][role][
                                         'usernames'][user], groupname, diff])
                        else:
                            data.append(
                                [path_url, project, project_name_id_mapping[project],
                                 project_app[project]['app_id'],
                                 project_app[project]['app_name'], role, "None",
                                 groupname, diff])
                    else:
                        if rolebinding_untrusted[project][role]['usernames'] is not None:
                            for user in range(len(
                                    rolebinding_untrusted[project][role][
                                        'usernames'])):
                                data.append(
                                    [path_url,project, project_name_id_mapping[project],
                                     "None", "None", role,
                                     rolebinding_untrusted[project][role][
                                         'usernames'][user], groupname, diff])
                        else:
                            data.append(
                                        [
                                            path_url, project, project_name_id_mapping[project],
                                            "None", "None", role, "None", groupname, diff
                                        ]
                                       )
        df = pd.DataFrame(data,
                          columns=["URL", "Tenant Name" ,"Tenant ID", "Application ID",
                                   "Application Name", "Role Name",
                                   "Users with Associate Roles",
                                   "Group Names", "Role Provisioned Age"
                                   ]
                          )
        date = datetime.datetime.now().strftime('%m%d%y')
        error_file = os.path.expanduser("~") + "/logs/cae_identity_mgmt_tc_1_fail_cases_" + date + ".csv" 
        if os.path.isfile(error_file):
            with open(error_file, 'a') as f:
                df.to_csv(f, header=False, index=False)
        else:
            df.to_csv(error_file, index=False)

    except Exception as e:
        print("ERROR: Fail to retrieve the user roles with error in untrused_data : %s" % str(e))


def complete_data(rolebinding_all, project_app, project_name_id_mapping,
                  trusted_roles ,session, team_id, scan_id,
                  path_url, scanid_valid, teamid_valid,rolebinding_groupName_all):
    """
     Method to append complete rolebinding data for the given project into a csv file
    :param rolebinding_all:
    :param project_app:
    :param project_name_id_mapping:
    :param trusted_roles:
    :param session:
    :param team_id:
    :param scan_id:
    :param path_url:
    :param scanid_valid:
    :param teamid_valid:
    :param rolebinding_groupName_all:
    :return:
    """
    try:

        data_all = []
        for project in rolebinding_all:
            if rolebinding_all[project] is not None:
                for role in rolebinding_all[project]:
                    dt = dateutil.parser.parse(
                        rolebinding_all[project][role]['timecreated'])
                    dt = dt.replace(tzinfo=None)
                    diff = datetime.datetime.now() - dt
                    diff = ("%s Days %s Hours %s Mins" % (
                        diff.days, diff.seconds // 3600,
                        (diff.seconds // 60) % 60))
                    groupname = rolebinding_groupName_all[project][role]
                    if type(groupname)==list:
                        groupname = ''.join(groupname)
                    if project in project_app:

                        if rolebinding_all[project][role]['usernames'] is not None:
                            for user in set(rolebinding_all[project][role]['usernames']):
                                if role in trusted_roles:
                                    compliance_status = "Compliant"
                                else:
                                    compliance_status = "Non-compliant"
                                if "admin" == role and user != "citeis-orchadm.gen":
                                    compliance_status = "Non-compliant"

                                data_all.append(
                                    [path_url, project, project_name_id_mapping[project],
                                     project_app[project]['app_id'],
                                     project_app[project]['app_name'], role,
                                     user, groupname, diff, compliance_status])
                                role_user = role + "-" + user

                                if scanid_valid and teamid_valid:
                                    if general_util.params_list_update(scan_id, tc, team_id, role_user, compliance_status, params_list):
                                        print("INFO: Updating params_list")
                                    else:
                                        print("ERROR: Issue observed while updating params_list")
                                        return None
                                else:
                                    print("INFO: ScanId or TeamId passed to main() method is not valid,"
                                          " hence ignoring Kinesis part")

                        else:
                            if role in trusted_roles:
                                compliance_status = "Compliant"
                            else:
                                compliance_status = "Non-compliant"
                            if "admin" == role:
                                compliance_status = "Non-compliant"
                            data_all.append(
                                [path_url, project, project_name_id_mapping[project],
                                 project_app[project]['app_id'],
                                 project_app[project]['app_name'], role, "None",
                                 groupname, diff, compliance_status])
                    else:
                        if role in trusted_roles:
                            compliance_status = "Compliant"
                        else:
                            compliance_status = "Non-compliant"
                        if "admin" == role and user != "citeis-orchadm.gen":
                            compliance_status = "Non-compliant"
                        if rolebinding_all[project][role]['usernames'] is not None:
                            for user in rolebinding_all[project][role]['usernames']:
                                data_all.append([path_url,project, "None", "None", role, user, groupname, diff, compliance_status])
                        else:
                            data_all.append([path_url,project, "None", "None", role, "None", groupname, diff, compliance_status])
        df = pd.DataFrame(data_all,
                          columns=["URL", "Tenant Name","Tenant ID", "Application ID",
                                   "Application Name", "Role Name",
                                   "Users with Associate Roles",
                                   "Group Names", "Role Provisioned Age", "Compliant Status"
                                   ]
                          )
        date = datetime.datetime.now().strftime('%m%d%y')
        metadata_file = os.path.expanduser("~") + "/logs/cae_identity_mgmt_tc_1_" + date + ".csv"

        if os.path.isfile(metadata_file):
            with open(metadata_file, 'a') as f:
                df.to_csv(f, header=False, index=False)
        else:
            df.to_csv(metadata_file, index=False)

        if scanid_valid and teamid_valid:
            print("INFO: Adding result to Stream")
            stream_info = general_util.add_result_to_stream(session, "CAE", str(team_id), tc, params_list)
            if stream_info is None:
                raise Exception("ERROR: Issue observed while calling add_result_to_stream() API")
                return None
            seq_nums_list.append(stream_info)

            print("INFO: Sending result complete")
            send_result = general_util.send_result_complete(session, "CAE", scan_id, team_id, tc, seq_nums_list)
            if send_result:
                print("INFO: Successfully submitted the result to Kinesis")
            else:
                print("ERROR: Failed to submit the result to Kinesis")
                return None
        else:
            print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

    except Exception as e:
        print("ERROR: Fail to retrieve the user roles with error in complete_data : %s" % str(e))

def output_parameters(trusted_roles, admin_untrusted,rolebinding_all={}, all_roles=[],
                      rolebinding_untrusted={}, users_with_untrusted_roles=[],rolebinding_groupname_untrusted={}):
    """
    :Method to print all required summary of the execution on the screen
    :param trusted_roles:
    :param rolebinding_all:
    :param all_roles:
    :param rolebinding_untrusted:
    :param users_with_untrusted_roles:
    """
    summary_report = {  "No_of_Tenant(s)_evaluated": 0,
                        "No_of_Unique_Role(s)": 0,
                        "No_of_Untrusted_Role(s)": 0,
                        "No_of_Tenants_with_untrusted_role(s)": 0,
                        "No_of_Users_with_untrusted_roles": 0,
                        "No_of_Users_tagged_to_admin_role": 0,
                        "No_of_Groups_with_untrusted_role(s)": 0
                     }
    try:
        print("Total Number of Tenant(s) Evaluated in Platform : %s" % (len(rolebinding_all.keys())))
        untrusted_roles = set(all_roles) - set(trusted_roles)
        print("Total Number of Unique Role(s) found Platform : %s" % len(set(all_roles)))
        if admin_untrusted == 0:
            admin_untrusted_role = 0
        else:
            admin_untrusted_role =1
        print("Total Number of Untrusted Role(s) Found : %s" % (len(untrusted_roles) + admin_untrusted_role)) 
        projects_with_untrusted_roles = [
                                         i for i in rolebinding_untrusted.keys()
                                         if rolebinding_untrusted[i] is not None
                                        ]
        print("Untrusted role(s) belongs to these many tenant(s): %s" % len(projects_with_untrusted_roles))
        print("Unsecured role(s) belongs to these many user(s) : %s" % (len(set(users_with_untrusted_roles))))
        print("Unsecured role(s) belongs to these many Group(s) : %s" % len(rolebinding_groupname_untrusted))
        summary_report = { "No_of_Tenant(s)_evaluated": len(rolebinding_all.keys()), "No_of_Unique_Role(s)":len(set(all_roles)),
                            "No_of_Untrusted_Role(s)":(len(untrusted_roles) + admin_untrusted_role),
                            "No_of_Tenants_with_untrusted_role(s)":len(projects_with_untrusted_roles),
                            "No_of_Users_with_untrusted_roles":(len(set(users_with_untrusted_roles))),
                            "No_of_Users_tagged_to_admin_role":admin_untrusted,
                            "No_of_Groups_with_untrusted_role(s)":len(rolebinding_groupname_untrusted)
                        }
    except Exception as e:
        print("ERROR: Failed to retrieve the user roles with error in output: %s" % str(e))
    return summary_report

def write_metadata_connection_error(path_url,project_name, project_id):
    """
     Method to send least available data into the csv file in case of connection error
    :param path_url:
    :param project_name:
    :param project_id:
    :return:
    """
    data = [path_url, project_name, project_id,
                                     None,
                                     None, None,
                                     None, None, None,None]
    df = pd.DataFrame(data,
                          columns=["URL", "Tenant Name","Tenant ID", "Application ID",
                                   "Application Name", "Role Name",
                                   "Users with Associate Roles",
                                   "Role Provisioned Age", "Compliant Status","Group Names"
                                   ])
    date = datetime.datetime.now().strftime('%m%d%y')
    metadata_file = os.path.expanduser("~") + "/logs/cae_identity_mgmt_tc_1_" + date + ".csv" 
    if os.path.isfile(metadata_file):
        with open(metadata_file, 'a') as f:
            df.to_csv(f, header=False, index=False)
    else:
        df.to_csv(metadata_file, index=False)


def main(path_url, p_name, scan_id, team_id):
    """
    :Constructor with project name and url as parameter, scan ID, team ID
    :param path_url: holds the url of project
    :param p_name: holds the name of project
    :param scan_id: holds the ID of the current scan
    :param team_id: holds the project/tenant ID
    """
    summary_report = {
			            "No_of_Tenant(s)_evaluated": 0,
			            "No_of_Unique_Role(s)": 0,
			            "No_of_Untrusted_Role(s)": 0,
			            "No_of_Tenants_with_untrusted_role(s)": 0,
			            "No_of_Users_with_untrusted_roles": 0,
			            "No_of_Users_tagged_to_admin_role": 0,
                        "No_of_Groups_with_untrusted_role(s)": 0
                     }
    try:
        scanid_valid = False
        teamid_valid = False
        project_name = p_name
        filename = os.environ["CLONED_REPO_DIR"] + "/audit_scripts/cae_user_roles"
        if os.path.isfile(filename):
            if scan_id and team_id is not None:
                scanid_valid = common_lib.scanid_validation(scan_id)
                teamid_valid = cae_lib.cae_teamid_validation(team_id)
            else:
                print("INFO: Valid ScanId or TeamId not found")
                return None, summary_report
            session = general_util.session_handle()
            if session:
                if scanid_valid and teamid_valid:
                    print("INFO: Update the scan record with \"InProgress\" Status")
                    update = general_util.updateScanRecord(session, "CAE", scan_id, team_id, tc, "InProgress")
                    if update is None:
                        raise Exception("ERROR: Issue observed with UpdateScanRecord API call for \"InProgress\" status")
                        return None, summary_report
                else:
                    print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")
                try:
                    dyn_client = create_connection(path_url)
                    if dyn_client:
                        try:
                            trusted_roles = read_trusted_roles(filename)
                            projects, project_list, project_name_id_mapping = fetch_project_list(
                                dyn_client, project_name)
                            if projects and project_list:
                                rolebinding_all, all_roles, rolebinding_untrusted, users_with_untrusted_roles, flag, admin_untrusted, rolebinding_groupname_untrusted = get_rolebindings(
                                    dyn_client, projects, trusted_roles, project_name,
                                    project_name_id_mapping, project_list, scan_id, team_id,
                                    session, path_url, scanid_valid, teamid_valid)
                            else:
                                update = general_util.updateScanRecord(session, "CAE", scan_id, team_id, tc, "Failed")
                                if update is None:
                                    raise Exception("ERROR: Issue observed with updateScanRecord API call")
                                    return None, summary_report
                                raise Exception(
                                    "ERROR: Failed to fetch either Project: %s or Project_list: %s" % (project_name, project_list))
                        except Exception as e:
                                write_metadata_connection_error(path_url, p_name, team_id)
                                print("ERROR: Fail to retrieve the projects with error in main : %s" % str(e))
                                return None, summary_report
                        summary_report=output_parameters(
                                          trusted_roles, admin_untrusted,rolebinding_all, all_roles,
                                          rolebinding_untrusted, users_with_untrusted_roles,rolebinding_groupname_untrusted
                                         )
                    else:
                        write_metadata_connection_error(path_url, p_name, team_id)
                        raise Exception(
                            "ERROR: Failed to establish connection to CAE Project %s" % project_name)
                except Exception as e:
                    print("ERROR: Fail to retrieve the user roles with error in main : %s" % str(e))
                    return None, summary_report

            else:
                raise Exception("ERROR: Failed to get the connection handle")
                return None, summary_report

        else:
            raise Exception("ERROR: The dependency file %s is not available for use" % filename)
            return None, summary_report

        if flag == 1:
            return "Compliant", summary_report
        else:
            return "Non-compliant", summary_report
    except Exception as e:
        print("ERROR: Fail to retrieve the user roles with error in complete_data : %s" % str(e))
        if scanid_valid and teamid_valid:
            print("INFO: Update the scan record with \"Failed\" Status")
            update = general_util.updateScanRecord(session, "CAE", scan_id, team_id, tc, "Failed")
            if update is None:
                raise Exception("ERROR: Issue observed while calling updateScanRecord API")
                return None, summary_report
        else:
            print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")
        return None, summary_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    description="Validate the Roles associated with users listed in OpenShift Project...")
    parser.add_argument("-u", "--auth_url", help="OpenShift Domain URL", required=True, action="store", dest="url")
    parser.add_argument("-t", "--team_name", help="Project/Tenant Name", action="store", dest="team")
    parser.add_argument("-s", "--scan_id", help="Scan Id from AWS", action="store", dest="scanid")
    parser.add_argument("-i", "--team_id", help="Project/Tenant ID", action="store", dest="teamid")

    args = parser.parse_args()
    url = args.url
    p_name = args.team
    scan_id = args.scanid
    team_id = args.teamid
    url_valid = cae_lib.cae_url_validation(url)
    if p_name is not None:
        if url_valid:
            compliance_status, summary_report = main(url, p_name, scan_id, team_id)
            print("INFO: Process complete with compliance status as ", compliance_status)
        else:
            print("ERROR: Failed with validation")
    else:
        print("ERROR:Need Tenant ID and domain url to run the script")
