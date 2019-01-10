#!/usr/bin/python

"""
  -------------------cae_identity_mgmt_tc_1.py------------------
   Description: This python script is to find out if any user have a role
                that outside the set of the roles defined for the normal user.

   Author: Sanjeev Garg <sangarg@cisco.com>; December 21st, 2018

  Copyright (c) 2018 Cisco Systems.
  All rights reserved.
  ---------------------------------------------------------------------------
"""

import requests.packages.urllib3
import pandas as pd
from kubernetes import client, config
from openshift.dynamic import DynamicClient
import argparse
import logging as LOG
from prettytable import PrettyTable
import dateutil.parser
import datetime
import os

from os import environ as env

requests.packages.urllib3.disable_warnings()
LOG.getLogger().setLevel(LOG.INFO)


def create_connection(url):
    """ #:Method to create connection with client """
    try:
        #if env["DEBUG_VALUE"] == 1:
         #   print("load_config(path): Pulling Config from %s filei => %s" % url)


        if url is not None:
            url_split = url.strip().split('.')
            string = str(url_split[0])
            string_split = string.strip().split('-')
            region_name = str(string_split[2].strip())
            path = '/home/centos/amar/working_kube_config_010719'
            #path = '/home/centos/.kube/config'
            #if region_name is not None:
            #    if region_name == "rtp":
            #        path = '/home/centos/sanjeev/sanjeev_conf/config_rtp'
            #    elif region_name == "rcdn":
            #        path = '/home/centos/sanjeev/sanjeev_conf/conf_rcdn'
            #    elif region_name == 'alln':
            #        path = '/home/centos/sanjeev/sanjeev_conf/config_alln'
            #    else:
            #        print("No region found")
            #        exit()
        k8s_client = config.new_client_from_config(path)
        dyn_client = DynamicClient(k8s_client)
    except Exception as e:
        print("Error: Fail to retrieve the user roles with error in connection: %s" %str(e))
    return dyn_client


def read_trusted_roles(filename):
    """ #:Method to read roles from text file """
    try:
        with open(filename) as f:
            content = f.readlines()
        trusted_roles = [x.strip() for x in content]
    except IOError as e:
        print('Error: An error occurred trying to read the file.: %s'%str(e))
    except Exception as e:
        print("Error: Fail to retrieve the user roles with error in trusted roles: %s" %str(e))
    return trusted_roles

def fetch_project_list(dyn_client, project_name):
    """ #:Method to fetch the project list """
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
                data = []
                data.append(["null", project_name, "null", "null", "null", "null", "null"])
                df = pd.DataFrame(data,columns=["Tenant ID", "Tenant Name", "Application ID", "Application Name", "Role Name", "Users with Associate Roles", "Role Provisioned Age"])
                df.to_csv('output.csv')
                exit()
    except Exception as e:
        print("Error: Fail to retrieve the user roles with error: %s" %str(e))
    return projects, project_list, project_name_id_mapping

def get_app_project_mapping(projects):
    """ #:Method to get application project mapping """
    try:
        app_list = projects
        app_project_mapping = {}
        for i in app_list.items:
            app_project_mapping[i.metadata.name] = { 'app_id' : i.metadata.annotations['citeis.cisco.com/application-id'], 'app_name' : i.metadata.annotations['citeis.cisco.com/application-name'] }
    except Exception as e:
        print("Error: Fail to retrieve the user roles with error in project_mapping : %s" %str(e))
    return app_project_mapping


def get_rolebindings(dyn_client, projects, trusted_roles, project_name, project_name_id_mapping, project_list=[]):
    """ #:Method to get rolebindings """
    try:
        flag = 0
        data = []
        format = '%Y-%m-%dT%H:%M'
        roles = dyn_client.resources.get(api_version='authorization.openshift.io/v1', kind='RoleBinding')
        rolebinding_all = {}
        rolebinding_untrusted = {}
        all_roles = []
        users_with_untrusted_roles = []
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
            rolebinding_all[project]= proj_role_bind
            rolebinding_untrusted[project]= proj_role_bind_untrusted.copy() if bool(proj_role_bind_untrusted) else None
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
                    dt = dateutil.parser.parse(rolebinding_all[project][role]['timecreated'])
                    dt = dt.replace(tzinfo=None)
                    diff = datetime.datetime.now() - dt
                    diff = ("%s Days %s Hours %s Mins" % (diff.days, diff.seconds//3600, (diff.seconds//60)%60))
                    if project in project_app:
                            if rolebinding_all[project][role]['usernames'] is not None:
                                for user in range(len(rolebinding_all[project][role]['usernames'])):
                                    data_all.append([project_name_id_mapping[project], project, project_app[project]['app_id'], project_app[project]['app_name'], role, rolebinding_all[project][role]['usernames'][user], diff])
                            else:
                                data_all.append([project_name_id_mapping[project], project, project_app[project]['app_id'], project_app[project]['app_name'], role, "None", diff])
                    else:
                        if rolebinding_all[project][role]['usernames'] is not None:
                            for user in range(len(rolebinding_all[project][role]['usernames'])):
                                data_all.append([project_name_id_mapping[project], project, "None", "None", role, rolebinding_all[project][role]['usernames'][user], diff])
                        else:
                            data_all.append([project_name_id_mapping[project], project, "None", "None", role, "None", diff])
        df = pd.DataFrame(data_all,columns=["Tenant ID", "Tenant Name", "Application ID", "Application Name", "Role Name", "Users with Associate Roles", "Role Provisioned Age"])
        df.to_csv('metadata.csv',index=False)
    except Exception as e:
        print("Error: Fail to retrieve the user roles with error in rolebindings : %s" %str(e))
    return rolebinding_all, all_roles, rolebinding_untrusted, users_with_untrusted_roles, flag

def output_parameters(trusted_roles, rolebinding_all={}, all_roles=[], rolebinding_untrusted={}, users_with_untrusted_roles=[]):
    """ #:Method to print all required paramenters """
    try:
        print("Total Number of Tenants Evaluated in Platform : %s" % (len(rolebinding_all.keys())))
        untrusted_roles = set(all_roles) - set(trusted_roles)
        print("Total Number of Unique Roles found evaluated in Platform : %s" % len(set(all_roles)))
        print("Total Number of Untrusted Role Found found : %s" % len(untrusted_roles))
        #print(" untrusted: %s" % rolebinding_untrusted)
        projects_with_untrusted_roles = [i for i in rolebinding_untrusted.keys() if rolebinding_untrusted[i] is not None]
        print("Untrusted roles belongs to these many tenants: %s" % len(projects_with_untrusted_roles))
        print("Unsecured role belongs to these many users : %s" % len(set(users_with_untrusted_roles)))
    except Exception as e:
        print("Error: Fail to retrieve the user roles with error in output: %s" %str(e))

def main(p_name, path_url):
    """ #:Method to execute function in pipeline """
    """ #:Constructor with project name and url as parameter
    #:param project_name: holds the name of project
    #:param url: holds the url of project """

    project_name = p_name
    filename = 'cae_user_roles'
    url = path_url
    try:
        dyn_client = create_connection(url)
        trusted_roles = read_trusted_roles(filename)
        projects, project_list, project_name_id_mapping = fetch_project_list(dyn_client, project_name)
        rolebinding_all, all_roles, rolebinding_untrusted, users_with_untrusted_roles, flag = get_rolebindings(dyn_client, projects, trusted_roles, project_name, project_name_id_mapping, project_list)
        output_parameters(trusted_roles, rolebinding_all, all_roles, rolebinding_untrusted, users_with_untrusted_roles)
    except Exception as e:
        print("Error: Fail to retrieve the user roles with error in main : %s" %str(e))
    if flag == 1:
        return "Compliant"
    else:
        return "Non-Compliant"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the images listed in OpenShift Project...")
    parser.add_argument("-u", "--auth_url", help="OpenShift Domain URL",required=True,action="store", dest="url")
    parser.add_argument("-t", "--team_id", help="Project/Tenant ID", action="store", dest="team")

    args = parser.parse_args()

    url = args.url
    p_name = args.team

    compliant_status = main(p_name, url)
    print(compliant_status)
    #    automate.execute()
