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

requests.packages.urllib3.disable_warnings()
LOG.getLogger().setLevel(LOG.INFO)

class Automate:
        def __init__(self,project_name,url):
            """ #:Constructor with project name and url as parameter
            #:param project_name: holds the name of project
            #:param url: holds the url of project """

            self.project_name = project_name
            self.filename = 'cae_roles.txt'
            self.url=url

        def create_connection(self):
            """ #:Method to create connection with client """
            try:
                self.k8s_client = config.new_client_from_config()
                self.dyn_client = DynamicClient(self.k8s_client)
            except Exception as e:
                print("Error: Fail to retrieve the user roles with error: %s" %str(e))


        def read_trusted_roles(self):
            """ #:Method to read roles from text file """
            try:
                with open(self.filename) as f:
                    content = f.readlines()
                self.trusted_roles = [x.strip() for x in content]
            except IOError as e:
                print('Error: An error occurred trying to read the file.: %s'%str(e))
            except Exception as e:
                print("Error: Fail to retrieve the user roles with error: %s" %str(e))

        def fetch_project_list(self):
            """ #:Method to fetch the project list """
            try:
                self.project_name_id_mapping = {}
                self.project_list = []
                v1_projects = self.dyn_client.resources.get(api_version='project.openshift.io/v1', kind='Project')
                self.projects = v1_projects.get()

                for project in self.projects.items:
                    self.project_list.append(project.metadata.name)
                    self.project_name_id_mapping[project.metadata.name] = project.metadata.uid
                if self.project_name is not None:
                    if self.project_name in self.project_list:
                        self.project_list = [self.project_name]
                    else:
                        print("project %s is not present" % self.project_name)
                        exit()
            except Exception as e:
                print("Error: Fail to retrieve the user roles with error: %s" %str(e))

        def get_app_project_mapping(self):
            """ #:Method to get application project mapping """
            try:
                app_list = self.projects
                self.app_project_mapping = {}
                for i in app_list.items:
                    self.app_project_mapping[i.metadata.name] = { 'app_id' : i.metadata.annotations['citeis.cisco.com/application-id'], 'app_name' : i.metadata.annotations['citeis.cisco.com/application-name'] }
                return self.app_project_mapping
            except Exception as e:
                print("Error: Fail to retrieve the user roles with error: %s" %str(e))


        def get_rolebindings(self):
            """ #:Method to get rolebindings """
            try:
                data = []
                format = '%Y-%m-%dT%H:%M'
                roles = self.dyn_client.resources.get(api_version='authorization.openshift.io/v1', kind='RoleBinding')
                self.rolebinding_all = {}
                self.rolebinding_untrusted = {}
                self.all_roles = []
                self.users_with_untrusted_roles = []
                for project in self.project_list:
                    rolebinding_project = roles.get(namespace=project)
                    rolebinding_dict = rolebinding_project.to_dict()
                    proj_role_bind = {}
                    proj_role_bind_untrusted = {}
                    for i in rolebinding_dict['items']:
                        self.all_roles.append(i['roleRef']['name'])
                        proj_role_bind[i['roleRef']['name']] = {'usernames': i['userNames'], 'timecreated' : i['metadata']['creationTimestamp']}
                        if i['roleRef']['name'] not in self.trusted_roles:
                            proj_role_bind_untrusted[i['roleRef']['name']] = {'usernames': i['userNames'], 'timecreated' : i['metadata']['creationTimestamp']}
                            self.users_with_untrusted_roles.append(i['userNames'])
                    self.rolebinding_all[project]= proj_role_bind
                    self.rolebinding_untrusted[project]= proj_role_bind_untrusted.copy() if bool(proj_role_bind_untrusted) else None
                self.users_with_untrusted_roles = [item for sublist in self.users_with_untrusted_roles if sublist for item in sublist]
                project_app = self.get_app_project_mapping()
                if not self.rolebinding_untrusted:
                    print('Pass')
                    return
                for project in self.rolebinding_untrusted:
                    if self.rolebinding_untrusted[project] is not None:
                        for role in self.rolebinding_untrusted[project]:
                            dt = dateutil.parser.parse(self.rolebinding_untrusted[project][role]['timecreated'])
                            dt = dt.replace(tzinfo=None)
                            diff = datetime.datetime.now() - dt
                            diff = ("%s Days %s Hours %s Mins" % (diff.days, diff.seconds//3600, (diff.seconds//60)%60))
                            if project in project_app:
                                    if self.rolebinding_untrusted[project][role]['usernames'] is not None:
                                        for user in range(len(self.rolebinding_untrusted[project][role]['usernames'])):
                                            data.append([self.project_name_id_mapping[project], project, project_app[project]['app_id'], project_app[project]['app_name'], role, self.rolebinding_untrusted[project][role]['usernames'][user], diff])
                                    else:
                                        data.append([self.project_name_id_mapping[project], project, project_app[project]['app_id'], project_app[project]['app_name'], role, "None", diff])
                            else:
                                if self.rolebinding_untrusted[project][role]['usernames'] is not None:
                                    for user in range(len(self.rolebinding_untrusted[project][role]['usernames'])):
                                        data.append([self.project_name_id_mapping[project], project, "None", "None", role, self.rolebinding_untrusted[project][role]['usernames'][user], diff])
                                else:
                                    data.append([self.project_name_id_mapping[project], project, "None", "None", role, "None", diff])
                df = pd.DataFrame(data,columns=["Tenant ID", "Tenant Name", "Application ID", "Application Name", "Role Name", "Users with Associate Roles", "Role Provisioned Age"])
                df.to_csv('output.csv')
                print('Fail')
            except Exception as e:
                print("Error: Fail to retrieve the user roles with error: %s" %str(e))

        def output_parameters(self):
            """ #:Method to print all required paramenters """
            try:
                print("Total Number of Tenants Evaluated in Platform : %s" % (len(self.rolebinding_all.keys())))
                self.untrusted_roles = set(self.all_roles) - set(self.trusted_roles)
                print("Total Number of Unique Roles found evaluated in Platform : %s" % len(set(self.all_roles)))
                print("Total Number of Untrusted Role Found found : %s" % len(self.untrusted_roles))
                projects_with_untrusted_roles = [i for i in self.rolebinding_untrusted.keys() if self.rolebinding_untrusted[i] is not None]
                print("Untrusted roles belongs to these many tenants: %s" % len(projects_with_untrusted_roles))
                print("Unsecured role belongs to these many users : %s" % len(set(self.users_with_untrusted_roles)))
            except Exception as e:
                print("Error: Fail to retrieve the user roles with error: %s" %str(e))

        def execute(self):
            """ #:Method to execute function in pipeline """
            try:
                self.create_connection()
                self.read_trusted_roles()
                self.fetch_project_list()
                self.get_rolebindings()
                self.output_parameters()
            except Exception as e:
                print("Error: Fail to retrieve the user roles with error: %s" %str(e))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the images listed in OpenShift Project...")
    parser.add_argument("-u", "--auth_url", help="OpenShift Domain URL", action="store", dest="url")
    parser.add_argument("-t", "--team_id", help="Project/Tenant ID", action="store", dest="team")

    args = parser.parse_args()

    url = args.url
    p_name = args.team


    automate = Automate(project_name=p_name,url=url)
    automate.execute()
