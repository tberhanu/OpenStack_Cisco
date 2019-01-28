#!/opt/app-root/bin/python
"""
-------------------------- generate_audit_reports.py---------------------------
Description: This python script is to summarize the results from the csv files
             generated as a result of executions done using audit test-scripts
             meant for projects in the P3 and the CAE Platform.

Author: Devaraj Acharya <devaacha@cisco.com>; January 25th, 2018

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------------
"""
import argparse
import csv
import datetime
import os
import pandas as pd
import re


def cae_image_hardening_tc_1(date_stamp):
    """
    This method is to summarize the result from .csv generated upon execution of
    CAE-IMAGE-HARDENING-TC-1 test over projects in CAE Platform
    :date_stamp: args.date
    """
    try:
        cae_unsecured_images = []
        print("\n######### SCAN REPORT FOR cae_image_hardening_tc_1 executed on: %s #########" % date_stamp)
        current_date_stamp = datetime.datetime.now().strftime('%m%d%y')
        csv_filename = os.path.expanduser("~") + "/logs/cae_image_hardening_tc_1_" + date_stamp + ".csv"
        with open(csv_filename, 'r') as f:
            csv_reader = csv.reader(f, delimiter=',')
            metadata = list(csv_reader)
            csv_list = pd.read_csv(csv_filename)
            
            if csv_list is not None:
                print("Total number of Tenants evaluated in CAE platform: %s" % len(csv_list['Tenant Name'].unique()))
                print("Total number of PODs evaluated in CAE platform: %s" % len(csv_list['Pod Name'].unique()))
                print("Total number of Images Evaluated in CAE platform: %s" % len(csv_list['Image ID'].unique()))
                
                """ Total no of unsecured images in the CAE platform """
                for untrusted_images in metadata:
                    if untrusted_images[12] == 'Non-compliant':
                        cae_unsecured_images.append(untrusted_images)
            else:
                print("The %s file is empty" % csv_filename)
        f.close()
        
        if cae_unsecured_images is not None:
            header = ["Tenant Name", "Tenant ID", "Application ID", "Application Name", "Pod Name", "Pod Namespace",
                      "Pod Namespace", "Container ID", "Image Name", "Image ID", "Container Start Date",
                      "Container Exposed Port", "Compliance_Status"]
            
            cae_unsecured_images_filename = (os.path.expanduser("~")
                            + "/logs/cae_unsecured_images_list_" + date_stamp + "_" + current_date_stamp + ".csv")
            with open(cae_unsecured_images_filename, 'w') as f:         
                writer = csv.writer(f, lineterminator='\n')
                writer.writerow(header)
                writer.writerows(cae_unsecured_images)
            f.close()
            
            cae_unsecured_images_file = pd.read_csv(cae_unsecured_images_filename)
            print("Total number of Unsecured Images found: %s" 
                  % len(cae_unsecured_images_file['Image ID'].unique()))
            print("Total number of PODS with the unsecured image(s) in CAE platform: %s"
                  % len(cae_unsecured_images_file['Pod Name'].unique()))
            print("Total number of Tenants with the unsecured image(s) in CAE platform: %s"
                  % len(cae_unsecured_images_file['Tenant Name'].unique()))
            print("INFO: Non-compliant records of unsecured images in CAE platform are available in:\n %s"
                  % cae_unsecured_images_filename)
        else:
            print("There are no unsecured images")

    except IOError as e:
        print("ERROR: Failed to retrieve %s file with error => %s" % (csv_filename, str(e)))
        return None


def cae_identity_mgmt_tc_1(date_stamp):
    """
    This method is to summarize the result from .csv generated upon execution of
    CAE-IDENTITY-MGMT-TC-1 test over projects in CAE Platform
    :date_stamp: args.date
    """
    try:
        print("\n######### SCAN REPORT FOR cae_identity_mgmt_tc_1 executed on: %s #########" % date_stamp)
        current_date_stamp = datetime.datetime.now().strftime('%m%d%y')
        cae_identity_mgmt_filename = os.path.expanduser("~") + "/logs/cae_identity_mgmt_tc_1_" + date_stamp + ".csv"
        with open(cae_identity_mgmt_filename, 'r') as file_cae_identity:
            csv_reader = csv.reader(file_cae_identity, delimiter=',')
            cae_identity_mgmt_metadata = list(csv_reader)
            cae_identity_mgmt_file = pd.read_csv(cae_identity_mgmt_filename)    
        
            print("Total number of Tenants Evaluated in Platform: %s"
                  % len(cae_identity_mgmt_file['Tenant ID'].unique()))
            print("Total number of Unique Roles found in Platform: %s"
                  % len(cae_identity_mgmt_file['Role Name'].unique()))
            
            list_untrusted_roles = []
            for untrusted_role in cae_identity_mgmt_metadata:
                if untrusted_role[8] == 'Non-compliant':
                    list_untrusted_roles.append(untrusted_role)
            
            if list_untrusted_roles is not None:
                header = ["URL", "Tenant Name", "Tenant ID", "Application ID", "Application Name", "Role Name", 
                          "Users with Associate Roles", "Role Provisioned Age", "Compliant Status"]
                cae_untrusted_role_filename = (os.path.expanduser("~")
                        + "/logs/cae_identity_untrusted_role_list_" + date_stamp + "_" + current_date_stamp + ".csv")
                
                with open(cae_untrusted_role_filename, 'w') as untrusted_role_file:
                    writer = csv.writer(untrusted_role_file, lineterminator='\n')
                    writer.writerow(header)
                    writer.writerows(list_untrusted_roles)
                untrusted_role_file.close()
                
                untrusted_role_file = pd.read_csv(cae_untrusted_role_filename)
                print("Total number of Untrusted Role found: %s" 
                      % len(untrusted_role_file['Role Name'].unique()))
                print("Total number of Tenants with Untrusted Role(s): %s"
                      % len(untrusted_role_file['Tenant ID'].unique()))
                print("Total number of Users with Untrusted Role(s): %s"
                      % len(untrusted_role_file['Users with Associate Roles'].unique()))
                print("INFO: Non-Compliant record for Untrusted Role(s) are available in:\n %s"
                      % cae_untrusted_role_filename)
            else:
                print("There are no any untrusted roles")
        file_cae_identity.close()
        
    except IOError as e:
        print("ERROR: Failed to retrieve %s file with error => %s" % (cae_identity_mgmt_filename, str(e)))
        return None


def p3_image_hardening_tc_1(date_stamp):
    """
    This method is to summarize the result from .csv generated upon execution of
    P3-IMAGE-HARDENING-TC-1 test over projects in P3 Platform
    :date_stamp: args.date
    """
    try:
        print("\n######### SCAN REPORT FOR p3_image_hardening_tc_1 executed on: %s #########" % date_stamp)
        current_date_stamp = datetime.datetime.now().strftime('%m%d%y')
        images_filename = os.path.expanduser("~") + "/logs/p3_all_images_list_" + date_stamp + ".csv"
        images = pd.read_csv(images_filename)
        print("Total number of Images evaluated in Platform : %s" % len(images['Image Id'].unique()))
        print("Total number of Tenants Evaluated in Platform: %s" % len(images['Tenant Name'].unique()))

        servers_filename = os.path.expanduser("~") + "/logs/p3_servers_list_" + date_stamp + ".csv"
        servers = pd.read_csv(servers_filename)
        print("Total number of VMs identified in Platform: %s" % len(servers['VM Id'].unique()))
        
        unsecured_images_filename = (os.path.expanduser("~")
            + "/logs/p3_all_unsecured_images_list_" + date_stamp + ".csv")
        unsecured_images = pd.read_csv(unsecured_images_filename)
        print("Total number of Unsecured Images evaluated in Platform : %s"
              % len(unsecured_images['Image Id'].unique()))
        print("Total number of tenant with unsecured images in Platform: %s"
              % len(unsecured_images['Tenant Name'].unique()))

        unsecured_servers_filename = (os.path.expanduser("~")
                + "/logs/p3_unsecured_servers_list_" + date_stamp + ".csv")
        unsecured_servers = pd.read_csv(unsecured_servers_filename)
        print("Total number of Instances with unsecured images: %s" % len(unsecured_servers['VM Id'].unique()))

        unused_unsecured_images_filename = (os.path.expanduser("~")
                    + "/logs/p3_unused_unsecured_image_list_" + date_stamp + ".csv")
        unused_unsecured_images = pd.read_csv(unused_unsecured_images_filename)
        print("Total number of unused unsecured images in Platform: %s"
              % len(unused_unsecured_images['Image Id'].unique()))
        print("INFO: Non-Compliant record for unsecured servers is available in:\n %s" % unsecured_servers_filename)
        print("INFO: Non-Compliant record for unused images is available in:\n %s" % unused_unsecured_images_filename)
        print("INFO: Non-Compliant record for all images is available in:\n %s" % unsecured_images_filename)

    except IOError as e:
        print("ERROR: Failed to retrieve %s file with error => %s" % (images_filename, str(e)))
        return None


def p3_identity_mgmt_tc_1(date_stamp):
    """
    This method is to summarize the result from .csv generated upon execution of
    P3-IDENTITY-MGMT-TC-1 test over projects in P3 Platform
    :date_stamp: args.date
    """
    try:
        print("\n######### SCAN REPORT FOR p3_identity_mgmt_tc_1 executed on: %s #########" % date_stamp)
        current_date_stamp = datetime.datetime.now().strftime('%m%d%y')
        p3_identity_mgmt_filename = os.path.expanduser("~") + "/logs/p3_identity_mgmt_tc_1_" + date_stamp + ".csv"
        
        with open(p3_identity_mgmt_filename, 'r') as file_p3_identity:
            csv_reader = csv.reader(file_p3_identity, delimiter=',')
            p3_identity_mgmt_metadata = list(csv_reader)
            p3_identity_mgmt_file = pd.read_csv(p3_identity_mgmt_filename)
            print("Total number of Tenants Evaluated in Platform: %s"
                  % len(p3_identity_mgmt_file['Tenant Name'].unique()))

            allowed_to_create_role = []
            for create_role in p3_identity_mgmt_metadata:
                if create_role[2] == 'Allowed':
                    allowed_to_create_role.append([create_role])
            print("Total number of Tenants that allow role creation: %s" % len(allowed_to_create_role))

            allowed_to_create_user = []
            for create_user in p3_identity_mgmt_metadata:
                if create_user[3] == 'Allowed':
                    allowed_to_create_user.append([create_user])
            print("Total number of Tenants that allow user creation: %s" % len(allowed_to_create_user))

            allowed_domain_creation = []
            for create_domain in p3_identity_mgmt_metadata:
                if create_domain[4] == 'Allowed':
                    allowed_domain_creation.append([create_domain])
            print("Total number of tenant that allow to create domain: %s" % len(allowed_domain_creation))

            allowed_to_change_domain = []
            for change_domain in p3_identity_mgmt_metadata:
                if change_domain[6] == 'Allowed':
                    allowed_to_change_domain.append([change_domain])
            print("Total number of Tenants that allow change domain: %s" % len(allowed_to_change_domain))

        file_p3_identity.close()
    except IOError as e:
        print("ERROR: Failed to retrieve %s file with error => %s" % (p3_identity_mgmt_filename, str(e)))

        return None


def valid_datestamp(datestring):
    """
    Method to validate the expected format of date_stamp
    :param datestring: datestamp
    :return: True|False
    """
    try:
        datetime.datetime.strptime(datestring, '%m%d%y')
        return True
    except ValueError:
        return False


def main(test_cases, date_stamp):
    """
    This main method is to summarize all the test case executed in the P3 and the CAE Platform
    :test_cases: args.test_case
    :date_stamp: args.date
    """

    """ Validate the received input values """
    tc_pattern = re.compile(r'^(P3|CAE)[-A-Z0-9]*(, (P3|CAE)[-A-Z0-9]*)*')
    if tc_pattern.match(test_cases) and valid_datestamp(date_stamp):
        print("LOG: Received valid TestID and DateStamp")
    else:
        raise Exception("ERROR: Either Received TestID or DateStamp(mmddyy) is not valid")

    audit_tc_list = test_cases.split(",")
    for tc in audit_tc_list:
        if tc == "CAE-IDENTITY-MGMT-TC-1":
            cae_identity_mgmt_tc_1(date_stamp)
        elif tc == "CAE-IMAGE-HARDENING-TC-1":
            cae_image_hardening_tc_1(date_stamp)
        elif tc == "P3-IDENTITY-MGMT-TC-1":
            p3_identity_mgmt_tc_1(date_stamp)
        elif tc == "P3-IMAGE-HARDENING-TC-1":
            p3_image_hardening_tc_1(date_stamp)
        else:
            print("ERROR: There is no valid TC")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analysis of overall audits executed on P3/CAE platform")
    parser.add_argument("-tc", "--audit_case_name", help="Audit test cases for which respective .csv "
                                                         "file requires summary", action="store", dest="test_case")
    parser.add_argument("-d", "--audit_date", help="Audit date", action="store", dest="date")
    args = parser.parse_args()
    test_cases = args.test_case
    date_stamp = args.date
    main(test_cases, date_stamp)
