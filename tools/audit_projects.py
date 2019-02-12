#!opt/app-root/bin/python

"""
--------------------------- audit_projects.py ---------------------------
Description: This script is used to run a Test Script based on script id
            on all the projects in P3 and CAE regions.
            Complete git repo will be downloaded when we run the script.
            If tenants file contain any data, then the script will run on
            the details that are provided in tenants file, if not it will
            fetch the complete projects list from the platform.
Execution: 
            Manual: python audit_projects.py -t <testcase-ID>(ex: P3-IDENTITY-MGMT-TC-1)
            for log: python audit_projects.py -t <testcase-ID> | tee <logFile_name> 
Dependency:
            data_p3.xml
            date_cae.xml
            env_variables.py
            csb_credentials.py.enc
            kube_config_rtp.enc
            kube_config_rcdn.enc
            kube_config_alln.enc
            OpenStack Client
            tenants
            audit_tc_list

Author: Ravi Gujja

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------
"""


import argparse
import csv
import datetime
import git
import importlib
import os
import pykube
import requests.packages.urllib3
import time
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET

from Crypto.Cipher import AES
from env_variables import env_variables
from audit_tc_list import audit_tc_list
from os import environ as env
from importlib import import_module
from os import path

from random import choice, shuffle
from string import digits, ascii_lowercase



requests.packages.urllib3.disable_warnings()

def gen_word(N, min_N_digits, min_N_lower):
    """
    Genetares a randum value based on the inputs
    :param N : n number to create random value
    :param min_N_digits: no of digits in random value
    :param min_N_lower: no of letters in random value
    :return: randum value

    """
    choose_from = [digits]*min_N_digits + [ascii_lowercase]*min_N_lower
    choose_from.extend([digits + ascii_lowercase] * (N-min_N_lower-min_N_digits))
    chars = [choice(bet) for bet in choose_from]
    shuffle(chars)
    return ''.join(chars)


def decrypt_file(key, in_filename):
    """
    Decrypts a file using AES(CBC mode) with the given key.
    :param key: key to be used for decryption
    :param in_filename: name of encrypted file
    :return: decrypted file
    """
    out_filename = os.path.splitext(in_filename)[0]
    chunk_size = 64*1024
    try:
        print("LOG: Decrypt %s file" % in_filename)
        with open(in_filename, 'rb') as infile:
            orig_size = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, iv)
            try:
                with open(out_filename, 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunk_size)
                        if len(chunk) == 0:
                            break
                        outfile.write(decryptor.decrypt(chunk))

                    outfile.truncate(orig_size)
            except IOError:
                print("ERROR: Failed to create the decrypted file %s" % out_filename)
    except IOError:
        print("ERROR: File %s was not accessible" % in_filename)

    if os.path.isfile(out_filename):
        return True
    else:
        return False


def load_enc_variable():
    """
    This method is used to load credential variables into environment variables
    :param: none
    :return: none
    """
    """ Decrypt credentials file. Then set environment variables w.r.t. required set of credentials  """
    key = "1329ebbc1b9646b890202384beaef2ec"
    if decrypt_file(key, "csb_credentials.py.enc"):
        print("LOG: Successfully decrypted Credential file")
        cred_file = importlib.import_module("csb_credentials")
        for var, val in cred_file.csb_credentials.items():
            os.environ[var] = val
    else:
        raise Exception("ERROR: Failed to decrypt \"csb_credentials.py.enc\" file")

    """ Decrypts the config fils for CAE region """
    if decrypt_file(key, "kube_config_rtp.enc"):
        print("Successfully decrypted RTP Config file")
    else:
        raise Exception("ERROR: Failed to decrypt \"kube_config_rtp.enc\" file")

    if decrypt_file(key, "kube_config_rcdn.enc"):
        print("Successfully decrypted Kube Config file")
    else:
        raise Exception("ERROR: Failed to decrypt \"kube_config_rcdn.enc\" file")

    if decrypt_file(key, "kube_config_alln.enc"):
        print("Successfully decrypted Kube Config file")
    else:
        raise Exception("ERROR: Failed to decrypt \"kube_config_alln.enc\" file")


def clone_git_repo():
    """
    This function is used to clone the git repo of csb-cnt
    :param : None
    :return: true or false
    """
    try:
        print("LOG: Clone GIT Repo")
        if os.path.isdir(os.environ["CLONED_REPO_DIR"]):
            shutil.rmtree(os.environ["CLONED_REPO_DIR"])
        tcp_protocol, git_url = os.environ["CSB_CNT_REPO"].split("//")
        git_repo_url = tcp_protocol + "//" + os.environ["GITHUB_TOKEN_CSBAUDITOR_GEN"] + "@" + git_url
        repo = git.Repo.clone_from(git_repo_url, os.environ["CLONED_REPO_DIR"])
        repo.git.checkout(os.environ["GIT_BRANCH_TO_USE"])
        return True
    except git.exc.GitCommandError as err_clone:
        print("ERROR: Git Clone failed; %s" % str(err_clone))
        return False


def get_projects(config_path):
    """
    This method is used to get the project list for CAE platform
    :param config_path : path to config file for cae regions
    :return: return the list of project details
    """
    try:
        api_handle = load_config(config_path)
        if api_handle:
            print("LOG: API loaded with current path %s"% config_path)

        try:
            print("LOG: Loading project metadata using API")
            project_met = pykube.Namespace.objects(api_handle).filter(namespace=pykube.all)
        except Exception as e:
            print("ERROR: Cannot load project metadata")

        plist = []
        if project_met :
            for project_list in project_met:
                try:
                    metadata_project = project_list.obj['metadata']
                    project_id = metadata_project.get('uid', None)
                    project_name = metadata_project.get('name', None)
                    project_status = project_list.obj['status']['phase']
                except Exception as e:
                    print("ERROR: cannot get metadata %s" % str(e))

                row = "%s %s %s" %(project_id, project_name, project_status)
                plist.append(row)
            return plist

        else:
            print("ERROR: Unable to connect to get Metadata of all the projects for config %s" % config_path)
            return None

    except Exception as e:
        print("ERROR: Failed to retrieve project list => %s" % str(e))
        return None


def load_config(config_path):
    """
    Method to create API Handle
    :param config_path:
    :return: API Handle
    """
    try:
        print("LOG: Loading config file from path %s " % config_path)
        api = pykube.HTTPClient(pykube.KubeConfig.from_file(config_path))
        return api
    except Exception as e:
        print("ERROR: Failed to retrieve pykube.KubeConfig.from_file path => %s" % config_path)
        return None


def main(test_id):
    """
    This method will run the audit test script on all the projects in P3 and CAE w.r.t the test id.
    This will also check if there are any details in tenants file, to execute testcase on multiple projects.
    This will also change the name of the csv file if it already exists.
    :param test_id: audit test ID
    return: none
    """
    test_script_name = str(test_id)
    test_script = test_script_name.replace("-", "_").lower()
    test_script_type = test_script.split("_")[0]
    script_file = os.environ["AUDIT_SCRIPTS_DIR"] + "/" + test_script + ".py"
    date_stamp = datetime.datetime.now().strftime('%m%d%y')
    summary_flag = False
    tc = test_script_name.upper()

    p_secured = 0
    p_unsecured = 0
    p_unknown = 0

    if test_script_type == "p3":
        if os.path.isfile(script_file):
            if test_script=="p3_identity_mgmt_tc_1":
                csv_file = os.environ["LOGS_DIR"] + "/p3_identity_mgmt_tc_1_" + date_stamp + ".csv"
                if os.path.isfile(csv_file):
                    new_csv_file = os.environ["LOGS_DIR"] + "/p3_identity_mgmt_tc_1_" + str(gen_word(8, 4, 4)) + ".csv"
                    os.rename(csv_file,new_csv_file)
            elif test_script=="p3_image_hardening_tc_1":
                all_image_csv = os.environ["LOGS_DIR"] + "/p3_all_images_list_" + date_stamp + ".csv"
                if os.path.isfile(all_image_csv):
                    new_all_image_csv = os.environ["LOGS_DIR"] + "/p3_all_images_list_" + str(gen_word(8, 4, 4)) + ".csv"
                    os.rename(all_image_csv,new_all_image_csv)

                all_unsecured_image_list_csv = os.environ["LOGS_DIR"] + "/p3_all_unsecured_images_list_" + date_stamp + ".csv"
                if os.path.isfile(all_unsecured_image_list_csv):
                    new_all_unsecured_image_list_csv = os.environ["LOGS_DIR"] + "/p3_all_unsecured_images_list_" + str(gen_word(8, 4, 4)) + ".csv"
                    os.rename(all_unsecured_image_list_csv,new_all_unsecured_image_list_csv)

                server_list_csv = os.environ["LOGS_DIR"] + "/p3_servers_list_" + date_stamp + ".csv"
                if os.path.isfile(server_list_csv):
                    new_server_list_csv = os.environ["LOGS_DIR"] + "/p3_servers_list_" + str(gen_word(8, 4, 4)) + ".csv"
                    os.rename(server_list_csv,new_server_list_csv)

                unsecured_server_list_csv = os.environ["LOGS_DIR"] + "/p3_unsecured_servers_list_" + date_stamp + ".csv"
                if os.path.isfile(unsecured_server_list_csv):
                    new_unsecured_server_list_csv = os.environ["LOGS_DIR"] + "/p3_unsecured_servers_list_" + str(gen_word(8, 4, 4)) + ".csv"
                    os.rename(unsecured_server_list_csv,new_unsecured_server_list_csv)

                unused_image_list_csv = os.environ["LOGS_DIR"] + "/p3_unused_image_list_" + date_stamp + ".csv"
                if os.path.isfile(unused_image_list_csv):
                    new_unused_image_list_csv = os.environ["LOGS_DIR"] + "/p3_unused_image_list_" + str(gen_word(8, 4, 4)) + ".csv"
                    os.rename(unused_image_list_csv,new_unused_image_list_csv)

                unused_unsecured_image_list_csv = os.environ["LOGS_DIR"] + "/p3_unused_unsecured_image_list_" + date_stamp + ".csv"
                if os.path.isfile(unused_unsecured_image_list_csv):
                    new_unused_unsecured_image_list_csv = os.environ["LOGS_DIR"] + "/p3_unused_unsecured_image_list_" + str(gen_word(8, 4, 4)) + ".csv"
                    os.rename(unused_unsecured_image_list_csv,new_unused_unsecured_image_list_csv)

        try:
            tenants_file = "tenants"
            project_count = 0
            finalsummary = {}
            rtp_summary = {}
            rcdn_summary = {}
            alln_summary ={}
            if path.exists(tenants_file) and path.getsize(tenants_file) > 0:
                if os.path.isfile(script_file):
                    sys.path.append(os.environ["AUDIT_SCRIPTS_DIR"])
                    tscript = importlib.import_module(test_script)
                    try:
                        start_time = time.time()
                        f = open(tenants_file,"r")
                        tenantslist = f.readlines()
                        if tenantslist:
                            for tenants in tenantslist:
                                region_url = " "
                                tenant=tenants.strip().split(",")
                                project_name = tenant[0]
                                region_name = tenant[1]
                                tree = ET.parse('data_p3.xml')
                                root = tree.getroot()
                                for regions in root.iter('region'):
                                    name = regions.find('regionname').text
                                    if name == region_name:
                                        region_url = regions.find('regionurl').text

                                if region_url != " " :
                                    summary = {}
                                    print("\n %s " % tenants)
                                    print("LOG: Initiating '%s' test on project %s in P3 region: %s "
                                                                % (test_script, project_name, region_url))
                                    n_secure, n_unsecure, n_unknown, summary = test_guardrail_for_multi_tenant(region_url, project_name, tscript, test_id)
                                    p_secured = p_secured + n_secure
                                    p_unsecured = p_unsecured + n_unsecure
                                    p_unknown = p_unknown + n_unknown
                                    for var,val in summary.items():
                                            if var in finalsummary:
                                                finalsummary[var]= finalsummary[var] + val
                                            else:
                                                finalsummary[var] = val
                                    project_count = project_count + 1
                                else:
                                    print("ERROR: NO URL Found for given REGION NAME %s" % region_name)
                            print("INFO: OVERALL SUMMARY FOR THIS EXECUTION")
                            print("INFO: No. of SECURE tenant for test Script %s are %s"
                                                                        % (test_id, p_secured))
                            print("INFO: No. of UN-SECURE tenant for test Script %s are %s"
                                                                        % (test_id, p_unsecured))
                            print("INFO: No. of UNKNOWN tenant for test Script %s are %s"
                                                                        % (test_id, p_unknown))
                        else:
                            print("ERROR: No tenant list found")
                        end_time = round(time.time() - start_time)
                        print("INFO: TIME of executing TEST id %s on given tenants is : %s seconds"
                                                            % (test_id, end_time))
                    except Exception as e:
                        print("ERROR: Cannot perform test on test_id due to - %s" % str(e))

                else:
                    print("INFO: Test Script %s DOES NOT exist" % test_id)
            else:
                print("LOG: Test Script belongs to P3 platform. Reading data.xml file of P3 region")

                tree = ET.parse('data_p3.xml')
                root = tree.getroot()
                print("LOG: Iterating the data file for getting regionURL and RegionName in P3 region ")
                for regions in root.iter('region'):
                    region_name = regions.find('regionname').text
                    region_url = regions.find('regionurl').text
                    p_secured = 0
                    p_unsecured = 0
                    p_unknown = 0

                    if os.path.isfile(script_file):

                        sys.path.append(os.environ["AUDIT_SCRIPTS_DIR"])
                        tscript = importlib.import_module(test_script)
                        try:
                            start_time = time.time()
                            print("\n \n \t-.-.-.--.- ITERATING THROUGH REGION -.-.-.-.-.-.-.-")
                            print("LOG: Getting Project list for region %s" % region_name)
                            my_env["OS_AUTH_URL"] = region_url
                            plist_cmd = 'openstack project list -c ID -c Name -f csv --long'
                            try:
                                plist_process = subprocess.Popen(
                                                                    plist_cmd, shell=True,
                                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                                    env=my_env
                                                                )
                                plist_process.wait()
                                print("project list assigned to plist")
                                project_list = plist_process.stdout
                                print("terminating plist sub process")

                            except Exception as e:
                                print("ERROR: Unable to generate project list for region %s" % region_name)
                                print(e)
                            if project_list:
                                index = '"ID","Name"'
                                for projectline in project_list:
                                    if projectline.strip() == index:
                                        pass
                                    else:
                                        summary = {}
                                        print("\n %s " % projectline)
                                        project_details = projectline.strip().split(",")
                                        project_id = project_details[0][1:-1]
                                        project_name = project_details[1][1:-1]
                                        print("LOG: Initiating '%s' test on project %s in P3 region: %s "
                                                                % (test_script, project_name, region_name))
                                        n_secure, n_unsecure, n_unknown,summary = test_guardrail(
                                                                                            region_url, project_id,
                                                                                            project_name, tscript,
                                                                                            region_name, test_id
                                                                                        )
                                        p_secured = p_secured + n_secure
                                        p_unsecured = p_unsecured + n_unsecure
                                        p_unknown = p_unknown + n_unknown
                                        for var,val in summary.items():
                                            if var in finalsummary:
                                                finalsummary[var]= finalsummary[var] + val
                                            else:
                                                finalsummary[var] = val
                                        project_count = project_count + 1
                                        if region_name == "RTP":
                                            for var,val in summary.items():
                                                if var in rtp_summary:
                                                    rtp_summary[var]= rtp_summary[var] + val
                                                else:
                                                    rtp_summary[var] = val
                                        elif region_name == "RCDN":
                                            for var,val in summary.items():
                                                if var in rcdn_summary:
                                                    rcdn_summary[var]= rcdn_summary[var] + val
                                                else:
                                                    rcdn_summary[var] = val
                                        elif region_name == "ALLN":
                                            for var,val in summary.items():
                                                if var in alln_summary:
                                                    alln_summary[var]= alln_summary[var] + val
                                                else:
                                                    alln_summary[var] = val

                                print("INFO: OVERALL SUMMARY FOR THE REGION : %s " % region_name)
                                print("INFO: No. of SECURE tenant for test Script %s in %s are %s"
                                                                            % (test_id, region_name, p_secured))
                                print("INFO: No. of UN-SECURE tenant for test Script %s in %s are %s"
                                                                            % (test_id, region_name, p_unsecured))
                                print("INFO: No. of UNKNOWN tenant for test Script %s in %s are %s"
                                                                            % (test_id, region_name, p_unknown))
                                if region_name == "RTP":
                                    for var,val in rtp_summary.items():
                                        print(str(var) + " : " + str(val) + "\n")
                                elif region_name == "RCDN":
                                    for var,val in rcdn_summary.items():
                                        print(str(var) + " : " + str(val) + "\n")
                                if region_name == "ALLN":
                                    for var,val in alln_summary.items():
                                        print(str(var) + " : " + str(val) + "\n")
                            else:
                                print("INFO: Project list did not generate for region %s " % region_name)
                            end_time = round(time.time() - start_time)
                            print("INFO: TIME of executing TEST id %s on region %s is : %s seconds"
                                                                % (test_id, region_name, end_time))


                        except Exception as e:
                            print("ERROR: Cannot perform test on test_id due to - %s" % str(e))

                    else:
                        print("INFO: Test Script %s DOES NOT exist" % test_id)
            print("\n -.-.-.-.--.. TOTAL NUMBER OF TENANTS: %s  .-.-.--.-." % project_count)
            for var,val in finalsummary.items():
                print(str(var) + " : " + str(val) + "\n")
        except Exception as e:
            print("ERROR: Exception caught - %s" % str(e))

    elif test_script_type == "cae":
        if os.path.isfile(script_file):
            if test_script=="cae_identity_mgmt_tc_1":
                identity_mgmt_csv = os.environ["LOGS_DIR"] + "/cae_identity_mgmt_tc_1_" + date_stamp + ".csv"
                if os.path.isfile(identity_mgmt_csv):
                    new_identity_mgmt_csv = os.environ["LOGS_DIR"] + "/cae_identity_mgmt_tc_1_" + str(gen_word(8, 4, 4)) + ".csv"
                    os.rename(identity_mgmt_csv,new_identity_mgmt_csv)

                identity_mgmt_fail_case_csv = os.environ["LOGS_DIR"] + "/cae_identity_mgmt_tc_1_fail_cases_" + date_stamp + ".csv"
                if os.path.isfile(identity_mgmt_fail_case_csv):
                    new_identity_mgmt_fail_case_csv = os.environ["LOGS_DIR"] + "/cae_identity_mgmt_tc_1_fail_cases_" + str(gen_word(8, 4, 4)) + ".csv"
                    os.rename(identity_mgmt_fail_case_csv,new_identity_mgmt_fail_case_csv)
            elif test_script =="cae_image_hardening_tc_1":
                image_hardening_csv = os.environ["LOGS_DIR"] + "/cae_image_hardening_tc_1_" + date_stamp + ".csv"
                if os.path.isfile(image_hardening_csv):
                    new_image_hardening_csv = os.environ["LOGS_DIR"] + "/cae_image_hardening_tc_1_" + str(gen_word(8, 4, 4)) + ".csv"
                    os.rename(image_hardening_csv,new_image_hardening_csv)

        try:
            tenants_file = "tenants"
            project_count = 0
            finalsummary = {}
            rtp_summary = {}
            rcdn_summary = {}
            alln_summary ={}
            if path.exists(tenants_file) and path.getsize(tenants_file) > 0:
                if os.path.isfile(script_file):
                    sys.path.append(os.environ["AUDIT_SCRIPTS_DIR"])
                    tscript = importlib.import_module(test_script)
                    try:
                        start_time = time.time()
                        f = open(tenants_file,"r")
                        tenantslist = f.readlines()
                        if tenantslist:
                            for tenants in tenantslist:
                                region_url = " "
                                tenant=tenants.strip().split(",")
                                project_name = tenant[0]
                                region_name = tenant[1]
                                tree = ET.parse('data_cae.xml')
                                root = tree.getroot()
                                for regions in root.iter('region'):
                                    name = regions.find('regionname').text
                                    if name == region_name:
                                        region_url = regions.find('regionurl').text
                                if region_url != " " :
                                    summary = {}
                                    print("\n %s " % tenants)
                                    print("LOG: Initiating '%s' test on project %s in CAE region: %s "
                                                                % (test_script, project_name, region_url))
                                    n_secure, n_unsecure, n_unknown,summary = test_guardrail_for_multi_tenant(region_url, project_name, tscript, test_id)
                                    p_secured = p_secured + n_secure
                                    p_unsecured = p_unsecured + n_unsecure
                                    p_unknown = p_unknown + n_unknown

                                    for var,val in summary.items():
                                            if var in finalsummary:
                                                finalsummary[var]= finalsummary[var] + val
                                            else:
                                                finalsummary[var] = val
                                    project_count = project_count + 1
                                else:
                                    print("ERROR: NO URL Found with given REGION NAME %s" % region_name)
                            print("INFO: OVERALL SUMMARY FOR THIS EXECUTION")
                            print("INFO: No. of SECURE tenant for test Script %s are %s"
                                                                        % (test_id, p_secured))
                            print("INFO: No. of UN-SECURE tenant for test Script %s are %s"
                                                                        % (test_id, p_unsecured))
                            print("INFO: No. of UNKNOWN tenant for test Script %s are %s"
                                                                        % (test_id, p_unknown))
                            #summary_flag = True

                        else:
                            print("ERROR: No tenant list found")
                        end_time = round(time.time() - start_time)
                        print("INFO: TIME of executing TEST id %s on given tenants is : %s seconds"
                                                            % (test_id, end_time))
                    except Exception as e:
                        print("ERROR: Cannot perform test on test_id due to - %s" % str(e))

                else:
                    print("INFO: Test Script %s DOES NOT exist" % test_id)
            else:
                print("LOG: Test Script belongs to CAE platform. Reading data.xml file of CAE region")
                tree = ET.parse('data_cae.xml')
                root = tree.getroot()
                print("LOG: Iterating the data file for getting regionURL and RegionName in CAE region ")
                for regions in root.iter('region'):
                    region_name = regions.find('regionname').text
                    region_url = regions.find('regionurl').text
                    config_path = regions.find('configpath').text
                    p_secured = 0
                    p_unsecured = 0
                    p_unknown = 0

                    if os.path.isfile(script_file):
                        sys.path.append(os.environ["AUDIT_SCRIPTS_DIR"])
                        tscript = importlib.import_module(test_script)
                        try:
                            start_time = time.time()
                            print("\n \n \t-.-.-.--.- ITERATING THROUGH REGION -.-.-.-.-.-.-.-")
                            print("LOG: Getting Project list for region %s" % region_name)
                            project_list = get_projects(config_path)
                            if project_list:
                                for projectline in project_list:
                                    summary = {}
                                    print("\n %s " % projectline)
                                    project_details = projectline.strip().split(" ")
                                    project_id = project_details[0]
                                    project_name = project_details[1]
                                    print("LOG: Initiating '%s' test on project %s in CAE region: %s"
                                                            % (test_script, project_name, region_name))
                                    n_secure, n_unsecure, n_unknown, summary = test_guardrail(
                                                                                        region_url, project_id,
                                                                                        project_name, tscript,
                                                                                        region_name, test_id
                                                                                    )
                                    p_secured = p_secured + n_secure
                                    p_unsecured = p_unsecured + n_unsecure
                                    p_unknown = p_unknown + n_unknown
                                    for var,val in summary.items():
                                            if var in finalsummary:
                                                finalsummary[var]= finalsummary[var] + val
                                            else:
                                                finalsummary[var] = val
                                    project_count = project_count + 1
                                    if region_name == "CAERTP":
                                        for var,val in summary.items():
                                            if var in rtp_summary:
                                                rtp_summary[var]= rtp_summary[var] + val
                                            else:
                                                rtp_summary[var] = val
                                    elif region_name == "CAERCDN":
                                        for var,val in summary.items():
                                            if var in rcdn_summary:
                                                rcdn_summary[var]= rcdn_summary[var] + val
                                            else:
                                                rcdn_summary[var] = val
                                    elif region_name == "CAEALLN":
                                        for var,val in summary.items():
                                            if var in alln_summary:
                                                alln_summary[var]= alln_summary[var] + val
                                            else:
                                                alln_summary[var] = val

                                print("\n OVERALL SUMMARY FOR THE REGION : %s " % region_name)
                                print("INFO: NO of SECURE tenant for test Script %s in %s are %s"
                                                                %(test_id, region_name, p_secured))
                                print("INFO: NO of UN-SECURE tenant for test Script %s in %s are %s"
                                                                %(test_id, region_name, p_unsecured))
                                print("INFO: NO of UNKNOWN tenant for test Script %s in %s are %s"
                                                                %(test_id, region_name, p_unknown))
                                if region_name == "CAERTP":
                                    for var,val in rtp_summary.items():
                                        print(str(var) + " : " + str(val) + "\n")
                                elif region_name == "CAERCDN":
                                    for var,val in rcdn_summary.items():
                                        print(str(var) + " : " + str(val) + "\n")
                                if region_name == "CAEALLN":
                                    for var,val in alln_summary.items():
                                        print(str(var) + " : " + str(val) + "\n")
                            else:
                                print("INFO: Project list didnot generate for region %s " % region_name)

                            end_time = round(time.time() - start_time)
                            print("INFO: TIME of executing TEST id %s on region %s is : %s seconds"
                                                                % (test_id, region_name, end_time))

                        except Exception as e:
                            print("ERROR: cannot perform test on test_id")
                    else:
                        print("INFO: Test Script %s DOES NOT exist" % test_id)
            print("-.-.-.-.--.. TOTAL NUMBER OF TENANTS: %s  .-.-.--.-." % project_count)
            for var,val in finalsummary.items():
                print(str(var) + " : " + str(val) + "\n")
        except Exception as e:
            print("ERROR: Exception caught - %s" % str(e))

    else:
        print("INFO: Wrong TestId :%s" % test_id)


def test_guardrail(region_url, project_id, project_name, tscript, region_name, test_id):
    """
    This function executes the main method of the audit script based on the test id
    :param region_ulr: url to pass to audit script
    :param project_id: project/tenant id
    :param project_name: name of the project/tenant
    :param tscript: import module of test script
    :param region_name: region name
    :param test_id: test id
    :return : count of secured and unsecured tenants for region,and also summary of the testcase for given project
    """
    print("LOG: Running Test Script on region %s" % region_name)
    count_secure = 0
    count_unsecure = 0
    count_unknown = 0
    try:
        scan_id = "samplescanid"
        summary = {}
        x,summary = tscript.main(region_url, project_name, scan_id, project_id)
        if x == "Compliant":
            count_secure = count_secure + 1
            print("********INFO: THIS PROJECT IS SECURE*******")
        elif x== "Non-compliant":
            print("********INFO: THIS PROJECT IS UN-SECURE*******")
            count_unsecure = count_unsecure + 1
        else:
            print("********INFO: THIS PROJECT IS UN-KNOWN*******")
            count_unknown = count_unknown + 1
    except Exception as e:
        print("*********INFO: EXCEPTION- UNKNOWN********")
        print("ERROR: Test Case %s did not run properly on project: %s due to %s" % (test_id, project_name, str(e)))
        count_unknown = count_unknown + 1

    return count_secure, count_unsecure, count_unknown , summary

def test_guardrail_for_multi_tenant(region_url,project_name,tscript,test_id):
    """
    This function executes the main method of the audit script based on the test id.
    This is used in case the testcase had to be executed based on tenants file
    :param region_ulr: url to pass to audit script
    :param project_name: name of the project/tenant
    :param tscript: import module of test script
    :param test_id: test id
    :return : count of secured and unsecured tenants for region and also summary of the testcase for given project
    """
    count_secure = 0
    count_unsecure = 0
    count_unknown = 0
    try:
        scan_id = "samplescanid"
        summary = {}
        project_id = str(gen_word(8, 4, 4))
        x,summary = tscript.main(region_url, project_name, scan_id, project_id)
        if x == "Compliant":
            count_secure = count_secure + 1
            print("********INFO: THIS PROJECT IS SECURE*******")
        elif x == "Non-compliant":
            print("********INFO: THIS PROJECT IS UN-SECURE*******")
            count_unsecure = count_unsecure + 1
        else:
            print("********INFO: THIS PROJECT IS UN-KNOWN*******")
            count_unknown = count_unknown + 1
    except Exception as e:
        print("*********INFO: EXCEPTION- UNKNOWN********")
        print("ERROR: Test Case %s did not run properly on project: %s due to %s" % (test_id, project_name, str(e)))
        count_unknown = count_unknown + 1

    return count_secure, count_unsecure, count_unknown, summary



if __name__== "__main__":
    parser = argparse.ArgumentParser(description="Get the test id and execute the respective audit tests on all projects")
    parser.add_argument("-t", "--test_id", help="Test id", action="store", dest="test_id")
    args = parser.parse_args()
    test_id = args.test_id

    if args.test_id in audit_tc_list["P3"]:
        platform = "P3"
    elif args.test_id in audit_tc_list["CAE"]:
        platform = "CAE"
    else:
        print("ERROR: Test ID entered is incorrect, please choose one from below list. CASE SENSITIVE : \n %s" % audit_tc_list)
        sys.exit()

    """ loading variables from encrypted credentials file, decrypting config and credentials file"""
    load_enc_variable()

    """ Setting environment variables required for execution of CBS-CNT related scripts """
    for var, val in env_variables.items():
        os.environ[var] = val

    """ clone CSB git repo"""
    
    repo_chk = clone_git_repo()
    if repo_chk:
        my_env = os.environ.copy()
        main(test_id)
    else:
        print("ERROR: Failed to download GIT REPO.")
        print("INFO: TERMINATING THE PROCESS")
    """
    #for manual execution
    my_env = os.environ.copy()
    main(test_id)
    """
    """ Delete the decrypted files """
    print("INFO: Delete decrypted Credential file")
    try:
        cred_file = os.path.expanduser("~") + "/" + "csb_credentials.py"
        if os.path.isfile(cred_file):
            os.remove(os.path.expanduser("~") + "/" + "csb_credentials.py")
            os.remove(os.path.expanduser("~") + "/" + "csb_credentials.pyc")
        else:
            print("INFO: No Credentials file Found")
    except OSError as e:
        print("ERROR: Unable to remove csb_credentials file")
        print(str(e))

