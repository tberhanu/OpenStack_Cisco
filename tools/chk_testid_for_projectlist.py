#!opt/app-root/bin/python

"""
#!/usr/bin/python
--------------------------p3_projectlist.py-------------------------
Description:
            This script is used to run a Test Script based on script id on all the projects in P3 and CAE that are listed in respective project list files.
            Complete git repo will be downloaded when we run the script.
Dependency: 
            data_p3.xml
            date_cae.xml
            P3 project list files:
                rtpProjList
                rcdnProjList
                allnProjList
            CAE project list files:
                caertpProjList
                caercdnProjList
                caeallnProjList
            env_variables.py
            csb_credentials.py.enc
            config_rtp.enc
            config_rcdn.enc
            config_alln.enc
            

Author: Ravi Gujja

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------
"""

import pykube
import re
import argparse
import os
import csv
import git
import shutil
import datetime
import sys
import time
import struct
import importlib
import requests.packages.urllib3
import xml.etree.ElementTree as ET
from os import environ as env
from os import path
from Crypto.Cipher import AES
from importlib import import_module
from env_variables import env_variables


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
        print("Decrypt %s file" % in_filename)
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
    key = "1329ebbc1b9646b890202384beaef2ec"
    """ Decrypt credentials file. Then set environment variables w.r.t. required set of credentials  """
    if decrypt_file(key, "csb_credentials.py.enc"):
        print("LOG: Successfully decrypted Credential file")
        cred_file = import_module("csb_credentials")
        for var, val in cred_file.csb_credentials.items():
            os.environ[var] = val
    else:
        raise Exception("ERROR: Failed to decrypt \"csb_credentials.py.enc\" file")
    """ Decrypts the config fils for CAE repion """
    if decrypt_file(key, "config_rtp.enc"):
        print("Successfully decrypted RTP Config file")
    else:
        raise Exception("ERROR: Failed to decrypt \"config_rtp.enc\" file")

    if decrypt_file(key, "config_rcdn.enc"):
        print("Successfully decrypted Kube Config file")
    else:
        raise Exception("ERROR: Failed to decrypt \"config_rcdn.enc\" file")

    if decrypt_file(key, "config_alln.enc"):
        print("Successfully decrypted Kube Config file")
    else:
        raise Exception("ERROR: Failed to decrypt \"config_alln.enc\" file")



def clone_git_repo():
    """
    this function is used to clone the git repo of csb-cnt
    :param : None
    :return: None
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


def main(test_id):
    """
    This method will run the audit test script on all the projects in P3 and CAE w.r.t the test id 
    :param test_id: audit test ID
    return: none
    """
    test_script_name = str(test_id)
    test_script = test_script_name.replace("-", "_").lower()
    test_script_type = test_script.split("_")[0]
    script_file = os.environ["AUDIT_SCRIPTS_DIR"] + "/" + test_script + ".py"
    if test_script_type == "p3":
        try:
            print("LOG: Test Script belongs to P3 platform. Reading data.xml file of P3 region")
            tree = ET.parse('data_p3.xml')
            root = tree.getroot()
            print("LOG: Iterating the data file for getting regionURL and RegionName in P3 region ")
            for regions in root.iter('region'):
                region_name = regions.find('regionname').text
                region_url = regions.find('regionurl').text
                regionfile_name = region_name.lower()+"ProjList"

                if os.path.isfile(script_file):
                    sys.path.append(os.environ["AUDIT_SCRIPTS_DIR"])
                    tscript = importlib.import_module(test_script)
                    try:
                        print("\n \n \t-.-.-.--.- ITERATING THROUGH REGION -.-.-.-.-.-.-.-")
                        print("LOG: Initiating '%s' test on each project in P3 region: %s " % (test_script,region_name))
                        n_secure,n_unsecure,n_unknown = test_guardrail(region_url,regionfile_name,tscript,region_name,test_id)
                        print("\n OVERALL SUMMARY FOR THE REGION")
                        print("INFO: NO of SECURE tenant for test Script %s in %s are %s"%(test_id,region_name,n_secure))
                        print("INFO: NO of UN-SECURE tenant for test Script %s in %s are %s"%(test_id,region_name,n_unsecure))
                        print("INFO: NO of UNKNOWN tenant for test Script %s in %s are %s"%(test_id,region_name,n_unknown))
                    except Exception as e:
                        print("ERROR: cannot perform test on test_id")
                else:
                    print("Test Script %s doesnot Exist" % test_id)
        except Exception as e:
            print(e)
    elif test_script_type == "cae":
        #print("dont have cae yet")

        try:
            print("LOG: Test Script belongs to CAE platform. Reading caedata.xml file of P3 region")
            tree = ET.parse('data_cae.xml')
            root = tree.getroot()
            print("LOG: Iterating the data file for getting regionURL and RegionName in P3 region ")
            for regions in root.iter('region'):
                region_name = regions.find('regionname').text
                region_url = regions.find('regionurl').text
                regionfile_name = region_name.lower()+"ProjList"
               
                if os.path.isfile(script_file):
                    sys.path.append(os.environ["AUDIT_SCRIPTS_DIR"])
                    tscript = importlib.import_module(test_script)
                    try:
                        print("\n \n \t-.-.-.--.- ITERATING THROUGH REGION -.-.-.-.-.-.-.-")
                        print("LOG: Initiating '%s' test on each project in P3 region: %s " % (test_script,region_name))
                        n_secure,n_unsecure,n_unknown = test_guardrail(region_url,regionfile_name,tscript,region_name,test_id)
                        print("\n OVERALL SUMMARY FOR THE REGION")
                        print("INFO: NO of SECURE tenant for test Script %s in %s are %s"%(test_id,region_name,n_secure))
                        print("INFO: NO of UN-SECURE tenant for test Script %s in %s are %s"%(test_id,region_name,n_unsecure))
                        print("INFO: NO of UNKNOWN tenant for test Script %s in %s are %s"%(test_id,region_name,n_unknown))
                    except Exception as e:
                        print("ERROR: cannot perform test on test_id")
                else:
                    print("Test Script %s doesnot Exist" % test_id)
        except Exception as e:
            print(e)
    else:
        print("wrong test id :%s" % test_id)

def test_guardrail(region_url,regionfile_name,tscript,region_name,test_id):
    """
    This function executes the main method of the script based on the test id
    :param region_ulr: url to pass to audit script
    :param regionfile_name: file containing the list of projects
    :param tscript: import module of test script
    :param region_name: region name
    :param test_id: test id
    :return : count of secured and unsecured tenants for region
    """
    print("LOG: Running Test Script on region %s" % region_name )
    count_secure = 0
    count_unsecure = 0
    count_unknown = 0
    if path.exists(regionfile_name):
        projects = open(regionfile_name,"r")
        lines = projects.readlines()
        if len(lines) != 0:
            try:
                for proj_details in lines:
                    project=proj_details.strip().split(" ")
                    project_name=project[1]
                    project_id = project[0]
                    try:
                        scan_id = "samplescanid"
                        x = tscript.main(region_url,project_name,scan_id,project_id)
                        if x == "Compliant":
                            count_secure = count_secure + 1
                        else:
                            count_unsecure = count_unsecure + 1
                    except Exception as e:
                        print("ERROR: Test Case %s didnot run properly on project: %s" % (test_id,project_name))
                        count_unknown = count_unknown + 1
            except Exception as e:
                print("ERROR:" + e )
        else:
            print("INFO: The project list file %s for this region %s does not contain any projects" % (regionfile_name,region_name)) 
    else:
        print("ERROR: image harden test failed, no project file avilable for %s" % region_name)
    return count_secure,count_unsecure,count_unknown




if __name__== "__main__":

    parser = argparse.ArgumentParser(description="gets the test id and runs the test on all projects")
    parser.add_argument("-t", "--test_id", help="Test id ", action="store", dest="test_id")
    args = parser.parse_args()
    test_id = args.test_id
    """ loading variables from encrypted credentials file, decrypting config and credentials file"""
    load_enc_variable()
    """ Setting environment variables required for execution of CBS-CNT related scripts """
    for var, val in env_variables.items():
        os.environ[var] = val
    """ clone CSB git repo"""
    clone_git_repo()
    my_env = os.environ.copy()
    
    main(test_id)

#    print("LOG: removing csb credentials file")
#   os.remove("csb_credentials.py")

