#!/usr/bin/python

"""
--------------------------p3_projectlist.py-------------------------
Description: This script is to get the list of projects available in all p3 regions.
            As an output it will generate projectlist for each region  and a common delta file for all p3 regions
            The main function iterates through data.xml and generate projectList files for each region mentioned in data file
            This will run every 60 seconds, untill manually interepted by user (ctrl+c)
Dependency: data.xml
            env_variables.py
            csb_credentials.py.enc
            teams_db_update
            openstack client

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
from os import environ as env

import xml.etree.ElementTree as ET
import os
from os import path
import datetime
import subprocess
import sys
import time
import struct
import requests.packages.urllib3
from Crypto.Cipher import AES
from importlib import import_module
from env_variables import env_variables
from teams_db_update_util import *


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



def write_to_project_file(project_details,regionfile_name,region_name,deltafile):
    """
    This method is writes the project details to the respective project list file and also update delta file if any new
    are added to the file
    :param project_details: single project details in a line
    :param regionfile_name: path/name of the projectlist file
    :param region_name: region name
    :param deltafile: delta file path/name
    :return: none
    """

    if project_details in open(regionfile_name).read():
        print("LOG: Project details already exist in %s" % regionfile_name)
        pass
    else:
        try:
            print("LOG: Open %s file in append mode" % deltafile)
            f = open(deltafile, "a")
        except IOError:
            print("LOG: Open %s file in write mode" % deltafile)
            f = open(deltafile, "w")
        f.write(region_name+" "+project_details+" Added on "+str(datetime.datetime.now().date())+":"+str(datetime.datetime.now().time())+'\n')
        print("LOG: Writting to Delta file on addition of new project details to %s" % region_name)
        try:
            print("LOG: Open %s file in append mode" % regionfile_name)
            f = open(regionfile_name,"a")
            print("LOG: Writing new project details to %s " % regionfile_name)
            f.write(project_details+'\n')
        except IOError:
            print("ERROR: File %s is not accessible" % regionfile_name)

def create_temp_file(project_details,region_name):
    """
    This method is to create a temp file for all the projects based on region
    :param project_details: single project details
    :param region_name: region name
    :return: none
    """
    try:
        print("LOG: Creating %s temp file in append mode to store current project list" % region_name)
        f = open(region_name+"temp","a")
        f.write(project_details+'\n')
    except IOError:
        print("ERROR: Failed to create %s temp file" % region_name)
        """
        print("LOG: opening %s temp file in write mode" % region_name)
        f = open(region_name+"temp","w")
        f.write(project_details+'\n')
        """

def delete_existing_project_details(project_details,regionfile_name):
    """
    This method is to delete existing project details from the file
    :param project_details: single project details in a line
    :param regionfile_name: file name of project list
    :return: none
    """
    try:
        print("LOG: Opening %s file in read mode for comparision" % regionfile_name)
        f = open(regionfile_name,"r")
        lines=f.readlines()
        f.close()
    except IOError:
        print("ERROR: Opening %s is not accessible" % regionfile_name)
    try:
        print("LOG: Opening %s in write mode to write current projects" % regionfile_name)
        f = open(regionfile_name,"w")
    except IOError:
        print("ERROR: Opening %s isnot accessible for writing" % regionfile_name)
    else:
        for newline in lines:
            if newline.strip().split(" ")[1] != project_details.strip().split(" ")[1]:
                f.write(newline)
        f.truncate()
        f.close()

def update_project_files(project_details,temp_file,regionfile_name,region_name,deltafile):
    """
    This method is to update the delta file if any projects are deleted, and calls delete_exesting_project_detils() to delete that project
    particular regions project file
    :param line: single project details in a line
    :param temp_file: temperory file name/path
    :param regionfile_name: path/name to the projectlist file
    :param region_name: region name
    :param deltaFile: delta file path/name
    :return: none
    """
    if not (path.exists(temp_file)):
        try:
            print("LOG: Opening %s in write mode" % temp_file)
            f = open(temp_file,"w")
        except IOError:
            print("ERROR: %s is not accessible" % temp_file)
    if project_details in open(temp_file).read():
		pass
    else:
        try:
            print("LOG: Opening %s in append mode" % deltafile)
            f = open(deltafile, "a")
        except IOError:
            print("ERROR: Unable to access %s " % deltafile)
        project_details=project_details.replace('\n', '').replace('\r', '')
        f.write(region_name+" "+project_details+" Deleted on "+str(datetime.datetime.now().date())+":"+str(datetime.datetime.now().time())+'\n')
        print("LOG: Written deleted project details of %s region to delta file" % region_name)
        delete_existing_project_details(project_details,regionfile_name)


def get_projects(config_path):
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
                    print("ERROR: cannot get metadata %s" % e)
                row = "%s %s %s" %(project_id,project_name,project_status)
                plist.append(row)
            return plist
        else:
            print("ERROR: Unable to connect to get metadate of all the projects for config %s"%config_path)
            return None
            #print(row)
    except Exception as e:
        print("ERROR: Failed to retrieve project list => %s" % str(e))


def load_config(config_path):
    # Method to create API handle
    #:param path: holds the path to config file
    #:return: api
    try:
        #import pdb; pdb.set_trace()
        print("LOG: Loading config file from path %s " % config_path)
        api = pykube.HTTPClient(pykube.KubeConfig.from_file(config_path))
        return api
    except Exception as e:
        print("ERROR: Failed to retrieve pykube.KubeConfig.from_file path => %s" % config_path)



def main():
    """
    This is main method to execute the project list script, it iterates through the data.xml file and gets regionname and regionurl
    calls the respective methods to create, update, and delete projects from project files based on region
    param: none
    return: none
    """

    requests.packages.urllib3.disable_warnings()
    cae_deltafile = "CAE-deltafile"
    deltafile = "P3-deltafile"
    try:
        print("LOG: Reading data.xml file for CAE platform")
        tree = ET.parse('caedata.xml')
        root = tree.getroot()

        #iterating through dat afile to get all regions an dtheir URL
        print("LOG: Iterating the data file for getting regionURL,RegionName and config path ")
        for regions in root.iter('region'):
            region_name = regions.find('regionname').text
            region_url = regions.find('regionurl').text
            regionfile_name = region_name.lower()+"ProjList"
            config_path = regions.find('configpath').text
            try:
                plist = get_projects(config_path)
            except Exception as e:
                print(e)
            if plist is not None:
                if path.exists(regionfile_name):
                    print("LOG: Project list file exists for region %s" % region_name)
                    for projectline in plist:
                        project_details = projectline.strip()
                        write_to_project_file(project_details,regionfile_name,region_name,cae_deltafile)
                        create_temp_file(project_details,region_name)
                else:
                    try:
                        print("LOG: Creating initial project list file for region %s " % region_name)
                        f = open(regionfile_name,"w")
                        for projectline in plist:
                            project_details=projectline.strip()
                            write_to_project_file(project_details,regionfile_name,region_name,cae_deltafile)
                            create_temp_file(project_details,region_name)
                    except IOError:
                        print("ERROR: Unable to create initial %s file" % regionfile_name)
                temp_file = region_name+"temp"
                try:
                    print("LOG: Opening %s file for deleting  old projects details" % regionfile_name)
                    file=open(regionfile_name,"r")
                    for project in file:
                        update_project_files(project,temp_file,regionfile_name,region_name,cae_deltafile)
                except IOError:
                    print("ERROR: Cannot access %s file for deletefiles" % regionfile_name)
                print("LOG: Deleting temp file %s" % temp_file)
                os.remove(temp_file)
                db_check = update_dynamodb(regionfile_name,region_name,region_url,contact,table,cae_platform)
                if db_check is True:
                    print("LOG: DynamoDB update is Successfully")
                else:
                    print("ERROR: DynamoDB update is UnSuccessful")
                print("INFO: -.-.-.-RegionEnd -.-.-.- ")
            else:
                ("ERROR: cannot connect to cae platform to get project list")

    except IOError:
        print("ERROR: Cannot access caedata.xml file for CAE platform")

    print("-.-.-.-.--.-. P3 Platform -.-.-.-.--")
    try:
        print("LOG: Reading data.xml file for P3 platform")
        tree = ET.parse('data.xml')
        root = tree.getroot()

        #iterating through dat afile to get all regions an dtheir URL
        print("LOG: Iterating the data file for getting regionURL,RegionName and config path ")
        for regions in root.iter('region'):
            region_name = regions.find('regionname').text
            region_url = regions.find('regionurl').text
            regionfile_name = region_name.lower()+"ProjList"
            my_env["OS_AUTH_URL"] = region_url
            plist_cmd = 'openstack project list -c ID -c Name -c Enabled -f value --long'
            try:
                plist_process = subprocess.Popen(plist_cmd, shell = True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=my_env)
                project_list = plist_process.stdout
                if path.exists(regionfile_name):
                    print("LOG: Project list file exists for region %s" % region_name)
                    for projectline in project_list:
				        project_details = projectline.strip()
				        write_to_project_file(project_details,regionfile_name,region_name,deltafile)
				        create_temp_file(project_details,region_name)
                else:
                    try:
                        print("LOG: Creating initial project list file for region %s " % region_name)
                        f = open(regionfile_name,"w")
                        for projectline in project_list:
				            project_details=projectline.strip()
				            write_to_project_file(project_details,regionfile_name,region_name,deltafile)
				            create_temp_file(project_details,region_name)
                    except IOError:
                        print("ERROR: Unable to create initial %s file" % regionfile_name)
            except subprocess.CalledProcessError as error:
                print("ERROR: %s " % error.output)

            temp_file = region_name+"temp"
            try:
                print("LOG: Opening %s file for deleting  old projects details" % regionfile_name)
                file=open(regionfile_name,"r")
                for project in file:
                    update_project_files(project,temp_file,regionfile_name,region_name,deltafile)
            except IOError:
                print("ERROR: Cannot access %s file for deletefiles" % regionfile_name)
            print("LOG: Deleting temp file %s" % temp_file)
            os.remove(temp_file)
            db_check = update_dynamodb(regionfile_name,region_name,region_url,contact,table,p3_platform)
            if db_check is True:
                print("LOG: DynamoDB update is Successfully")
            else:
                print("ERROR: DynamoDB update is UnSuccessful")
            print("INFO: -.-.-.-RegionEnd -.-.-.- ")


    except IOError:
        print("ERROR: Cannot access caedata.xml file for P3 platform")




if __name__== "__main__":

    load_enc_variable()
    #Setting environment variables required for execution of CBS-CNT related scripts
    for var, val in env_variables.items():
        os.environ[var] = val

    my_env = os.environ.copy()
    sleep_time= float(my_env["WAIT_TIME_FOR_PROJECT_LIST_SCHEDULE"])

    
    table_name = "devTeams"
    contact = "csbauditor.gen@cisco.com"
    session = boto3.Session(aws_access_key_id=my_env["AWS_ACCESS_KEY_ID"], aws_secret_access_key=my_env["AWS_SECRET_ACCESS_KEY"], region_name='us-east-1')
    ddb=session.resource("dynamodb")
    table = ddb.Table(table_name)

    cae_platform = "CAE"
    p3_platform = "P3"

#for single execution
#    main()
#for scheduling
    try:
        while True:
            main()
            print("----NEXT Iteration---------")
            time.sleep(sleep_time)
    except KeyboardInterrupt:
        print("Manually interupted by user")

