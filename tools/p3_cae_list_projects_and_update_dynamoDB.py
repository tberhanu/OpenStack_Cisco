#!/opt/app-root/bin/python

"""
--------------------------p3_cae_list_projects_and_update_dynamoDB.py-----------------------
Description: This script is to get the list of projects available in all P3 and CAE regions.
            As an output it will generate projectlist for each region  and a common delta
            file for all p3 regions. The main function iterates through data.xml and 
            generate projectList files for each region mentioned in data file.
            This will run  based on env variable set, untill manually interepted 
            by user (ctrl+c)
Dependency:
            data_p3.xml
            date_cae.xml
            env_variables.py
            csb_credentials.py.enc
            teams_db_update_util
            openstack client
            kube_config_rcdn.enc
            kube_config_rtp.enc
            kube_config_alln.enc

Author: Ravi Gujja

Copyright (c) 2019 Cisco Systems.
All rights reserved.
------------------------------------------------------------------------------------------
"""
import pykube
import argparse
import datetime
import os
import subprocess
import time
import struct
import requests.packages.urllib3
import xml.etree.ElementTree as ET

from os import environ as env
from os import path
from Crypto.Cipher import AES
from importlib import import_module
from teams_db_update_util import *
from landscape_of_execution import landscape
from prod_env_variables import prod_env_variables
from nonprod_env_variables import nonprod_env_variables



def decrypt_file(filenames):
    """
    Decrypts the encrypted files using AES(CBC mode) with the given key.
    :param filenames: name of encrypted kube config file(s)
    :return: generate decrypted file and return True/False
    """
    """ Key to decrypt the encrypted files required for CSB Audit """
    key = "1329ebbc1b9646b890202384beaef2ec"

    list_of_enc_files = filenames.split(",")
    flag = True
    for in_filename in list_of_enc_files:
        out_filename = os.path.splitext(in_filename)[0]
        chunk_size = 64*1024
        try:
            print("INFO: Decrypt %s file" % in_filename)
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
                    flag = False
        except IOError:
            print("ERROR: File %s was not accessible" % in_filename)
            flag = False

        if os.path.isfile(out_filename):
            print("INFO: Decrypted version of %s file is available for use" % in_filename)
        else:
            print("ERROR: Decrypted version of %s file is not available for use" % in_filename)
            flag = False

    return flag

def write_to_project_file(project_details, regionfile_name, region_name, deltafile):
    """
    This method is writes the project details to the respective project list file and also update delta file if any new project details
    are added to the projectfile
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
            f = open(regionfile_name, "a")
            print("LOG: Writing new project details to %s " % regionfile_name)
            f.write(project_details+'\n')
        except IOError:
            print("ERROR: File %s is not accessible" % regionfile_name)


def create_temp_file(project_details, region_name):
    """
    This method is to create a temp file for all the projects based on region
    :param project_details: single project details
    :param region_name: region name
    :return: none
    """
    try:
        print("LOG: Creating %s temp file in append mode to store current project list" % region_name)
        f = open(region_name+"temp", "a")
        f.write(project_details+'\n')
    except IOError:
        print("ERROR: Failed to create %s temp file" % region_name)


def delete_existing_project_details(project_details, regionfile_name):
    """
    This method is to delete existing project details from the file
    :param project_details: single project details in a line
    :param regionfile_name: file name of project list
    :return: none
    """
    try:
        print("LOG: Opening %s file in read mode for comparision" % regionfile_name)
        f = open(regionfile_name, "r")
        lines = f.readlines()
        f.close()
    except IOError:
        print("ERROR: Opening %s is not accessible" % regionfile_name)
    try:
        print("LOG: Opening %s in write mode to write current projects" % regionfile_name)
        f = open(regionfile_name, "w")
    except IOError:
        print("ERROR: Opening %s isnot accessible for writing" % regionfile_name)
    else:
        for newline in lines:
            if newline.strip().split(",")[0] != project_details.strip().split(",")[0]:
                #if newline != project_details:
                f.write(newline)
        f.truncate()
        f.close()


def update_project_files(project_details, temp_file, regionfile_name, region_name, deltafile):
    """
    This method is to update the delta file if any projects are deleted, and calls delete_exesting_project_detils() to delete that project
    particular regions project file
    :param project_details: single project details in a line
    :param temp_file: temperory file name/path
    :param regionfile_name: path/name to the projectlist file
    :param region_name: region name
    :param deltafile: delta file path/name
    :return: none
    """
    if not (path.exists(temp_file)):
        try:
            print("LOG: Opening %s in write mode" % temp_file)
            f = open(temp_file, "w")
        except IOError:
            print("ERROR: %s is not accessible" % temp_file)
    if len(project_details) == 1:
        print("INFO: Removing blank line")
        delete_existing_project_details(project_details, regionfile_name)
    else:
        if project_details in open(temp_file).read():
            pass
        else:
            try:
                print("LOG: Opening %s in append mode" % deltafile)
                f = open(deltafile, "a")
            except IOError:
                print("ERROR: Unable to access %s " % deltafile)
            project_details = project_details.replace('\n', '').replace('\r', '')
            f.write(region_name+" "+project_details+" Deleted on "+str(datetime.datetime.now().date())+":"+str(datetime.datetime.now().time())+'\n')
            print("LOG: Written deleted project details of %s region to delta file" % region_name)
            delete_existing_project_details(project_details, regionfile_name)


def get_projects(config_path):
    """
    This method is used to get the project list for CAE platform
    :param config_path : path to config file for cae regions
    :return: return the list of project details 
    """
    try:
        api_handle = load_config(config_path)
        if api_handle:
            print("LOG: API loaded with current path %s" % config_path)
        try:
            print("LOG: Loading project metadata using API")
            project_met = pykube.Namespace.objects(api_handle).filter(namespace=pykube.all)
        except Exception as e:
            print("ERROR: Cannot load project metadata")
            print(e)
        plist = []
        if project_met:
            for project_list in project_met:
                try:
                    metadata_project = project_list.obj['metadata']
                    project_id = metadata_project.get('uid', None)
                    project_name = metadata_project.get('name', None)
                    project_status = project_list.obj['status']['phase']
                except Exception as e:
                    print("ERROR: cannot get metadata %s" % e)
                row = "%s %s %s" % (project_id, project_name, project_status)
                plist.append(row)
            return plist
        else:
            print("ERROR: Unable to connect to get metadate of all the projects for config %s" % config_path)
            return None
    
    except Exception as e:
        print("ERROR: Failed to retrieve project list => %s" % str(e))
        return None


def load_config(config_path):
    """
    Method to create API handle
    :param config_path: holds the path to config file
    :return: api handle to access projects in cae
    """
    try:
        print("LOG: Loading config file from path %s " % config_path)
        api = pykube.HTTPClient(pykube.KubeConfig.from_file(config_path))
        return api
    except Exception as e:
        print("ERROR: Failed to retrieve pykube.KubeConfig.from_file path => %s" % config_path)
        print(e)
        return None


def main():
    """
    This is main method to execute the project list script, it iterates through the data file and gets regionname,regionurl for P3 and config path for CAE regions
    This function calls the respective functios to create, update, and delete projects from project files based on region
    This also calls the functions to update dynamoDB teams table for both P3 and CAE.
    param: none
    return: none
    """
    requests.packages.urllib3.disable_warnings()
    cae_deltafile = "CAE-deltafile"
    deltafile = "P3-deltafile"

    """ CAE platform """
    try:
        print("LOG: Reading data.xml file for CAE platform")
        tree = ET.parse('data_cae.xml')
        root = tree.getroot()
        print("LOG: Iterating the data file for getting regionURL,RegionName and config path ")
        for regions in root.iter('region'):
            region_name = regions.find('regionname').text
            region_url = regions.find('regionurl').text
            regionfile_name = region_name.lower()+"ProjList"
            config_path = regions.find('configpath').text
            """generating CAE projectlist """
            plist = get_projects(config_path)

            if plist is not None:
                if path.exists(regionfile_name):
                    print("LOG: Project list file exists for region %s" % region_name)
                    for projectline in plist:
                        project_details = projectline.strip()
                        write_to_project_file(project_details, regionfile_name, region_name, cae_deltafile)
                        create_temp_file(project_details, region_name)
                else:
                    try:
                        print("LOG: Creating initial project list file for region %s " % region_name)
                        f = open(regionfile_name, "w")
                        for projectline in plist:
                            project_details = projectline.strip()
                            write_to_project_file(project_details, regionfile_name, region_name, cae_deltafile)
                            create_temp_file(project_details, region_name)
                    except IOError:
                        print("ERROR: Unable to create initial %s file" % regionfile_name)

                temp_file = region_name+"temp"
                try:
                    print("LOG: Opening %s file for deleting  old projects details" % regionfile_name)
                    pfile = open(regionfile_name, "r")
                    for project in pfile:
                        update_project_files(project, temp_file, regionfile_name, region_name, cae_deltafile)
                except IOError:
                    print("ERROR: Cannot access %s file for deletefiles" % regionfile_name)

                print("LOG: Deleting temp file %s" % temp_file)
                os.remove(temp_file)
                print("\n-.-.-.-.-. DynamoDB details-.-.-.-.-")
                """ calling function to update dynamoDB teams table """
                db_check, item_success, item_unsuccess, item_unknown, item_success_delete, item_failed_delete, item_unknown_delete  = update_dynamodb(regionfile_name, region_name, region_url, contact, cae_platform)
                if db_check is True:
                    print("LOG: DynamoDB update is Successfully")
                else:
                    print("ERROR: DynamoDB update is UnSuccessful")

                print("----------OVERALL SUMMARY FOR REGION %s---------" % region_name)
                print("Total number of projects successful in adding to Database: %s" % item_success)
                print("Total number of projects UnSuccessful in adding to Database: %s" % item_unsuccess)
                print("Total number of projects unknown while adding to Database: %s" % item_unknown)
                print("Total number of projects successfully UnInstalled in Database: %s" % item_success_delete)
                print("Total number of projects unsuccessful in UnInstalling in Database: %s" % item_failed_delete)
                print("Total number of projects unknown while UnInstalling in Database: %s" % item_unknown_delete)
                print("INFO: -.-.-.-RegionEnd -.-.-.- ")
            else:
                print("ERROR: cannot connect to cae platform to get project list")
    except IOError:
        print("ERROR: Cannot access data_cae.xml file for CAE platform")

    """ P3 platform """
    print("-.-.-.-.--.-. P3 Platform -.-.-.-.--")
    try:
        print("LOG: Reading data.xml file for P3 platform")
        tree = ET.parse('data_p3.xml')
        root = tree.getroot()
        print("LOG: Iterating the data file for getting regionURL,RegionName and config path ")
        for regions in root.iter('region'):
            region_name = regions.find('regionname').text
            region_url = regions.find('regionurl').text
            regionfile_name = region_name.lower()+"ProjList"
            my_env["OS_AUTH_URL"] = region_url
            plist_cmd = 'openstack project list -c ID -c Name -c Enabled -f csv --long'
            try:
                plist_process = subprocess.Popen(plist_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=my_env)
                project_list = plist_process.stdout
                if path.exists(regionfile_name):
                    print("LOG: Project list file exists for region %s" % region_name)
                    for projectline in project_list:
                        project_details = projectline.strip()
                        write_to_project_file(project_details, regionfile_name, region_name, deltafile)
                        create_temp_file(project_details, region_name)
                else:
                    try:
                        print("LOG: Creating initial project list file for region %s " % region_name)
                        f = open(regionfile_name, "w")
                        for projectline in project_list:
                            project_details = projectline.strip()
                            write_to_project_file(project_details, regionfile_name, region_name, deltafile)
                            create_temp_file(project_details, region_name)
                    except IOError:
                        print("ERROR: Unable to create initial %s file" % regionfile_name)
            except subprocess.CalledProcessError as error:
                print("ERROR: %s " % error.output)

            temp_file = region_name+"temp"
            try:
                print("LOG: Opening %s file for deleting  old projects details" % regionfile_name)
                pfile = open(regionfile_name, "r")
                for project in pfile:
                    update_project_files(project, temp_file, regionfile_name, region_name, deltafile)
            except IOError:
                print("ERROR: Cannot access %s file for deletefiles" % regionfile_name)

            print("LOG: Deleting temp file %s" % temp_file)
            os.remove(temp_file)
            print("\n-.-.-.-.-. DynamoDB details-.-.-.-.-")
            """ calling function to update dynamoDB teams table"""
            db_check, item_success, item_unsuccess, item_unknown, item_success_delete, item_failed_delete, item_unknown_delete = update_dynamodb(regionfile_name, region_name, region_url, contact, p3_platform)
            if db_check is True:
                print("LOG: DynamoDB update is Successfully")
            else:
                print("ERROR: DynamoDB update is UnSuccessful")

            print("----------OVERALL SUMMARY FOR REGION %s---------" % region_name)
            print("Total number of projects successful in adding to Database: %s" % item_success)
            print("Total number of projects UnSuccessful in adding to Database: %s" % item_unsuccess)
            print("Total number of projects unknown while adding to Database: %s" % item_unknown)
            print("Total number of projects successfully UnInstalled in Database: %s" % item_success_delete)
            print("Total number of projects unsuccessful in UnInstalling in Database: %s" % item_failed_delete)
            print("Total number of projects unknown while UnInstalling in Database: %s" % item_unknown_delete)
            print("INFO: -.-.-.-RegionEnd -.-.-.- \n")
    except IOError:
        print("ERROR: Cannot access data_p3.xml file for P3 platform")

def set_credentials_env(e_type):
    """
    Method to set the environment in terms of credentials to be used during execution
    :return:
    """
    print("INFO: Decrypt credentials file. Then set environment variables w.r.t. required set of credentials")
    if e_type == "prod":
        cred_file = "csb_credentials.py.enc_prod"
    elif e_type == "nonprod":
        cred_file = "csb_credentials.py.enc_nonprod"
    else:
        print("ERROR: Didn't receive the expected value for ENV_TYPE - %s" % e_type)

    if decrypt_file(cred_file):
        print("INFO: Successfully decrypted Credential file")
        cred_file_handle = import_module("csb_credentials")
        for var, val in cred_file_handle.csb_credentials.items():
            os.environ[var] = val
        return True
    else:
        raise Exception("ERROR: Failed to decrypt %s file" % cred_file)
        return False

def generate_kube_config_file():
    """
    Method to generate Kube config file per CAE Cluster listed in landscape_of_execution.py file
    :return: True|False
    """
    kube_config_at_home = os.path.expanduser("~") + "/.kube/config"
    for cluster in landscape["CAE_CLUSTER"]:
        try:
            if path.exists(kube_config_at_home):
                os.remove(kube_config_at_home)
        except OSError as rm_err:
            if rm_err.errno == errno.ENOENT:
                print("INFO: %s" % str(rm_err))
            else:
                print("ERROR: %s" % str(rm_err))
                return False

        print("INFO: Cluster - %s" % cluster)
        out = subprocess.Popen([
                                '/usr/bin/oc', 'login', cluster,
                                '-u', os.environ["OC_USERNAME"],
                                '-p', os.environ["OC_PASSWORD"],
                                '--insecure-skip-tls-verify'
                                ],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT
                              )
        stdout, stderr = out.communicate()
        print("DEBUG: STDOUT while logging into Cluster: %s - %s" % (cluster, stdout))
        if stderr:
            print("ERROR: stderr while logging in to Cluster: %s - %s" % (cluster, stderr))
            return False

        if "Login successful" in str(stdout):
            #kube_config_rgn = os.path.expanduser("~") + "/kube_config_" + cluster.split(".")[0].split("-")[-1]
            kube_config_rgn = os.path.expanduser("~") + "/" + "kube_config_" + cluster.split("//")[1].split(".")[0].replace("-", "_")
            out = subprocess.Popen(['cp', kube_config_at_home, kube_config_rgn],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout, stderr = out.communicate()
            if stderr:
                print("ERROR: STDERR while copying the file - %s" % stderr)
                return False
            elif os.path.isfile(kube_config_rgn):
                print("INFO: Generated Kube config file - %s" % kube_config_rgn)
        else:
            print("ERROR: Failed to login to Cluster: %s" % cluster)
            return False
    return True



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pass on the type of execution environment")
    parser.add_argument("-e", "--env_type", help="Environment Type(\"prod\" or \"nonprod\")", action="store", dest="env")
    args = parser.parse_args()

    if args.env and (args.env == "prod" or args.env == "nonprod"):
        env_type = args.env
        print("INFO: Execution will continue for %s ENV" % str(env_type).upper())
    else:
        print("ERROR: Received ENV Type is not appropriate. Expected ENV Type is either \"prod\" or \"nonprod\"")

    #set_credential_env will dectypt the credentials file.
    if set_credentials_env(env_type):
        """ Setting environment variables required for execution of CBS-CNT related scripts """
        if env_type == "prod":
            print("INFO: Set all required variables as part of ENV for ENV_TYPE = %s" % env_type)
            for var, val in prod_env_variables.items():
                os.environ[var] = val
        elif env_type == "nonprod":
            print("INFO: Set all required variables as part of ENV for ENV_TYPE = %s" % env_type)
            for var, val in nonprod_env_variables.items():
                os.environ[var] = val
        else:
            print("ERROR: Didn't receive the expected value for ENV_TYPE - %s" % env_type)

        if generate_kube_config_file():
            print("INFO: Successfully generated the required Kube Config file for "
                  "each cluster listed in landscape_of_execution.py")

        else:
            print("ERROR: Issue observed while generating Kube config file.")
            print("INFO: Overall execution for CAE Tenants will get affected")
    else:
        raise Exception("ERROR: Failed to initialize the environment in terms of credentials to use.")


    
    """ assigning env variables to my_env, will be using this in subprocess for getting p3 project list"""
    my_env = os.environ.copy()

    sleep_time = float(my_env["WAIT_TIME_FOR_PROJECT_LIST_SCHEDULE"])
    
    """ values to be used in updating dynamodb table"""
    cae_platform = "CAE"
    p3_platform = "P3"
    contact = "csbauditor.gen@cisco.com"
#   for single execution
#    main()
#    for scheduling
    try:
        while True:
            main()
            print("----NEXT Iteration---------")
            sys.stdout.flush()
            time.sleep(sleep_time)
    except KeyboardInterrupt:
        print("Manually interrupted by user")
        print("INFO: Delete decrypted Credential file")
        os.remove(os.path.expanduser("~") + "/" + "csb_credentials.py")
        os.remove(os.path.expanduser("~") + "/" + "csb_credentials.pyc")
