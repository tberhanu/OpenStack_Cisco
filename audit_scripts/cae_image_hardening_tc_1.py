#!/opt/app-root/bin/python
"""
--------------------------cae_image_hardening_tc_1.py--------------------------
Description: This python script is to list all the images in the CAE namespace
             and validate if the image used are from the trusted source or not.
Dependency:
            Kube config files per region
Author: Dharavahani Malepati <dmalepat@cisco.com>; January 8th, 2019
Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------------
"""


import argparse
import csv
import datetime
import requests.packages.urllib3
import pykube
import re
import os
import time
import sys
import json

sys.path.append(os.environ["CLONED_REPO_DIR"] + "/library")
from general_util import updateScanRecord, add_result_to_stream, send_result_complete, session_handle


""" Translating script name to get the TC Label """
filename = os.path.abspath(__file__).split("/")[-1].split(".py")[0]
tc = filename.replace("_", "-").upper()
seq_nums_list = []
session = session_handle()


""" Creating name of CSV file """
date_stamp = datetime.datetime.now().strftime('%m%d%y')
csv_filename = os.path.expanduser("~") + "/logs/cae_image_hardening_tc_1_" + date_stamp + ".csv"
csv_filename2 = os.path.expanduser("~") + "/logs/cae_image_hardening_Non_Compliant_" + date_stamp + "_.csv"


def load_config(path):
    """
    Method to create API Handle
    :param path: holds the path to kube config file
    :return: api handle
    """
    try:
        api = pykube.HTTPClient(pykube.KubeConfig.from_file(path))
        return api
    except Exception as e:
        print("ERROR: Failed to retrieve pykube.KubeConfig.from_file path => %s" % str(e))
        return None


def get_projects(project_name,path):
    """
    Method to fetch project specific metadata
    :param project_name: Name of the project
    :param path: holds the path to kube config file
    :return: project_file_text
    """
    project_file_text = None
    try:
        print("LOG: Inside get_project method to collect info about Project")
        api_handle = load_config(path)
        project_met = pykube.Namespace.objects(api_handle).get(name=project_name)
        metadata_project = project_met.obj['metadata']
        if metadata_project is not None:
            uid = none_check(metadata_project.get('uid', None))
            name = none_check(metadata_project.get('name', None))
            annotations = metadata_project.get('annotations', {})
            if annotations is not None:
                try:
                    application_id = annotations['citeis.cisco.com/application-id']
                except KeyError:
                    application_id = 'None'
                    print("LOG: No application Id found ")

                try:
                    application_name = annotations['citeis.cisco.com/application-name']
                except KeyError:
                    application_name = 'None'
                    print("LOG: No application Name found ")

            project_file_text = [name, uid, application_id, application_name]
            print("LOG: Successfully returning the projects")
        else:
            print("LOG: No annotations found")
            project_file_text = ['None','None', 'None', 'None']
    except Exception as e:
        print("ERROR: Failed to retrieve project list => %s" % str(e))
    return project_file_text


def get_pods(project_pod,path):
    """
    Method to fetch project specific POD info
    :param project_pod: holds project name
    :param path: holds path to Kube config file
    :return: PODs list
    """
    try:
        print("LOG: Checking for Projects => %s" % project_pod)
        api_handle = load_config(path)
        pods = pykube.Pod.objects(api_handle).filter(namespace=project_pod)
        if pods is not None and len(pods):
            print("LOGS: Successfully retreived pods, Pod count is ", len(pods))
            return pods
        else:
            print("LOGS: No pods found in the pod list")
            return None
    except Exception as e:
        print("ERROR: Failed to retrieve pods with error => %s" % str(e))
        return None


def get_image(project_img, pod, path, compliance_status, scan_id, team_id, scanid_valid, teamid_valid):
    """
    Method to get image details of application running on pod under specified project
    :param project_img: holds Project Name
    :param pod: holds POD Name
    :param path: holds path to Kube config file
    :return: image_data | None
    """
    try:
        print("LOG: Listing the images in the pods in the project  => %s" % project_img)
        api = load_config(path)
        pod = pykube.Pod.objects(api).filter(namespace=project_img).get(name=pod)
        if pod is not None:
            metadata = pod.obj['metadata']
            pod_name = none_check(metadata.get('name', None))
            pod_namespace = none_check(metadata.get('namespace', None))
            pod_stat = pod.obj['status']
            pod_status = none_check(pod_stat.get('phase', None))
            container_status = pod.obj['status']
            container_info = container_status.get('containerStatuses', None)
            if container_info is not None:
                for container in container_info:
                    image_name = none_check(container.get('image', None))
                    image_id = none_check(container.get('imageID', None))
                    container_id = none_check(container.get('containerID', None))
                    try:
                        container_state = container.get('state', {}).get('running', {})
                        container_start_date = none_check(container_state.get('startedAt', None))
                    except KeyError:
                        container_start_date = 'None'
                    for container_list in pod.obj["spec"]["containers"]:
                        image = none_check(container_list.get('image',None))
                        compliance_status = compliance_status_validation(image)
                        try:
                            ports = " "
                            for container_port in container_list['ports']:
                                container_exposed_port = str(container_port.get('containerPort',None))
                                ports = container_exposed_port + "/" + ports
                        except KeyError:
                                ports = 'None'
                    params_list = []
                    if scanid_valid and teamid_valid:
                        if container_id is not None:
                            resource_name = str(pod) + "_" + str(container_id.split("//")[1][:7])
                        else:
                            resource_name = str(pod)
                        if kinesis_update(session, "CAE", scan_id, tc, team_id, resource_name, compliance_status,
                                          params_list):
                            print("LOG: Inside For loop Added the info to Kinesis Stream")
                        else:
                            print("LOG: Kinesis Update API Failed")
                            return None
                    else:
                        print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")
                    image_file_text = [pod_name, pod_namespace, pod_status, container_id, image_name, image_id,
                                       container_start_date, ports, compliance_status]
                    proj_txt = get_projects(project_img, path)
                    image_data = [image_file_text, proj_txt, compliance_status]
                    build_metadata(image_data, csv_filename)
                    non_compliant_str = 'Non-Compliant'
                    if compliance_status.lower() == non_compliant_str.lower():
                        # Write a new CSV file when the image is Non-compliant
                        create_csv_file_headers(csv_filename2)
                        build_metadata(image_data, csv_filename2)

            else:
                image_file_text = [pod_name, pod_namespace, pod_status, 'None', 'None', 'None',
                                   'None', 'None', compliance_status]
                proj_txt = get_projects(project_img, path)
                image_data = [image_file_text, proj_txt,compliance_status]
                build_metadata(image_data, csv_filename)

            return image_data
        else:
            print("No images found")
            return compliance_status
    except Exception as e:
        print("ERROR: Failed to retrieve images with error => %s" % str(e))
        return None


def print_metadata(image_file_text, project_file_text, csv_filename):
    """
    Method to print the metadata in image_file_text and Project_file_text
    :param image_file_text: holds pod name,pod status,pod namespace,container id,
    container status,container exposed port,image name, image id, compliance_status
    :param project_file_text:holds project id, project name, application_id, application_name
    :return: None
    """
    try:
        print("LOG: Saving the metadata into a file")
        file_content = []
        if project_file_text and image_file_text is not None:
            file_content = [project_file_text + image_file_text]
        with open(csv_filename, 'a') as csvFile:
            writer = csv.writer(csvFile)
            writer.writerows(file_content)
        csvFile.close()
    except Exception as e:
        print("ERROR: Failed to write the output file with error => %s" % str(e))


def empty_metadata(namespace, path, compliance_status):

    proj_txt = get_projects(namespace, path)
    image_file_text = ["None"] * 8 + [compliance_status]
    print_metadata(image_file_text, proj_txt, csv_filename)


def build_metadata(image_values, csv_filename):
    """
     Method to build the metadata into a file
    :param namespace: holds name of the project
    :param pod: hold name of the pod
    :param path: hold path to the kube config file
    :param compliance_status: hold the compliant or non compliant status
    :return:None
    """
    try:
        print("LOG: Building the metadata into a file")
        image_file_text = image_values[0]
        project_file_text = image_values[1]
        print_metadata(image_file_text, project_file_text, csv_filename)
    except Exception as e:
        print("ERROR: Failed to build metadata with error => %s" % str(e))
        return None


def scanid_validation(scan_id):
    scanid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    if scanid_pattern.match(scan_id):
        print("LOG: Received valid ScanID")
        return True
    else:
        print("ERROR: Received ScanID is not valid")
        return False


def cae_teamid_validation(team_id):
    teamid_pattern = re.compile(r'^CAE:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    if teamid_pattern.match(team_id):
        print("LOG: Received valid TeamID")
        return True
    else:
        print("ERROR: Received TeamID is not valid")
        return False



def cae_url_validation(url):
    cae_url_pattern = re.compile(r'^https://cae-np-.*.cisco.com$')
    if cae_url_pattern.match(url):
        print("LOG: Received valid Domain URL")
        return True
    else:
        print("ERROR: Received Domain URL is not valid")
        return False

def main(url, namespace, scan_id, team_id):
    """
    Main method to start the audit over images used in the given NameSpace
    :param url:hold the urls
    :param namespace:holds the name of the project
    :param scan_id:
    :param team_id:
    :return: Compliant | Non-compliant | None
    """
    try:
        flag = "Compliant"
        scanid_valid = False
        teamid_valid = False
        if scan_id and team_id is not None:
            scanid_valid = scanid_validation(scan_id)
            teamid_valid = cae_teamid_validation(team_id)
        else:
            print("LOG: Valid ScanId or TeamId not found")
            print("INFO: Execution will proceed without Kinesis update")

        requests.packages.urllib3.disable_warnings()
        print("INFO: Based on URL accepted, fetching respective Kube config file")
        if url is not None:
            region_name = url.split(".")[0].split("-")[-1]
            if region_name is not None:
                path = os.path.expanduser("~") + "/" + "kube_config_" + region_name
            else:
                raise Exception("ERROR: Region name is None")
                return None
            session = session_handle()
            if session:
                if scanid_valid and teamid_valid:
                    print("LOG: Update the scan record with \"InProgress\" Status")
                    update = updateScanRecord(session, "CAE", scan_id, team_id, tc, "InProgress")
                    if update is None:
                        raise Exception("LOG: Issue observed with UpdateScanRecord API call for \"InProgress\" status")
                        return None
                else:
                    print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

                create_csv_file_headers(csv_filename)
                print("LOG: Check whether source of image used is a trusted one")
                pods_list = get_pods(namespace, path)
                proj_txt = get_projects(namespace, path)
                compliance_status = "Compliant"
                non_compliant_str = 'Non-Compliant'
                if proj_txt is not None:
                    if pods_list is not None:
                        pod_count = 0
                        pod_status_sub_str2 = ""
                        for pod in pods_list:
                            if pod_count < 5:
                                metadata = pod.obj['metadata']
                                pod_name = none_check(metadata.get('name', None))
                                pod_stat = pod.obj['status']
                                pod_status = none_check(pod_stat.get('phase', None))
                                pod_status_sub_str = pod_name[:-5]
                                if pod_status_sub_str.lower() == pod_status_sub_str2.lower() and pod_status.lower() == "failed":
                                    pod_count +=1
                                else:
                                    pod_count -= 1
                                pod_status_sub_str2 = pod_name[:-5]
                                image_data = get_image(namespace, pod, path, compliance_status, scan_id, team_id, scanid_valid, teamid_valid)
                                flag_txt = image_data[2]
                                if flag_txt.lower() == non_compliant_str.lower():
                                    flag = non_compliant_str
                            else:
                                print("ERROR: Exiting after 5 unsuccessful retries")
                                break
                    else:
                        print("INFO: No Pods running in the project")
                        empty_metadata(namespace, path, compliance_status)
                        params_list = []
                        pod = 'NULL'
                        if scanid_valid and teamid_valid:
                            if kinesis_update(session,"CAE", scan_id, tc, team_id, pod, compliance_status,params_list):
                                print("LOG: Added the info to Kinesis Stream")
                            else:
                                print("LOG: Kinesis Update API Failed")
                                return None
                        else:
                            print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")
                        return compliance_status
                else:
                    proj_txt = [namespace] + ["Does not exist"] * 4
                    image_file_text = ["Does not exist"] * 9
                    print_metadata(image_file_text, proj_txt, csv_filename)
        else:
            print("ERROR:URL not found")
            return None

        if scanid_valid and teamid_valid:
            print("INFO: Sending result complete")
            send_result = send_result_complete(session, "CAE", scan_id, team_id, tc, seq_nums_list)
            if send_result:
                print("LOG: Successfully submitted the result to Kinesis")
            else:
                print("LOG: Failed to submit the result to Kinesis")
                return None
        else:
            print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

        return flag

    except Exception as e:
        print("INFO: Failed to retrieve image list and pod list => %s" % str(e))
        update = updateScanRecord(session, "CAE", scan_id, team_id, tc, "Failed")
        if update is None:
            raise Exception("ERROR: Issue observed with updateScanRecord API call")
            return None
        raise Exception(
            "ERROR: Failed to fetch either Projects: %s or Project_list")
        return None


def kinesis_update(session, platform, scan_id, tc, team_id, pod, compliance_status, params_list):

    audit_time = int(time.time()) * 1000
    try:
        params = {
            "scanid": scan_id,
            "testid": tc,
            "teamid": str(team_id),
            "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, pod),
            "createdAt": audit_time,
            "updatedAt": audit_time,
            "resourceName": str(pod),
            "complianceStatus": compliance_status,
        }
        params_list.append(params.copy())

        while sys.getsizeof(json.dumps(params_list)) >= 900000:
            print("INFO: FIRST ELEMENT OF PARAMS LIST: ", params_list[0])
            stream_info = add_result_to_stream(session, platform, str(team_id), tc, params_list)
            seq_nums_list.append(stream_info)
            print("LOG: Empty params list ... ", params_list)
            params_list[:] = []
        print("INFO: Adding result to Stream")
        stream_info = add_result_to_stream(session, platform, str(team_id), tc, params_list)
        seq_nums_list.append(stream_info)
        return True

    except Exception as params_err:
        print("ERROR: Issue observed while adding result to streams - %s" % str(params_err))
        return False

def none_check(val):
    if val is None:
        val = 'None'
    return val


def create_csv_file_headers(csv_filename):
    if os.path.isfile(csv_filename):
        print("INFO: CSV file is available to read")
        with open(csv_filename, 'r') as csvFile:
            reader = csv.reader(csvFile, delimiter=",")
            data = list(reader)
            row_count = len(data)
    else:
        print("INFO: CSV file is not available to read, writing new file ")
        row_count = 0
    if row_count <= 0:
        file_headers = ['Tenant Name', 'Tenant ID', 'Application ID', 'Application Name', 'Pod Name',
                        'Pod Namespace', 'Pod Status', 'Container ID', 'Image Name', 'Image ID',
                        'Container Start Date', 'Container Exposed Port ', 'Compliance_Status'
                        ]
        file_content = [file_headers]
        with open(csv_filename, 'a') as csvFile:
            writer = csv.writer(csvFile)
            writer.writerows(file_content)


def compliance_status_validation(image):
    if re.match(r'^containers.*.cisco.com\/*', image):
        compliance_status = "Compliant"
        return compliance_status
    else:
        compliance_status = "Non-Compliant"
        return compliance_status


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Identify images with insecure source')
    parser.add_argument("-u", "--domain_url", help="Domain/Region specific URL", action="store", dest="domain_url")
    parser.add_argument('-t', '--namespace', help='name of namespace/project to Search', action="store", dest='namespace')
    parser.add_argument("-s", "--scan_id", help="Scan ID from AWS", action="store", dest="scanid")
    parser.add_argument("-i", "--team_id", help="Project/Tenant ID", action="store", dest="teamid")

    args = parser.parse_args()
    url = args.domain_url
    namespace = args.namespace
    scan_id = args.scanid
    team_id = args.teamid
    url_valid = cae_url_validation(url)
    if url and namespace is not None:
        if url_valid is not None:
            compliance_status = main(url, namespace, scan_id, team_id)
            print("LOG: Process complete with compliance status as ", compliance_status)
        else:
            print("ERROR: Failed with validation")
    else:
        print("ERROR:Need Tenant ID and domain url to run the script")

