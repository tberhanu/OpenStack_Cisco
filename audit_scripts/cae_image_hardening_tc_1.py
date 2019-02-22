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

sys.path.append(os.environ["CLONED_REPO_DIR"] + "/library")
import cae_lib
import common_lib
import general_util


""" Translating script name to get the TC Label """
filename = os.path.abspath(__file__).split("/")[-1].split(".py")[0]
tc = filename.replace("_", "-").upper()
seq_nums_list = []
params_list = []

""" Creating name of CSV file """
date_stamp = datetime.datetime.now().strftime('%m%d%y')

csv_filename = os.path.expanduser("~") + "/logs/cae_image_hardening_tc_1_" + date_stamp + ".csv"
csv_filename2 = os.path.expanduser("~") + "/logs/cae_image_hardening_Non_Compliant_" + date_stamp + ".csv"


def get_projects(project_name,url):
    """
    Method to fetch project specific metadata
    :param project_name: Name of the project
    :param path: holds the path to kube config file
    :return: project_file_text
    """
    project_file_text = None
    try:
        print("INFO: Inside get_project method to collect info about Project")
        api_handle =cae_lib.load_config(url)
        for i in range(0,100):
            try:
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
                            print("INFO: No application Id found ")

                        try:
                            application_name = annotations['citeis.cisco.com/application-name']
                        except KeyError:
                            application_name = 'None'
                            print("INFO: No application Name found ")

                    project_file_text = [name, uid, application_id, application_name]
                    print("INFO: Successfully returning the projects")
                else:
                    print("INFO: No annotations found")
                    project_file_text = ['None', 'None', 'None', 'None']
            except Exception as e:
                exception_str = str(e)
                if '429' in str(e):
                    time.sleep(5)
                    print("LOG:RETRYING When too many requests hit the cluster",exception_str)
                    continue
                else:
                    print("ERROR:HTTP error ", exception_str)
            break
    except Exception as e:
        print("ERROR: Failed to retrieve project list => %s" % str(e))
    return project_file_text


def get_pods(project_pod,url):
    """
    Method to fetch project specific POD info
    :param project_pod: holds project name
    :param path: holds path to Kube config file
    :return: PODs list
    """
    try:
        print("INFO: Checking for Projects => %s" % project_pod)
        api_handle = cae_lib.load_config(url)
        for i in range(0,100):
            try:
                pods = pykube.Pod.objects(api_handle).filter(namespace=project_pod)
                if pods is not None and len(pods):
                    print("LOGS: Successfully retreived pods, Pod count is ", len(pods))
                    return pods, len(pods)
                else:
                    print("LOGS: No pods found in the pod list")
                    return None, None
            except Exception as e:
                exception_str = str(e)
                if '429' in exception_str:
                    time.sleep(5)
                    print("LOG:RETRYING When too many requests hit the cluster", exception_str)
                    continue
                else:
                    print("ERROR:HTTP error ", str(e))
            break
    except Exception as e:
        print("ERROR: Failed to retrieve pods with error => %s" % str(e))
        return None


def get_image(project_img, pod, url, compliance_status, scan_id, team_id, scanid_valid, teamid_valid, image_count,
              unsecured_image_count):
    """
    Method to get image details of application running on pod under specified project
    :param project_img: holds Project Name
    :param pod: holds POD Name
    :param path: holds path to Kube config file
    :return: image_data | None
    """
    try:
        api = cae_lib.load_config(url)
        for i in range(0,100):
            try:
                try:
                    print("INFO: Listing the images in the pods: %s " % pod)
                    pod_image = pykube.Pod.objects(api).filter(namespace=project_img).get(name=pod)
                except Exception as e:
                    pod_image = None
                    print(e)
                    print("ERROR: Unable to get image for the pod %s" % pod)
                    pass
                if pod_image is not None:
                    metadata = pod_image.obj['metadata']
                    pod_name = none_check(metadata.get('name', None))
                    pod_namespace = none_check(metadata.get('namespace', None))
                    pod_stat = pod_image.obj['status']
                    pod_status = none_check(pod_stat.get('phase', None))
                    container_status = pod_image.obj['status']
                    container_info = container_status.get('containerStatuses', None)
                    if container_info is not None:
                        for container in container_info:
                            image_name = none_check(container.get('image', None))
                            image_id = none_check(container.get('imageID', None))
                            if image_id is not 'None' and image_id != 'None':
                                image_count +=1
                            try:
                                container_id = none_check(container.get('containerID', None))
                            except KeyError:
                                container_id = 'None'
                            try:
                                container_state = container.get('state', {}).get('running', {})
                                container_start_date = none_check(container_state.get('startedAt', None))
                            except KeyError:
                                container_start_date = 'None'
                            for container_list in pod_image.obj["spec"]["containers"]:
                                image = none_check(container_list.get('image',None))
                                compliance_status = compliance_status_validation(image)
                                try:
                                    ports = " "
                                    for container_port in container_list['ports']:
                                        container_exposed_port = str(container_port.get('containerPort',None))
                                        ports = container_exposed_port + "/" + ports
                                except KeyError:
                                        ports = 'None'

                            if scanid_valid and teamid_valid:
                                if container_id is not None:
                                    """"updating params_list with pod name and last 5 digits of container ID"""
                                    resource_name = str(pod) + "_" + str(container_id.split("//")[1][:7])
                                else:
                                    """updating params_list with pod name """
                                    resource_name = str(pod)
                                if general_util.params_list_update(scan_id, tc, team_id, resource_name, compliance_status, params_list):
                                    print("INFO: Updating params_list")
                                else:
                                    print("ERROR: Issue observed while updating params_list")
                                    return None
                            else:
                                print("INFO: ScanId or TeamId passed to main() method is not valid, "
                                      "hence ignoring Kinesis part")
                            image_file_text = [pod_name, pod_namespace, pod_status, container_id, image_name, image_id,
                                               container_start_date, ports, compliance_status]
                            proj_txt = get_projects(project_img, url)
                            image_data = [image_file_text, proj_txt, compliance_status]
                            build_metadata(image_data, csv_filename)
                            non_compliant_str = 'Non-compliant'
                            if compliance_status.lower() == non_compliant_str.lower():
                                unsecured_image_count +=1
                                """ Write a new CSV file when the image is Non-compliant """
                                create_csv_file_headers(csv_filename2)
                                build_metadata(image_data, csv_filename2)

                    else:
                        image_file_text = [pod_name, pod_namespace, pod_status, 'None', 'None', 'None',
                                           'None', 'None', compliance_status]
                        proj_txt = get_projects(project_img, url)
                        image_data = [image_file_text, proj_txt,compliance_status]
                        build_metadata(image_data, csv_filename)

                    return image_data, image_count, unsecured_image_count
                else:
                    print("INFO: No images found")
                    image_file_text = [pod, 'Does not exist', 'Does not exist', 'Does not exist', 'Does not exist', 'Does not exist',
                                       'Does not exist', 'Does not exist', 'Does not exist']
                    proj_txt = get_projects(project_img, url)
                    image_data = [image_file_text, proj_txt, 'Does not exist']
                    build_metadata(image_data, csv_filename)
                    return image_data,0,0
            except Exception as e:
                exception_str = str(e)
                if '429' in exception_str:
                    time.sleep(5)
                    print("LOG:RETRYING When too many requests hit the cluster", exception_str)
                    continue
            break
    except Exception as e:
        print("ERROR: Failed to retrieve images with error => %s" % str(e))
        return None, 0, 0


def print_metadata(image_file_text, project_file_text, csv_filename):
    """
    Method to print the metadata in image_file_text and Project_file_text
    :param image_file_text: holds pod name,pod status,pod namespace,container id,
    container status,container exposed port,image name, image id, compliance_status
    :param project_file_text:holds project id, project name, application_id, application_name
    :return: None
    """
    try:
        print("INFO: Saving the metadata into a file")
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
    """

    :param namespace:
    :param path:
    :param compliance_status:
    :return:
    """
    proj_txt = get_projects(namespace, url)
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
        print("INFO: Building the metadata into a file")
        image_file_text = image_values[0]
        project_file_text = image_values[1]
        print_metadata(image_file_text, project_file_text, csv_filename)
    except Exception as e:
        print("ERROR: Failed to build metadata with error => %s" % str(e))
        return None


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
        summary_dict = {
                        'No_of_POD(s)_evaluated': 0,
                        'No_of_Image(s)_evaluated': 0,
                        'No_of_Unsecured_Image(s)_found': 0,
                        'No_of_POD(s)_using_unsecured_image(s)': 0,
                        'No_of_Tenants_with_unsecure_image(s)': 0
                       }

        flag = "Compliant"
        unsecured_tenant_count = 0
        scanid_valid = False
        teamid_valid = False
        if scan_id and team_id is not None:
            scanid_valid = common_lib.scanid_validation(scan_id)
            teamid_valid = cae_lib.cae_teamid_validation(team_id)
        else:
            print("INFO: Valid ScanId or TeamId not found")
            print("INFO: Execution will proceed without Kinesis update")

        requests.packages.urllib3.disable_warnings()
        print("INFO: Based on URL accepted, fetching respective Kube config file")
        if url is not None:
            session = general_util.session_handle()
            if session:
                if scanid_valid and teamid_valid:
                    print("INFO: Update the scan record with \"InProgress\" Status")
                    update = general_util.updateScanRecord(session, "CAE", scan_id, team_id, tc, "InProgress")
                    if update is None:
                        raise Exception("INFO: Issue observed with UpdateScanRecord API call for \"InProgress\" status")
                        return None,summary_dict
                else:
                    print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")

                create_csv_file_headers(csv_filename)
                print("INFO: Check whether source of image used is a trusted one")
                proj_txt = get_projects(namespace, url)
                compliance_status = "Compliant"
                non_compliant_str = 'Non-compliant'
                if proj_txt is not None:
                    pods_list, pod_count = get_pods(namespace, url)
                    if pods_list is not None:
                        temp_pod_count = 0
                        pod_status_sub_str2 = ""
                        image_count = 0
                        unsecured_pod_count = 0
                        unsecured_image_count_total = 0
                        for pod in pods_list:
                            if temp_pod_count < 5:
                                metadata = pod.obj['metadata']
                                pod_name = none_check(metadata.get('name', None))
                                pod_stat = pod.obj['status']
                                pod_status = none_check(pod_stat.get('phase', None))
                                pod_status_sub_str = pod_name[:-5]
                                if pod_status_sub_str.lower() == pod_status_sub_str2.lower() \
                                        and pod_status.lower() == "failed":
                                    temp_pod_count += 1
                                else:
                                    temp_pod_count -= 1
                                pod_status_sub_str2 = pod_name[:-5]
                                unsecured_image_count = 0
                                image_data, image_count, unsecured_image_count = get_image(namespace, pod, url,
                                                        compliance_status, scan_id, team_id, scanid_valid,
                                                        teamid_valid, image_count, unsecured_image_count)
                                unsecured_image_count_total = unsecured_image_count_total + unsecured_image_count
                                if unsecured_image_count > 0:
                                    unsecured_pod_count +=1
                                if image_data is not None:
                                    flag_txt = image_data[2]
                                    if flag_txt.lower() == non_compliant_str.lower():
                                        flag = non_compliant_str
                                        unsecured_tenant_count =1
                            else:
                                print("ERROR: Exiting after 5 unsuccessful retries")
                                break
                        summary_dict = build_summary_report(pod_count, image_count, unsecured_image_count_total,
                                                                unsecured_pod_count, unsecured_tenant_count)
                    else:
                        print("INFO: No Pods running in the project")
                        empty_metadata(namespace, path, compliance_status)
                        pod = 'NULL'
                        if scanid_valid and teamid_valid:
                            if general_util.params_list_update(scan_id, tc, team_id, pod, compliance_status, params_list):
                                print("INFO: Updating params_list")
                            else:
                                print("ERROR: Issue observed while updating params_list")
                                return None,summary_dict
                        else:
                            print("INFO: ScanId or TeamId passed to main() method is not valid, "
                                  "hence ignoring Kinesis part")
                        return compliance_status,summary_dict
                else:
                    proj_txt = [namespace] + ["Does not exist"] * 3
                    image_file_text = ["Does not exist"] * 9
                    print_metadata(image_file_text, proj_txt, csv_filename)
                    return None, summary_dict
        else:
            print("ERROR:URL not found")
            return None, summary_dict

        if scanid_valid and teamid_valid:
            stream_info = general_util.add_result_to_stream(session, "CAE", str(team_id), tc, params_list)
            if stream_info is None:
                raise Exception("ERROR: Issue observed while calling add_result_to_stream() API")
                return None,summary_dict
            seq_nums_list.append(stream_info)

            print("INFO: Sending result complete")
            send_result = general_util.send_result_complete(session, "CAE", scan_id, team_id, tc, seq_nums_list)
            if send_result:
                print("INFO: Successfully submitted the result to Kinesis")
            else:
                print("INFO: Failed to submit the result to Kinesis")
                return None, summary_dict
        else:
            print("INFO: ScanId or TeamId passed to main() method is not valid, hence ignoring Kinesis part")
        return flag, summary_dict

    except Exception as e:
        print("INFO: Failed to retrieve image list and pod list => %s %s" %(str(e),summary_dict))
        update = general_util.updateScanRecord(session, "CAE", scan_id, team_id, tc, "Failed")
        if update is None:
            raise Exception("ERROR: Issue observed with updateScanRecord API call")
            return None,summary_dict
        raise Exception("ERROR: Failed to fetch either Projects" % str(e))
        return None, summary_dict


def none_check(val):
    """

    :param val:
    :return:
    """
    if val is None:
        val = 'None'
    return val


def create_csv_file_headers(csv_filename):
    """

    :param csv_filename:
    :return:
    """
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
    """
    :param image:
    :return:
    """
    if re.match(r'^containers.*.cisco.com\/*', image):
        compliance_status = "Compliant"
        return compliance_status
    else:
        compliance_status = "Non-compliant"
        return compliance_status


def build_summary_report(pod_count, image_count, unsecured_image_count_total, unsecured_pod_count, unsecured_tenant_count):
    summary_dict = {'No_of_POD(s)_evaluated': pod_count,
                    'No_of_Image(s)_evaluated': image_count,
                    'No_of_Unsecured_Image(s)_found': unsecured_image_count_total,
                    'No_of_POD(s)_using_unsecured_image(s)': unsecured_pod_count,
                    'No_of_Tenants_with_unsecure_image(s)': unsecured_tenant_count}
    return summary_dict


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
    url_valid = cae_lib.cae_url_validation(url)
    if url and namespace is not None:
        if url_valid is not None:
            compliance_status, summary_report = main(url, namespace, scan_id, team_id)
            print("INFO: Process complete with compliance status as ", compliance_status, summary_report)
        else:
            print("ERROR: Failed with validation")
    else:
        print("ERROR:Need Tenant ID and domain url to run the script")

