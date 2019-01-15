#!/opt/app-root/bin/python


import requests.packages.urllib3
import pykube
import re
import argparse
import os
import csv
import time
import sys
import json
from os import environ as env

sys.path.append(os.environ["CLONED_REPO_DIR"] + "/library")
from general_util import updateScanRecord, add_result_to_stream, send_result_complete, session_handle

filename = os.path.abspath(__file__).split("/")[-1].split(".py")[0]
tc = filename.replace("_", "-").upper()

def load_config(path):
    # Method to create API handle
    #:param path: holds the path to config file
    #:return: api
    try:
        print("Pulling Config from file => %s" , path)
        api = pykube.HTTPClient(pykube.KubeConfig.from_file(path))
        return api
    except Exception as e:
        print("ERROR: Failed to retrieve pykube.KubeConfig.from_file path => %s" % str(e))


def get_projects(project_name,path,flag):
    project_file_text = []
    try:
	print("LOG: Inside get_project method")
	api_handle = load_config(path)
        project_met = pykube.Namespace.objects(api_handle).get(name=project_name)
        metadata_project = project_met.obj['metadata']
        if metadata_project is not None:
            uid = metadata_project.get('uid', None)
            name = metadata_project.get('name', None)
            annotations = metadata_project.get('annotations', {})
            if annotations is not None:
                try:
                    application_id = annotations['citeis.cisco.com/application-id']
                except Exception:
                    application_id = 'None'
                try:
                    application_name = annotations['citeis.cisco.com/application-name']
                except Exception:
                    application_name='None'

            project_file_text = [name, uid, application_id, application_name]
            print("LOG: Sucessfully returning the projects")
        else:
            print("LOG: No annotations found")
    except Exception as e:
        print("ERROR: Failed to retrieve project list => %s" % str(e))

    return project_file_text


def get_pods(project_pod,path):
    # Method to fetch project specific POD info
    ##:param project_pod: holds project name
    #:return: pods
    try:
        print("LOG: Checking for POD => %s" % project_pod)
        api_handle = load_config(path)
        pods = pykube.Pod.objects(api_handle).filter(namespace=project_pod)
        if pods is not None:
            return pods
        else:
            print("No pods found")
    except Exception as e:
        print("ERROR: Failed to retrieve pods with error => %s" % str(e))
        return pods

def get_image(project_img, pod, path,flag):
    # Method to get image details of application running on pod under specified project
    #:param project_img: holds project name
    #:param pod: holds pod name
    #:return: image info
    image_data = []
    try:
        print("LOG: Listing the images in the pods in the project  => %s" % project_img)
        api = load_config(path)
        pod = pykube.Pod.objects(api).filter(namespace=project_img).get(name=pod)
        container = pod.obj['status']['containerStatuses'][0]
        image = pod.obj["spec"]["containers"][0]["image"]
        if image is not None:
            metadata = pod.obj['metadata']
            pod_name = metadata.get('name',None)
            pod_namespace = metadata.get('namespace',None)
            pod_stat = pod.obj['status']
            pod_status = pod_stat.get('phase',None)
            container_id = container.get('containerID',None)
            image_name = container.get('image',None)
            image_id = container.get('imageID',None)
            try:
                container_state = container.get('state', {}).get('running', {})
                container_start_date = container_state['startedAt']
            except Exception:
                container_start_date = 'None'
            try:
                container_exposed_port = pod.obj['spec']['containers'][0]['ports'][0]['containerPort']
            except Exception:
                container_exposed_port = 'None'
                print("Ports not found in the container")

            flag_status = flag
            image_file_text = [pod_name, pod_namespace,
                                pod_status, container_id, image_name,
                               image_id, container_start_date,
                                container_exposed_port, flag_status]
            image_data = [image, image_file_text]
            return image_data
        else:
            print("No images found")
    except Exception as e:
        print("ERROR: Failed to retrieve images with error => %s" % str(e))
        return image_data



def print_metadata(image_file_text, project_file_text):
    try:
        print("LOG: Saving the metadata into a file")
        file_content = []
        if project_file_text and image_file_text is not None:
            file_content = [project_file_text + image_file_text]
        with open('cae_image_hardening.csv', 'a') as csvFile:
            writer = csv.writer(csvFile)
            writer.writerows(file_content)
        csvFile.close()
    except Exception as e:
        print("ERROR: Failed to write the output file with error => %s" % str(e))


def build_metadata(namespace, pod, path,flag):
    try:
        print("LOG: Building the metadata into a file")
        image_values = get_image(namespace, pod, path,flag)
        image_file_text = image_values[1]
        project_file_text = get_projects(namespace, path,flag)
        print_metadata(image_file_text, project_file_text)

    except Exception as e:
        print("ERROR: Failed to build metadata with error => %s" % str(e))


def main(url,namespace,scan_id,team_id):
    # Method to raise a flag when source of image used is a non-trusted one
    #:param dom_url: just a place holder
    #:param namespace: holds the name of project
    #:return: True/False
    try:
	flag = "Compliant"
        #getting region froim the url
        if url is not None:
            url_split = url.strip().split('.')
            string = str(url_split[0])
            string_split = string.strip().split('-')
            region_name = str(string_split[2].strip())
            path = ''
            if region_name is not None:
                if region_name == "rtp":
                    path = os.path.expanduser("~") + "/" + "kube_config"
                elif region_name == "rcdn":
                    path = os.path.expanduser("~") + "/" + "kube_config"
                elif region_name == 'alln':
                    path = os.path.expanduser("~") + "/" + "kube_config"
            else:
                print("No region found")
            print("Check whether source of image used is a trusted one => ")
            requests.packages.urllib3.disable_warnings()
            pods_list = get_pods(namespace, path)
			
	    #Kinesis Update
            session = session_handle()
            if session:
                print("LOG: Update the scan record with \"InProgress\" Status")
                updateScanRecord(session, "CAE", scan_id, team_id, tc, "InProgress")
                seq_nums_list = []
                params_list = []
            
	    exists = os.path.isfile('cae_image_hardening.csv')
            if exists:
                print("CSV file is available to read  => ")
                with open('cae_image_hardening.csv', 'r') as csvFile:
                    reader = csv.reader(csvFile, delimiter=",")
                    data = list(reader)
                    row_count = len(data)
                csvFile.close()
            else:
                print("CSV file is not available to read, writing new file  => ")
                row_count = 0
            file_headers = ['Tenant Name', 'Tenant ID', 'Application ID', 'Application Name', 'Pod Name',
                            'Pod Namespace',
                            'Pod Namespace', 'Container ID', 'Image Name', 'Image ID', 'Container Start Date',
                            'Container Exposed Port ','Flag']
            file_content = [file_headers]
            if row_count <= 0:
                with open('cae_image_hardening.csv', 'a') as csvFile:
                    writer = csv.writer(csvFile)
                    writer.writerows(file_content)
                csvFile.close()
            if pods_list is not None:
                for pod in pods_list:
                    flag = ''
                    image_data = get_image(namespace, pod, path,flag)
                    if image_data is not None:
                        image = image_data[0]
                        if re.match('containers.cisco.com\/*', image):
                            compliance_status = "Compliant"
                            print("Secure - %s with image: %s " % (pod, image))
                            build_metadata(namespace, pod, path,flag)
                        else:
                            compliance_status = "Non-compliant"
			    flag = "Non-compliant"
                            print("Not Secure! - %s with image: %s " % (pod, image))
                            build_metadata(namespace, pod, path,flag)
		    #Kinesis Update
                    audit_time = int(time.time()) * 1000
                    params = {
                         "scanid": scan_id,
                         "testid": tc,
                         "teamid": str(team_id),
                         "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, str(pod)),
                         "createdAt": audit_time,
                         "updatedAt": audit_time,
                         "resourceName": str(pod),
                         "complianceStatus": compliance_status,
                        }
                    params_list.append(params.copy())

                    while sys.getsizeof(json.dumps(params_list)) >= 900000:
                        print("LOG: FIRST ELEMENT OF PARAMS LIST: ", params_list[0])
                        stream_info = add_result_to_stream(session, "CAE", str(team_id), tc, params_list)
                        seq_nums_list.append(stream_info)

                #Kinesis Update
                print("LOG: Adding result to Stream")
                stream_info = add_result_to_stream(session, "CAE", str(team_id), tc, params_list)
                seq_nums_list.append(stream_info)
                print("LOG: Sending result complete")
                send_result_complete(session, "CAE", scan_id, team_id, tc, seq_nums_list)
				
            else:
                print("No Pods running in the project")
	return flag
    except Exception as e:
        print("ERROR: Failed to retrieve image list and pod list with error => %s" % str(e))
	print("LOG: Update the scan record with \"Failed\" Status")
        updateScanRecord(session, "CAE", scan_id, team_id, tc, "Failed")
	return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Identify images with insecure source')
    parser.add_argument("-u", "--domain_url", help="Domain/Region specific URL", action="store", dest="domain_url")
    parser.add_argument('-t', '--namespace', action="store", dest='namespace', help='name of namespace/project to Search')
    parser.add_argument("-s", "--scan_id", help="OpenStack Horizon URL", action="store", dest="scanid")
    parser.add_argument("-i", "--team_id", help="Project/Tenant ID", action="store", dest="teamid")

    args = parser.parse_args()
    url = args.domain_url
    namespace = args.namespace
    scan_id = args.scanid
    team_id = args.teamid
    compliant_status = main(url, namespace,scan_id,team_id)
    print(compliant_status)
