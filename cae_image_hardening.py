"""
---------------------------- cae_image_hardening.py ----------------------------
Description : This script is meant to raise a flag if there's a

December 17th, 2018 Dharavahini Malepati <dmalepat@cisco.com>

Copyright (c) 2018 Cisco Systems
All rights reserved.
-------------------------------------------------------------------------------
"""

#!/usr/bin/env python
import requests
import pykube
import re
import argparse


def load_config(path):

    #Method to create API handle
    #:param path: holds the path to config file
    #:return: api
    
    api = pykube.HTTPClient(pykube.KubeConfig.from_file(path))
    return api

def get_pods(project_pod):

    #Method to fetch project specific POD info
    ##:param project_pod: holds project name
    #:return: pods
    
    api_handle = load_config('~/.kube/config')
    pods = pykube.Pod.objects(api_handle).filter(namespace=project_pod)
    return pods


def get_image(project_img, pod):

    #Method to get image details of application running on pod under specified project
    #:param project_img: holds project name
    #:param pod: holds pod name
    #:return: image info
    
    api = load_config('~/.kube/config')
    pod = pykube.Pod.objects(api).filter(namespace=project_img).get(name=pod)
    return pod.obj["spec"]["containers"][0]["image"]


def main(dom_url, namespace):

    #Method to raise a flag when source of image used is a non-trusted one
    #:param dom_url: just a place holder
    #:param namespace: holds the name of project
    #:return: True/False
    
    requests.packages.urllib3.disable_warnings()
    payload = {'inUserName': 'user', 'inUserPass': 'password'}
    requests.get(url, headers=payload, verify=False)

    flag = True
    pods_list = get_pods(namespace)
    for pod in pods_list:
        if re.match('containers.cisco.com\/*', get_image(namespace, pod)):
            print "Secure - %s with image: %s " % (pod, get_image(namespace, pod))
            flag = True
        else:
            print "Not Secure! - %s with image: %s " % (pod, get_image(namespace, pod))
            flag = False

    if flag:
        return True
    else:
        return False


if __name__ == '__main__':
    

    parser = argparse.ArgumentParser(description='Identify images with insecure source')
    parser.add_argument("-u", "--domain_url", help="Domain/Region specific URL", action="store", dest="url")
    parser.add_argument('-n', '--namespace', action="store", dest='project', help='name of namespace/project to Search')
    parser.add_argument('-t', '--user', action="store", dest='user', help='name of namespace/project to Search') 
    parser.add_argument('-p', '--password', action="store", dest='password', help='name of namespace/project to Search')

    args = parser.parse_args()
    url = args.url
    user = args.user
    password = args.password
    project = args.project
    main(url, project)


    main(url, project)

