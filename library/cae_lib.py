#!/opt/app-root/bin/python

"""
------------------------------- cae_lib.py ----------------------------
Description: This python module holds the APIs required for CAE
             platform related operations.

Author: Devaraj Acharya <devaccha@cisco.com>; February 12th, 2019

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-----------------------------------------------------------------------
"""

import errno
import os
import pykube
import re
import subprocess
import sys

sys.path.append(os.environ["CLONED_REPO_DIR"] + "/tools/supporting_files")
from landscape_of_execution import landscape


def get_kube_config_path(url):
    """
    Method to determine the path of required Kube config file w.r.t. received Cluster URL
    :param url: Cluster URL
    :return: expected path of kube config file
    """
    kc_path = os.path.expanduser("~") + "/" + "kube_config_" + url.split("//")[1].split(".")[0].replace("-", "_")
    return kc_path


def load_config(url):
    """
    Method to create API Handle
    :param path: holds the path to kube config file
    :return: api handle
    """
    try:
        if url is not None:
            path = get_kube_config_path(url)
            api = pykube.HTTPClient(pykube.KubeConfig.from_file(path))
            return api
        else:
            print("ERROR: URL not found")
    except Exception as e:
        print("ERROR: Failed to retrieve pykube.KubeConfig.from_file path => %s" % str(e))
        return None


def cae_teamid_validation(team_id):
    """
    Method to validate the received teamId for a CAE Tenant
    :param team_id:
    :return:
    """
    teamid_pattern = re.compile(r'^CAE:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    if teamid_pattern.match(team_id):
        print("LOG: Received valid TeamID")
        return True
    else:
        print("ERROR: Received TeamID is not valid")
        return False


def cae_url_validation(url):
    """
    Method to validate the received domain url
    :param url: Domain URL
    :return: True or False
    """
    cae_url_pattern = re.compile(r'(^https://cae-np-.*.cisco.com$)|(^https://cae-prd-.*.cisco.com$)')
    if cae_url_pattern.match(url):
        print("LOG: Received valid Domain URL")
        return True
    else:
        print("ERROR: Received Domain URL is not valid")
        return False


def generate_kube_config_file():
    """
    Method to generate Kube config file per CAE Cluster listed in landscape_of_execution.py file
    :return: True|False
    """
    kube_config_at_home = os.path.expanduser("~") + "/.kube/config"
    for cluster in landscape["CAE_CLUSTER"]:
        try:
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
            kube_config_rgn = get_kube_config_path(cluster)
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
