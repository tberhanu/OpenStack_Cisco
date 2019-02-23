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

import os
import pykube
import re


def load_config(url):
    """
    Method to create API Handle
    :param path: holds the path to kube config file
    :return: api handle
    """
    try:
        if url is not None:
            region_name = url.split("//")[1].split(".")[0].replace("-", "_")
            if region_name is not None:
                path = os.path.expanduser("~") + "/" + "kube_config_" + region_name
            else:
                raise Exception("ERROR: Region name is None")
            api = pykube.HTTPClient(pykube.KubeConfig.from_file(path))
            return api
        else:
            print("ERROR: URL not found")
    except Exception as e:
        print("ERROR: Failed to retrieve pykube.KubeConfig.from_file path => %s" % str(e))
        return None


def cae_teamid_validation(team_id):
    """
    Method to validate the recevied teamId for a CAE Tenant
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
