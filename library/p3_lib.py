#!/opt/app-root/bin/python

"""
------------------------------- p3_lib.py -----------------------------
Description: This python module holds the APIs required for p3 platform
             related operations.

Author: Devaraj Acharya <devaccha@cisco.com>; February 12th, 2019

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-----------------------------------------------------------------------
"""

import openstack
import re
import os
from os import environ as env


def p3_teamid_validation(team_id):
    """
    This method is to validate that team id of the P3 platform while sending the report to Kinesis.
    :param team_id: TeamID
    """
    teamid_pattern = re.compile(r'^P3:[0-9a-f]{32}$')
    if teamid_pattern.match(team_id):
        print("LOG: Received valid TeamID")
        return True
    else:
        print("ERROR: Received TeamID is not valid")
        return False


def p3_url_validation(url):
    """
    This method is to validate the authorized url of the P3 platform.
    :url: OpenStack's Horizon URL
    """
    p3_url_pattern = re.compile(r'^https://cloud-.*-1.cisco.com:5000/v3$')
    if p3_url_pattern.match(url):
        print("LOG: Received valid Domain URL")
        return True
    else:
        print("ERROR: Received Domain URL is not valid")
        return False


def connect(os_auth_url, project_name, region):
    """
    
    :param os_auth_url:
    :param project_name:
    :param region:
    :return:
    """
    try:
        print("LOG: Creating Connection handle to OpenStack Project - %s" % project_name)
        conn = openstack.connect(
            auth_url=os_auth_url,
            project_name=project_name,
            username=env['OS_USERNAME'],
            password=env['OS_PASSWORD'],
            region_name=region
        )
        return conn
    except Exception as e:
        print("ERROR: Connection failed with error => %s" % str(e))
        return None

