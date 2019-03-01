#!/opt/app-root/bin/python

"""
------------------------------- common_lib.py -------------------------
Description: This python module holds the APIs commonly used across 
             other scripts in the repo.

Author: Devaraj Acharya <devaccha@cisco.com>; February 12th, 2019

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-----------------------------------------------------------------------
"""

import re


def scanid_validation(scan_id):
    """
    This method is to validate that scan id while sending the report to Kinesis.
    :param scan_id: ScanID received from AWS SQS
    """
    scanid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    if scanid_pattern.match(scan_id):
        print("LOG: Received valid ScanID")
        return True
    else:
        print("ERROR: Received ScanID is not valid")
        return False


