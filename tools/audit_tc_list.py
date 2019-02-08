#!/opt/app-root/bin/python

"""
------------------------------- audit_tc_list.py ------------------------------
Description : This file is meant to maintain a dictionary of
              audit tc tags per platform - P3 and CAE.

Author: Amardeep Kumar <amardkum@cisco.com>; February 1st, 2019

Copyright (c) 2019 CISCO Systems.
All rights reserved.
-------------------------------------------------------------------------------
"""

audit_tc_list = {
    "P3": {
            "P3-IDENTITY-MGMT-TC-1",
            "P3-IMAGE-HARDENING-TC-1",
    },
    "CAE" : {
            "CAE-IDENTITY-MGMT-TC-1",
            "CAE-IMAGE-HARDENING-TC-1",
    }
}

if __name__ == "__main__":
    print(audit_tc_list)
    pass
