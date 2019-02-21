#!/opt/app-root/bin/python

"""
-------------------------- landscape_of_execution.py ---------------------------
Description : This file is meant to maintain the list of web urls that
              constitutes CiscoIT-CSB's execution landscape.

Author: Amardeep Kumar <amardkum@cisco.com>; February 20nd, 2019

Copyright (c) 2019 CISCO Systems.
All rights reserved.
--------------------------------------------------------------------------------
"""

landscape = {
    "P3_HORIZON": {
            "https://cloud-alln-1.cisco.com",
            "https://cloud-rcdn-1.cisco.com",
            "https://cloud-rtp-1.cisco.com"
    },
    "CAE_CLUSTER": {
            "https://cae-np-alln.cisco.com",
            "https://cae-np-rcdn.cisco.com",
            "https://cae-np-rtp.cisco.com"
    }
}

if __name__ == "__main__":
    print(landscape)
    pass
