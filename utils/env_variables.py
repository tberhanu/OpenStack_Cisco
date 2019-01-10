#!/opt/app-root/bin/python

"""
------------------------------- env_variables.py ------------------------------
Description : This file is meant to maintain a dictionary of env. variables
              along with their values as key-value pairs.

Author: Amardeep Kumar <amardkum@cisco.com>; January 3rd, 2019

Copyright (c) 2019 CISCO Systems.
All rights reserved.
-------------------------------------------------------------------------------
"""
import os

env_variables = {
    "SQS_URL": "https://sqs.us-east-1.amazonaws.com/283603838660/devCSBRelayQueueCAE.fifo",
    "SQS_MSG_VISIBILITY_TIMEOUT": "60",
    "CSB_CNT_REPO": "https://wwwin-github.cisco.com/CiscoIT-CSB/CiscoIT-CSB",
    "CLONED_REPO_DIR": os.path.expanduser("~") + "/",
    "OS_INTERFACE": "public",
    "OS_IDENTITY_API_VERSION": "3",
    "OS_PROJECT_DOMAIN_NAME": "cisco",
    "OS_USER_DOMAIN_NAME": "cisco",
    "MAX_LIMIT_OF_SPAWNED_CONTAINER": "20",
    "BREAKOUT_HOUR": "10",   # 1000 hrs.
    "AWS_REGION": "us-east-1",
    "AWS_ENV_TYPE": "dev",
    "COUNT_OF_SQS_READ_MSG": "1",
    "WAIT_TIME_FOR_NEXT_POLL": "60",
    "WAIT_TIME_FOR_PROJECT_LIST_SCHEDULE": "300",
    "MPROC_TIMEOUT": "120",
    "GIT_BRANCH_TO_USE": "csb_dev"  
}

if __name__ == "__main__":
    print(env_variables)
    pass
