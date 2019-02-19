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
    "AWS_REGION": "us-east-1",
    "AWS_SERVICE": "execute-api",
    "AWS_ENV_TYPE": "dev",
    "AWS_EXECUTE_API_URL": "https://n98uo7cw6i.execute-api.us-east-1.amazonaws.com/devStaging/teams",
    "AWS_CANONICAL_URI": "/devStaging/teams",
    "COUNT_OF_SQS_READ_MSG": "1",
    "SQS_URL": "https://sqs.us-east-1.amazonaws.com/283603838660/devCSBRelayQueueCAE",
    "SQS_DEAD_LETTER_QUEUE_URL": "https://sqs.us-east-1.amazonaws.com/283603838660/devCSBDeadLetterQueueCAE",
    "SQS_MSG_VISIBILITY_TIMEOUT": "600",

    "AUDIT_SCRIPTS_DIR": os.path.expanduser("~") + "/csb_cnt_repo/audit_scripts",
    "CLONED_REPO_DIR": os.path.expanduser("~") + "/csb_cnt_repo",
    "LOGS_DIR": os.path.expanduser("~") + "/logs",
    "CSB_CNT_REPO": "https://wwwin-github.cisco.com/CiscoIT-CSB/CiscoIT-CSB",
    "GIT_BRANCH_TO_USE": "csb_dev",

    "OS_INTERFACE": "public",
    "OS_IDENTITY_API_VERSION": "3",
    "OS_PROJECT_DOMAIN_NAME": "cisco",
    "OS_USER_DOMAIN_NAME": "cisco",

    "MPROC_TIMEOUT": "180",
    "WAIT_TIME_FOR_NEXT_POLL": "60",
    "WAIT_TIME_FOR_PROJECT_LIST_SCHEDULE": "86400",
}

if __name__ == "__main__":
    print(env_variables)
    pass
