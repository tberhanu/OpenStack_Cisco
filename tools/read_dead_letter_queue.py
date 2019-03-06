#!/usr/bin/python
"""
-------------------------- read_dead_letter_queue.py --------------------------
Description: This python script is to read out the messages from
             Dead Letter Queue and put it in a csv file for further analysis

Prerequisite: Initialize below ENV Variables -
              1. AWS_ACCESS_KEY_ID
              2. AWS_SECRET_ACCESS_KEY
              3. AWS_REGION
              4. SQS_DEAD_LETTER_QUEUE_URL
              5. COUNT_OF_DEAD_LETTER_QUEUE_MSG
              6. DEFAULT_VISIBILITY_TIMEOUT_VALUE
Note:
 Refer csb_credentials.py.enc_[prod|nonprod] and [prod|nonprod]env_variables.py
 for value against above ENV Variables

Usage:
    python read_dead_letter_queue.py

Author: Amardeep Kumar <amardkum@cisco.com>; February 15th, 2019

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------------
"""

import boto3
import botocore
import csv
import datetime
import os
import time


def sqsclient():
    """
    Create SQS Client Handle
    :return: SQS session handle
    """
    try:
        session = boto3.session.Session(
                                        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
                                        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
                                        region_name=os.environ["AWS_REGION"]
                                       )

        sqsclient = session.client("sqs")
        return sqsclient
    except botocore.exceptions.ClientError as sess_err:
        print("ERROR: Issue with session handle creation - %s" % str(sess_err))
        return None


def poll_sqs_queue(sqsclient):
    """
    Receive message from SQS queue
    :param sqsclient:
    :return: True|False
    """
    try:
        response = sqsclient.receive_message(
                                                QueueUrl=os.environ["SQS_DEAD_LETTER_QUEUE_URL"],
                                                AttributeNames=[
                                                    'All'
                                                ],
                                                MaxNumberOfMessages=int(os.environ["COUNT_OF_DEAD_LETTER_QUEUE_MSG"]),
                                                MessageAttributeNames=[
                                                    'All'
                                                ],
                                            )
    except botocore.exceptions.ClientError as rec_err:
        print("ERROR: Issue observed while reading the message from SQS Queue: %s" % str(rec_err))
        return False

    try:
        print("Count of read message: %s" % len(response["Messages"]))
        for message in response['Messages']:
            team_name = message["MessageAttributes"]["teamname"]["StringValue"]
            test_id = message["MessageAttributes"]["testid"]["StringValue"]
            scan_id = message["MessageAttributes"]["scanid"]["StringValue"]
            tenant_id = message["MessageAttributes"]["teamid"]["StringValue"]
            url = message["MessageAttributes"]["url"]["StringValue"]
            receipt_handle = message["ReceiptHandle"]

            print("Project: %s, TeamID: %s, TestIDs: %s, URL: %s, Scan ID = %s"
                  % (tenant_id, team_name, test_id, url, scan_id))

            headers = ["Project", "Team Name", "TestID", "URL", "ScanID"]
            msg_att = [tenant_id, team_name, test_id, url, scan_id]

            date_stamp = datetime.datetime.now().strftime('%m%d%y')
            dead_letter_queue_name = os.environ["SQS_DEAD_LETTER_QUEUE_URL"].split("/")[-1]
            csv_filename = os.path.expanduser("~") + "/logs/messages_from_" + dead_letter_queue_name + "_" + date_stamp + ".csv"

            with open(csv_filename, 'a') as f:
                file_is_empty = os.stat(csv_filename).st_size == 0
                writer = csv.writer(f, lineterminator='\n')
                if file_is_empty:
                    writer.writerow(headers)
                writer.writerows([msg_att])

            try:
                sqsclient.delete_message(
                                            QueueUrl=os.environ["SQS_DEAD_LETTER_QUEUE_URL"],
                                            ReceiptHandle=receipt_handle
                                        )
                print("INFO: Response while attempting to delete the message: %s" % response)
                return True

            except botocore.exceptions.ClientError as del_err:
                print("ERROR: Failed to delete the message from SQS Queue: %s" % str(del_err))
                return False

    except KeyError as empty_msg:
        print("INFO: SQS Message received does not hold required message contents - %s" % str(empty_msg))
        return False


if __name__ == "__main__":
    counter = 0
    sqsclient_handle = sqsclient()
    if sqsclient_handle:
        while True:
            try:
                if poll_sqs_queue(sqsclient_handle):
                    time.sleep(2)
                else:
                    counter += 1
                    if counter > 20:
                        print("INFO: Breaking the loop after receiving 20 empty messages")
                        break
                    print("INFO: Waiting for %s seconds before next attempt of reading messages from SQS Queue"
                          % os.environ["DEFAULT_VISIBILITY_TIMEOUT_VALUE"])
                    time.sleep(int(os.environ["DEFAULT_VISIBILITY_TIMEOUT_VALUE"]))
            except KeyboardInterrupt as stop_signal:
                print("Received Abort signal(ctrl+c) to stop the execution - %s" % str(stop_signal))
                break
