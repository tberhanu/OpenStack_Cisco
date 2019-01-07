#!/usr/bin/python

"""
--------------------------- general_util.py ---------------------------
Description: This python script holds the APIs required to post
             test-results to AWS Kinesis Stream

Author: Sudip Das <sudipda@cisco.com>; January 7th, 2019

Copyright (c) 2018 Cisco Systems.
All rights reserved.
-----------------------------------------------------------------------
"""

import boto3
import botocore
import datetime
import time
import os
import sys
import json
import decimal

from datetime import date


def add_result_to_stream(platform, teamid, testid, params_list):
    """
    Function add_result_data_stream to ResultStream<platform suffix e.g. CAE, P3>
        params_list is a list of dictionary the pattern params below
        **As of now params is required to have only scanid and teamid-testid-resourceName **
        ** but this may change to include all mentioned below which are maintained at test**
        params = {
           'scanid':"<scanid same as in SQS queue>", Required
           'testid':"<audit testid in SQS, if you have multiple subtests with the same testid
                   you can still separate those in Results table
                   by using a format testid:subtestid>",
           'teamid':"<teamid same as in SQS queue>",
           'resourceName':"<resourceName that will identify your resource uniquely as well as separate the record>",
           'teamid-testid-resourceName':"<concatenation of teamid-testid-resourceName above>",
           'createdAt':<value taken as audit_time = int(time.time()) * 1000>,
           'updatedAt':<value in the same form as audit_time = int(time.time()) * 1000>
           }

    Every params goes to dynamoDB as record and has size restriction
    per https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Limits.html
    There are other restriction as dynamoDB key can not have null value

    os.environ['ENV_TYPE'] should return blank for production as "".

    :param platform:
    :param teamid:
    :param testid:
    :param params_list: list of dictionary the pattern params below
    :return:
    """
    sortKey = "{}-{}".format(teamid, testid)
    """
    Validate size and params_list for keys pertaining to Results DB and raise exception if not.
    Kinesis stream record limit is 1 MiB
    """
    if sys.getsizeof(json.dumps(params_list)) > 1000000:
        raise Exception("CSBError: params_list exceeds the allowed size of 1 MB")
    for params in params_list:
        if 'scanid' not in params:
            raise Exception("CSBError: params_list contains params with missing partition key for resultDB")
        if 'teamid-testid-resourceName' not in params:
            raise Exception("CSBError: params_list contains params with missing sort key for resultDB")

    """
    Not having region name will make the service fail when there is no default region in config file
    Since this is a common code CSB deployment region us-east-1 is used not impacting any audit-tests
    """
    kinesis_client = boto3.client('kinesis', region_name='us-east-1')
    try:
        response = kinesis_client.put_record(
                                                StreamName=os.environ['ENV_TYPE']+"ResultStream"+platform,
                                                Data=json.dumps(params_list, cls=CustomEncoder),
                                                PartitionKey=sortKey
                                            )
    except Exception as add_result_err:
        print("ERROR: Record posting on Kinesis Stream failed due to %s" % str(add_result_err))

    """ sequence number and shard id to validate later in results stream lambda """
    stream_info = {"shard_id": response['ShardId'], "seq_num": response["SequenceNumber"]}
    return stream_info


def updateScanRecord(platform, scanid, teamid, testid, status):
    """
    update scan records

    :param platform: name of platform
    :param scanid: scanid received while reading SQS message
    :param teamid: teamid received while reading SQS message
    :param testid: testid received while reading SQS message
    :param status:
    :return:
    """
    timeStamp = int(time.time() * 1000)
    sortKey = "{}-{}".format(teamid, testid)
    kinesis_client = boto3.client('kinesis')
    value = {
            "id": scanid,
            "scanStatus": status,
            "teamid": teamid,
            "teamid-testid": sortKey,
            "updatedAt": timeStamp
            }
    try:
        response = kinesis_client.put_record(
                                                StreamName=os.environ['ENV_TYPE']+"ScanStream"+platform,
                                                Data= json.dumps(value, cls=CustomEncoder),
                                                PartitionKey=sortKey
                                            )
    except Exception as update_record_err:
        print("ERROR: Record posting on Kinesis Stream failed due to %s" % str(update_record_err))

    return response


def send_result_complete(platform, scanid, teamid, testid, seq_nums_list):
    """
    The function send_result_complete needs to be called only once for a testid i.e. the testid main audit test
    to send status to ScanStream with list of sequence numbers and shard id for results data
    ****example code how it can be called *******************************
    seq_nums_list = [] # list of sequence numbers for result data in ResultStream
    other codes related to audit test#######
    stream_info = add_result_to_stream(platform, teamid, <testid or testid:subtest>, params_list)
    seq_nums_list.append(stream_info)
    send_result_complete(platform, scanid, teamid, testid, "ResultComplete", seq_nums_list)
    **** end of example code *****************
    :param platform:
    :param scanid:
    :param teamid:
    :param testid:
    :param seq_nums_list:
    :return:
    """
    sortKey = "{}-{}".format(teamid, testid)
    timeStamp = int(time.time() * 1000)
    kinesis_client = boto3.client('kinesis')
    value = {
            "id": scanid,
            "scanStatus": "ResultComplete",
            "teamid": teamid,
            "teamid-testid": sortKey,
            "seq_list":seq_nums_list,
            "updatedAt": timeStamp
            }
    try:
        response = kinesis_client.put_record(
            StreamName=os.environ['ENV_TYPE']+"ScanStream"+platform,
            Data= json.dumps(value, cls=CustomEncoder),
            PartitionKey=sortKey
        )
    except Exception as send_result_err:
        print("ERROR: Record posting on Kinesis Stream failed due to %s" % str(send_result_err))

    return response


class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            return int(obj)
        elif isinstance(obj, (datetime.datetime, date)):
            return obj.isoformat()
        return super(CustomEncoder, self).default(obj)
