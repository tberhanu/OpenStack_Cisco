#!/usr/bin/python

"""
-------------------------------csb_relay.py------------------------------
Description: This python script is to read messages from
             AWS SQS Queue created for CNT-CSB, process the
             required information and pass it on to CAE for spawning
             execution environment over containers.

Dependencies:
    csb_credentials.py.enc
    env_variables.py

Author: Amardeep Kumar <amardkum@cisco.com>; December 19th, 2018

Copyright (c) 2018 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------
"""


import boto3
import botocore
import git
import json
import multiprocessing
import os
import shutil
import struct
import sys
import time

from Crypto.Cipher import AES
from env_variables import env_variables
from general_util import add_result_to_stream, updateScanRecord, send_result_complete
from importlib import import_module


def decrypt_file(key, in_filename):
    """
    Decrypts a file using AES(CBC mode) with the given key.
    :param key: key to be used for decryption
    :param in_filename: name of encrypted file
    :return: decrypted file
    """
    out_filename = os.path.splitext(in_filename)[0]
    chunk_size = 64*1024
    try:
        print("Decrypt %s file" % in_filename)
        with open(in_filename, 'rb') as infile:
            orig_size = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, iv)
            try:
                with open(out_filename, 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunk_size)
                        if len(chunk) == 0:
                            break
                        outfile.write(decryptor.decrypt(chunk))

                    outfile.truncate(orig_size)
            except IOError:
                print("ERROR: Failed to create the decrypted file %s" % out_filename)
    except IOError:
        print("ERROR: File %s was not accessible" % in_filename)

    if os.path.isfile(out_filename):
        return True
    else:
        return False

def sqs_client_handle():
    """
    This method is meant to create a communication handle to AWS SQS Queue
    :return: handle to sqs queue
    """
    try:
        print("Create SQS Client Handle")
        session = boto3.session.Session(aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"], aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"], region_name=os.environ["SQS_URL"].split(".")[1])
        sqsclient_handle = session.client("sqs")
        return sqsclient_handle
    except Exception as err:
        print("ERROR: Failed to create sqs client handle with error: %s" % str(err))


def read_message_from_sqs(sqsclient, count_of_message_to_read):
    """
    This method is to read the message from SQS Queue
    :param sqsclient: sqs handle
    :param count_of_message_to_read: no. of messages expected per poll
    :return: batch of message received from SQS Queue
    """
    try:
        print("Read message from SQS")
        response = sqsclient.receive_message(
                                                QueueUrl=os.environ["SQS_URL"],
                                                AttributeNames=[
                                                    'All'
                                                ],
                                                MaxNumberOfMessages=count_of_message_to_read,
                                                MessageAttributeNames=[
                                                    'All'
                                                ],
                                                VisibilityTimeout=int(os.environ["SQS_MSG_VISIBILITY_TIMEOUT"])
                                            )
    except botocore.exceptions.ClientError as sqs_rec_msg_err:
        print("ERROR: Issue observed while reading messages from SQS Queue: %s" % str(sqs_rec_msg_err))

    return response


def clone_git_repo():
    try:
        print("Clone GIT Repo")
        if os.path.isdir(os.environ["CLONED_REPO_DIR"]):
            shutil.rmtree(os.environ["CLONED_REPO_DIR"])
        tcp_protocol, git_url = os.environ["CSB_CNT_REPO"].split("//")
        git_repo_url = tcp_protocol + "//" + os.environ["GITHUB_TOKEN_CSBAUDITOR_GEN"] + "@" + git_url
        git.Repo.clone_from(git_repo_url, os.environ["CLONED_REPO_DIR"])
    except git.exc.GitCommandError as err_clone:
        print("ERROR: Git Clone failed; %s" % str(err_clone))


def process_messages(messages):
    """
    This method is initiate the execution per team/per message
    :param messages: batch of message(s) received from SQS Queue
    :return: None
    """
    print("Process the messages read from SQS")
    processes = list()
    # for message in messages["Messages"]:
    for message in messages:
        team_name, team_id, test_id, url, scan_id, receipt_handle = retrieve_details(message)
        print("Project: %s, TeamID: %s, TestIDs: %s, URL: %s, Scan ID = %s, Receipt Handle: %s" % (team_name, team_id, test_id, url, scan_id, receipt_handle))
        try:
            """ New process will be initiated per message/team """
            print("Start the execution of Audit test-scripts per team")
            proc = multiprocessing.Process(target=audit_project, args=(team_id, team_name, test_id, url, scan_id, receipt_handle))
            processes.append(proc)
            proc.start()

            for one_process in processes:
                one_process.join()

        except Exception as e:
            print("ERROR: Multiprocessing failed for TeamId-TeamName => %s-%s due to %s" % (team_id, team_name, str(e)))


def retrieve_details(msg):
    """
    This method is to retrieve individual information available per message
    :param msg: one message dump from SQS Queue
    :return: team_name, team_id, test_id, url, scan_id, receipt_handle
    """
    print("Retrieve individual information available per message")
    team_name = msg["MessageAttributes"]["teamname"]["StringValue"]
    test_id = msg["MessageAttributes"]["testid"]["StringValue"]
    scan_id = msg["MessageAttributes"]["scanid"]["StringValue"]
    team_id = msg["MessageAttributes"]["teamid"]["StringValue"]
    url = msg["MessageAttributes"]["url"]["StringValue"]
    receipt_handle = msg["ReceiptHandle"]

    return team_name, team_id, test_id, url, scan_id, receipt_handle


def audit_project(team_id, team_name, test_id, url, scan_id, receipt_handle):
    """
    This method will spawn new container per team, for executing the related audit test-cases
    For now, calling the execution from within this script
    :param team_id:
    :param team_name:
    :param test_id:
    :param url:
    :param scan_id:
    :param receipt_handle:
    :return: None
    """
    print("Execute individual Audit test-scripts for the team: %s" % team_name)
    """ Update the scan record with \"InProgress\" Status """
    # updateScanRecord(team_name.split(":")[0], scan_id, team_id, test_id, "InProgress")

    audit_test_list = test_id.split(",")
    results = dict()
    seq_nums_list = []
    for tc in audit_test_list:
        """ Translating TC name to fetch the respective audit script name """
        audit_tc_script = tc.replace("-", "_").lower()
        print(audit_tc_script)
        if os.path.isfile(audit_tc_script + ".py"):
            tc_script = import_module(audit_tc_script)
            audit_time = int(time.time()) * 1000
            try:
                results[audit_tc_script] = tc_script.main(url, team_name.split(":")[1])
                params_list = []
                # params = {
                #             "scanid": scan_id,
                #             "testid": tc,
                #             "name": item['name'],
                #             "teamid": str(team_id),
                #             "teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc, item['id']),
                #             "createdAt": audit_time,
                #             "updatedAt": audit_time,
                #             "instanceid": item['id'],
                #             "resourceName": item['id'],
                #             "complianceStatus": results[audit_tc_script],
                #           }
                # params_list.append(params.copy())

                # while sys.getsizeof(json.dumps(params_list)) >= 900000:
                #     print("FIRST ELEMENT OF PARAMS LIST: ", params_list[0])
                #     stream_info = add_result_to_stream(team_name.split(":")[0], str(team_id), tc, params_list)
                #     seq_nums_list.append(stream_info)

            except Exception as e:
                print("ERROR: Failed read the result from execution => %s" % str(e))
        else:
            results[audit_tc_script] = "Script is not available"
            raise Exception("ERROR: Required Test-Script is not available")
    print("Execution result for Team: %s \n%s" % (team_name, results))

    # send_result_complete(team_name.split(":")[0], scan_id, team_id, test_id, "ResultComplete", seq_nums_list)

    # delete_msg_from_sqs(receipt_handle)

def delete_msg_from_sqs(receipt_handle):
    """
    This method is meant to delete received message from SQS queue w.r.t. the Receipt handle
    :param receipt_handle: Receipt handle associated with the message meant for deletion
    :return: None
    """
    print("Delete message from SQS")
    try:
        response = sqsclient.delete_message(
                                             QueueUrl=os.environ["SQS_URL"],
                                             ReceiptHandle=receipt_handle
                                            )
    except botocore.exceptions.ClientError as del_err:
        print("ERROR: Failed to delete the message from SQS Queue: %s" % str(del_err))


if __name__ == '__main__':

    """ Key to decrypt the encrypted files required for CSB Audit """
    key = os.environ["KEY"]

    """ Decrypt the kube config file """
    if decrypt_file(key, "kube_config.enc"):
        print("Successfully decrypted Kube Config file")
    else:
        raise Exception("ERROR: Failed to decrypt \"kube_config.enc\" file")

    """ Decrypt credentials file. Then set environment variables w.r.t. required set of credentials  """
    if decrypt_file(key, "csb_credentials.py.enc"):
        cred_file = import_module("csb_credentials")
        for var, val in cred_file.csb_credentials.items():
            os.environ[var] = val
    else:
        raise Exception("ERROR: Failed to decrypt \"csb_credentials.py.enc\" file")

    """ Setting environment variables required for execution of CBS-CNT related scripts """
    for var, val in env_variables.items():
        os.environ[var] = val

    """ Get the connection handle to AWS SQS """
    sqsclient = sqs_client_handle()

    """ Read messages from AWS SQS """
    try:
        count_of_message_read = 0
        list_of_msgs_from_sqs = list()
        while count_of_message_read != int(os.environ["COUNT_OF_SQS_READ_MSG"]):
            messages_from_sqs = read_message_from_sqs(sqsclient, int(int(os.environ["COUNT_OF_SQS_READ_MSG"]) - count_of_message_read))
            list_of_msgs_from_sqs.extend(messages_from_sqs["Messages"])
            count_of_message_read = count_of_message_read + len(messages_from_sqs["Messages"])

            time.sleep(3)

        # print(len(list_of_msgs_from_sqs))
        # print(list_of_msgs_from_sqs)
    except Exception as err:
        print("ERROR: Failed to fetch the required no. of SQS messages: %s" % str(err))

    """ Clone Git Repo for the audit test-scripts """
    clone_git_repo()

    """ Initiate processing of the messages received from SQS """
    process_messages(list_of_msgs_from_sqs)

    """ Delete the decrypted files """
    # os.remove(os.path.expanduser("~") + "/" + "csb_credentials.py")
    # os.remove(os.path.expanduser("~") + "/" + "kube_config")
    os.remove("csb_credentials.py")
    os.remove("kube_config")

    """ Exit Gracefully """
    # API call for the container to exit gracefully
