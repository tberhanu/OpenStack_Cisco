#!/opt/app-root/bin/python

"""
---------------------------- csb_auditor.py ------------------------------
Description: This python script is to
			 a. decrypt the requried encrypted file(s)
             b. clone git repo
             c. create connection handle to SQS Queue
             d. read messages from SQS Queue created for CNT-CSB
             e. process the required information
             f. pass the information to audit test-script
             g. consolidate results from each audit test-script per team
             h. post the result to kinesis
             i. delete message from SQS Queue

Dependencies:
    csb_credentials.py.enc
    env_variables.py
    kube_config.enc

Author: Amardeep Kumar <amardkum@cisco.com>; December 19th, 2018

Copyright (c) 2018 Cisco Systems.
All rights reserved.
--------------------------------------------------------------------------
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
    :return: generated decrypted file and return TRUE/FALSE
    """
    out_filename = os.path.splitext(in_filename)[0]
    chunk_size = 64*1024
    try:
        print("LOG: Decrypt %s file" % in_filename)
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
        print("LOG: Decrypted File is available for use")
        return True
    else:
        print("ERROR: Decrypted File is not available for use")
        return False


def sqs_client_handle():
    """
    This method is meant to create a communication handle to AWS SQS Queue
    :return: handle to sqs queue or None
    """
    try:
        print("LOG: Create SQS Client Handle")
        region = os.environ["SQS_URL"].split(".")[1]
        session = boto3.session.Session(aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"], aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"], region_name=region)
        sqsclient_handle = session.client("sqs")
        return sqsclient_handle
    except botocore.exceptions.ClientError as boto_err:
        print("ERROR: Failed to establish connection with AWS SQS Queue - %s" % str(boto_err))
        return None
    except botocore.executions.ParamValidationError as param_err:
        print("ERROR: Parameter validation error: %s" % param_err)
    except Exception as err:
        print("ERROR: Failed to create sqs client handle with error: %s" % str(err))
        return None


def read_message_from_sqs(sqsclient):
    """
    This method is to read the message from SQS Queue
    :param sqsclient: sqs handle
    :return: batch of message(s) received from SQS Queue or None
    """
    response = None
    try:
        print("INFO: Read message from SQS")
        while True:
            try:
                response = sqsclient.receive_message(
                                                        QueueUrl=os.environ["SQS_URL"],
                                                        AttributeNames=[
                                                            'All'
                                                        ],
                                                        MaxNumberOfMessages=int(os.environ["COUNT_OF_SQS_READ_MSG"]),
                                                        MessageAttributeNames=[
                                                            'All'
                                                        ],
                                                        VisibilityTimeout=int(os.environ["SQS_MSG_VISIBILITY_TIMEOUT"])
                                                    )
                if response.get("Messages", None):
                    break
                else:
                   print("INFO: Attempt to read message from SQS didn't get any.")
                   print("INFO: Waiting for %s secs. before re-polling SQS Queue" % os.environ["WAIT_TIME_FOR_NEXT_POLL"])
                   time.sleep(int(os.environ["WAIT_TIME_FOR_NEXT_POLL"]))
            except botocore.exceptions.ClientError as sqs_rec_msg_err:
                print("ERROR: Issue observed while reading messages from SQS Queue: %s" % str(sqs_rec_msg_err))
                response = None
                break

    except Exception as read_err:
        print("ERROR: Issue observed while reading messages from SQS - %s" % str(read_err))

    return response


def clone_git_repo():
    """
    This method is to clone the GIT Repo holding audit test-scripts
    :return: True|False
    """
    try:
        print("LOG: Clone GIT Repo")
        if os.path.isdir(os.environ["CLONED_REPO_DIR"]):
            shutil.rmtree(os.environ["CLONED_REPO_DIR"])
        tcp_protocol, git_url = os.environ["CSB_CNT_REPO"].split("//")
        git_repo_url = tcp_protocol + "//" + os.environ["GITHUB_TOKEN_CSBAUDITOR_GEN"] + "@" + git_url
        git.Repo.clone_from(git_repo_url, os.environ["CLONED_REPO_DIR"])
        return True
    except git.exc.GitCommandError as err_clone:
        print("ERROR: Git Clone failed; %s" % str(err_clone))
        return False

def process_messages(messages):
    """
    This method is initiate the execution per team/per message
    :param messages: batch of message(s) received from SQS Queue
    :return: None
    """
    print("LOG: Process the messages read from SQS")
    processes = list()
    try:
        for message in messages["Messages"]:
            team_name, team_id, test_id, url, scan_id, receipt_handle = retrieve_details(message)
            print("Project: %s, TeamID: %s, TestIDs: %s, URL: %s, Scan ID = %s, Receipt Handle: %s" % (team_name, team_id, test_id, url, scan_id, receipt_handle))
            try:
                """ New process will be initiated per message/team """
                print("LOG: Start the thread for execution of Audit test-scripts per team")
                proc = multiprocessing.Process(target=audit_project, args=(team_id, team_name, test_id, url, scan_id, receipt_handle))
                processes.append(proc)
                proc.start()

                for one_process in processes:
                    one_process.join()

            except Exception as e:
                print("ERROR: Multiprocessing failed for TeamId-TeamName => %s-%s due to %s" % (team_id, team_name, str(e)))
    except KeyError:
        print("ERROR: Message received does not hold right set of info")


def retrieve_details(msg):
    """
    This method is to retrieve individual information available per message
    :param msg: one message dump from SQS Queue
    :return: team_name, team_id, test_id, url, scan_id, receipt_handle
    """
    print("LOG: Retrieve individual information available per message")
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
    print("LOG: Execute individual Audit test-scripts per team: %s" % team_name)
    region = os.environ["SQS_URL"].split(".")[1]
    session = boto3.session.Session(aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"], aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"], region_name=region)


    audit_test_list = test_id.split(",")
    results = dict()
    for tc in audit_test_list:
        """ Translating TC name to fetch the respective audit script name """
        audit_tc_script = tc.replace("-", "_").lower()
        print("LOG: Script under execution - %s" % audit_tc_script)
        """ Update the scan record with \"InProgress\" Status """
        updateScanRecord(session, team_id.split(":")[0], scan_id, team_id, tc, "InProgress")

        seq_nums_list = []
        if os.path.isfile(audit_tc_script + ".py"):
            tc_script = import_module(audit_tc_script)
            audit_time = int(time.time()) * 1000
            counter = 0
            try:
                results[audit_tc_script] = tc_script.main(url, team_name)
                params_list = []
                params = {
                             "scanid": scan_id,
                             "testid": tc,
                             "teamid": str(team_id),
                             #"teamid-testid-resourceName": "{}-{}-{}".format(str(team_id), tc),
                             "teamid-testid": "{}-{}".format(str(team_id), tc),
                             "createdAt": audit_time,
                             "updatedAt": audit_time,
#                             "resourceName": item['id'],
                             "complianceStatus": results[audit_tc_script],
                           }
                params_list.append(params.copy())

                print(params_list)
                while sys.getsizeof(json.dumps(params_list)) >= 900000:
                    print("LOG: FIRST ELEMENT OF PARAMS LIST: ", params_list[0])
                    stream_info = add_result_to_stream(session, team_name.split(":")[0], str(team_id), tc, params_list)
                    seq_nums_list.append(stream_info)

                send_result_complete(session, team_id.split(":")[0], scan_id, team_id, tc, seq_nums_list)
            except Exception as e:
                print("ERROR: Failed read the result from execution => %s" % str(e))
        else:
            results[audit_tc_script] = "Script is not available"
            raise Exception("ERROR: Required Test-Script is not available")
    print("LOG: Execution result for Team: %s \n%s" % (team_name, results))


    delete_msg_from_sqs(receipt_handle)

def delete_msg_from_sqs(receipt_handle):
    """
    This method is meant to delete received message from SQS queue w.r.t. the Receipt handle
    :param receipt_handle: Receipt handle associated with the message meant for deletion
    :return: None
    """
    print("LOG: Delete message from SQS")
    try:
        sqsclient = sqs_client_handle()
        response = sqsclient.delete_message(
                                             QueueUrl=os.environ["SQS_URL"],
                                             ReceiptHandle=receipt_handle
                                            )
    except botocore.exceptions.ClientError as del_err:
        print("ERROR: Failed to delete the message from SQS Queue: %s" % str(del_err))


def main():
    """ Key to decrypt the encrypted files required for CSB Audit """
    #key = os.environ["KEY"]
    key = "1329ebbc1b9646b890202384beaef2ec"

    """ Decrypt the kube config file """
    if decrypt_file(key, "kube-config.enc"):
        print("INFO: Successfully decrypted Kube Config file")
    else:
        raise Exception("ERROR: Failed to decrypt \"kube_config.enc\" file")

    """ Decrypt credentials file. Then set environment variables w.r.t. required set of credentials  """
    if decrypt_file(key, "csb_credentials.py.enc"):
        print("INFO: Successfully decrypted Credential file")
        cred_file = import_module("csb_credentials")
        for var, val in cred_file.csb_credentials.items():
            os.environ[var] = val
    else:
        raise Exception("ERROR: Failed to decrypt \"csb_credentials.py.enc\" file")

    """ Setting environment variables required for execution of CBS-CNT related scripts """
    print("INFO: Set all required variables as part of ENV")
    for var, val in env_variables.items():
        os.environ[var] = val

    """ Clone Git Repo for the audit test-scripts """
    if clone_git_repo():
        """ Get the connection handle to AWS SQS """
        sqsclient = sqs_client_handle()
        if sqsclient:
            """ Read messages from AWS SQS """
            msg_from_sqs = read_message_from_sqs(sqsclient)
            if msg_from_sqs:
                """ Initiate processing of the messages received from SQS """
                process_messages(msg_from_sqs)
        else:
            print("ERROR: Failed to get SQS Handle")

    """ Delete the decrypted files """
    print("INFO: Delete decrypted Credential file")
    os.remove(os.path.expanduser("~") + "/" + "csb_credentials.py")
    os.remove(os.path.expanduser("~") + "/" + "csb_credentials.pyc")
    print("INFO: Delete decrypted kube_config file")
    os.remove(os.path.expanduser("~") + "/" + "kube-config")


if __name__ == '__main__':
    main()
