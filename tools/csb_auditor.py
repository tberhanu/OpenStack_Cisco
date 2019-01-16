#!/opt/app-root/bin/python

"""
---------------------------- csb_auditor.py ------------------------------
Description: This python script is to
                a. decrypt the required encrypted file(s)
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
import multiprocessing
import os
import shutil
import struct
import time

from Crypto.Cipher import AES
from env_variables import env_variables
from importlib import import_module


def decrypt_file(in_filename):
    """
    Decrypts a file using AES(CBC mode) with the given key.
    :param in_filename: name of encrypted file
    :return: generate decrypted file and return TRUE/FALSE
    """
    """ Key to decrypt the encrypted files required for CSB Audit """
    key = "1329ebbc1b9646b890202384beaef2ec"
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
    print("INFO: Read message from SQS")
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
        return response
    except botocore.exceptions.ClientError as sqs_rec_msg_err:
        print("ERROR: Issue observed while reading messages from SQS Queue: %s" % str(sqs_rec_msg_err))
        return None


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
        repo = git.Repo.clone_from(git_repo_url, os.environ["CLONED_REPO_DIR"])
        repo.git.checkout(os.environ["GIT_BRANCH_TO_USE"])
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
    if "Messages" in messages:
        for message in messages["Messages"]:
            team_name, team_id, test_id, url, scan_id, receipt_handle = retrieve_details(message)
            print("Project: %s, TeamID: %s, TestIDs: %s, URL: %s, Scan ID = %s, Receipt Handle: %s" % (team_name, team_id, test_id, url, scan_id, receipt_handle))
            try:
                """ New process will be initiated per message/team """
                print("LOG: Start the thread for execution of Audit test-scripts per team")
                proc = multiprocessing.Process(target=audit_project, args=(team_id, team_name, test_id, url, scan_id, receipt_handle))
                processes.append(proc)
                proc.start()
            except Exception as e:
                print("ERROR: Message processing failed for TeamId-TeamName => %s-%s due to %s" % (team_id, team_name, str(e)))

        try:
            for one_process in processes:
                one_process.join(int(os.environ["MPROC_TIMEOUT"]))
        except multiprocessing.TimeoutError as proc_err:
            print("ERROR: Execution of audit_project\(\) for team %s took more time than expected - %s" % (team_name, str(proc_err)))

    else:
        print("LOG: There was no message available for processing")


def retrieve_details(msg):
    """
    This method is to retrieve individual information available per message
    :param msg: one message dump from SQS Queue
    :return: team_name, team_id, test_id, url, scan_id, receipt_handle
    """
    print("LOG: Retrieve individual information available per message")
    team_name = msg["MessageAttributes"]["teamname"].get("StringValue", None)
    test_id = msg["MessageAttributes"]["testid"].get("StringValue", None)   # [P3|CAE]:<alphanumeric string>
    scan_id = msg["MessageAttributes"]["scanid"].get("StringValue", None)   # <alphanumeric string>f8a51d2e-1467-11e9-8219-fe4a21889d64
    team_id = msg["MessageAttributes"]["teamid"].get("StringValue", None)   # [P3|CAE]:<alphanumeric string>
    url = msg["MessageAttributes"]["url"].get("StringValue", None)          # https...
    receipt_handle = msg.get("ReceiptHandle", None)

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
    audit_test_list = test_id.split(",")
    results = dict()
    del_flag = True

    """ Building module path audit_scripts dir """
    scripts_mod_path = os.environ["CLONED_REPO_DIR"].split("/")[-1] + "." + "audit_scripts"

    for tc in audit_test_list:
        """ Translating TC name to fetch the respective audit script name """
        audit_tc_script = tc.replace("-", "_").lower()
        script_file = os.environ["AUDIT_SCRIPTS_DIR"] + "/" + audit_tc_script + ".py"
        if os.path.isfile(script_file):
            tc_script = import_module("." + audit_tc_script, scripts_mod_path)
            try:
                results[audit_tc_script] = tc_script.main(url, team_name, scan_id, team_id)
                if results[audit_tc_script] is None:
                    print("LOG: Result for %s was received as None; retrying..." % audit_tc_script)
                    results[audit_tc_script] = tc_script.main(url, team_name, scan_id, team_id)
                    print("LOG: Second Attempt received result as %s" % results[audit_tc_script])
                    print("LOG: Continuing with next Audit Test-Script")
                    if results[audit_tc_script] is None:
                        del_flag = False
            except Exception as e:
                del_flag = False
                print("ERROR: Execution of %s Audit Test-script failed to return expected value - %s" % (str(e), audit_tc_script))
        else:
            results[audit_tc_script] = "Script is not available"
            raise Exception("ERROR: Required Audit Test-Script is not available %s" % audit_tc_script)
    print("LOG: Execution result for Team: %s \n%s" % (team_name, results))

    if del_flag:
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


def set_credentials_env():
    """
    Method to set the environment in terms of credentials to be used during execution
    :return:
    """
    print("LOG: Decrypt credentials file. Then set environment variables w.r.t. required set of credentials")
    if decrypt_file("csb_credentials.py.enc"):
        print("LOG: Successfully decrypted Credential file")
        cred_file = import_module("csb_credentials")
        for var, val in cred_file.csb_credentials.items():
            os.environ[var] = val
        return True
    else:
        raise Exception("ERROR: Failed to decrypt \"csb_credentials.py.enc\" file")
        return False


def main():
    """
    Method to drive the CSB function of auditing the P3 and CAE Cloud based projects
    :return:None
    """
    if set_credentials_env():
        """ Decrypt the kube config file """
        if decrypt_file("kube_config.enc"):
            print("INFO: Successfully decrypted Kube Config file")
        else:
            raise Exception("ERROR: Failed to decrypt \"kube_config.enc\" file")

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
                while True:
                    msg_from_sqs = read_message_from_sqs(sqsclient)
                    if msg_from_sqs.get("Messages", None):
                        print("INFO: Initiate processing of the messages received from SQS")
                        process_messages(msg_from_sqs)
                    else:
                        print("INFO: Attempt to read message from SQS didn't get any.")
                        print("INFO: Waiting for %s secs. before re-polling SQS Queue" % os.environ["WAIT_TIME_FOR_NEXT_POLL"])
                        time.sleep(int(os.environ["WAIT_TIME_FOR_NEXT_POLL"]))
            else:
                print("ERROR: Failed to get SQS Handle")

        """ Delete the decrypted files """
        print("INFO: Delete decrypted Credential file")
        os.remove(os.path.expanduser("~") + "/" + "csb_credentials.py")
        os.remove(os.path.expanduser("~") + "/" + "csb_credentials.pyc")
        print("INFO: Delete decrypted kube_config file")
        os.remove(os.path.expanduser("~") + "/" + "kube_config")
    else:
        raise Exception("ERROR: Failed to initialize the environment in terms of credentials to use.")


if __name__ == '__main__':
    main()
