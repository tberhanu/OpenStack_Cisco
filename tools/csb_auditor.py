#!/opt/app-root/bin/python

"""
-------------------------------- csb_auditor.py --------------------------------
Description: This python script is to
                a. set environment in terms of credentials to be used
                b. set environment w.r.t. other required parameters
                c. generate the kube config files per cluster
                d. clone git repo
                e. create connection handle to SQS Queue
                f. read messages from SQS Queue created for CNT-CSB
                g. process the required information
                h. pass the information to audit test-script
                i. consolidate return values from each audit script per team
                j. delete message from SQS Queue, if none of the return values
                   are not "None"

Dependencies:
    csb_credentials.py.enc_prod
    csb_credentials.py.enc_nonprod
    prod_env_variables.py
    nonprod_env_variables.py
    requirements.txt

Usage:
    python csb_auditor.py -e [prod|nonprod]

Author: Amardeep Kumar <amardkum@cisco.com>; December 19th, 2018

Copyright (c) 2018 Cisco Systems.
All rights reserved.
--------------------------------------------------------------------------------
"""

import argparse
import boto3
import botocore
import datetime
import git
import multiprocessing
import os
import re
import shutil
import struct
import time

from Crypto.Cipher import AES
from prod_env_variables import prod_env_variables
from nonprod_env_variables import nonprod_env_variables
from importlib import import_module


def decrypt_file(filenames):
    """
    Decrypts the encrypted files using AES(CBC mode) with the given key.
    :param filenames: name of encrypted kube config file(s)
    :return: generate decrypted file and return True/False
    """
    """ Key to decrypt the encrypted files required for CSB Audit """
    key = "1329ebbc1b9646b890202384beaef2ec"

    list_of_enc_files = filenames.split(",")
    flag = True
    for in_filename in list_of_enc_files:
        out_filename = os.path.splitext(in_filename)[0]
        chunk_size = 64*1024
        try:
            print("INFO: Decrypt %s file" % in_filename)
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
                    flag = False
        except IOError:
            print("ERROR: File %s was not accessible" % in_filename)
            flag = False

        if os.path.isfile(out_filename):
            print("INFO: Decrypted version of %s file is available for use" % in_filename)
        else:
            print("ERROR: Decrypted version of %s file is not available for use" % in_filename)
            flag = False

    return flag


def sqs_client_handle():
    """
    This method is meant to create a communication handle to AWS SQS Queue
    :return: handle to sqs queue or None
    """
    try:
        print("INFO: Create SQS Client Handle")
        region = os.environ["SQS_URL"].split(".")[1]
        session = boto3.session.Session(
                                        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
                                        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
                                        region_name=region
                                        )
        sqsclient_handle = session.client("sqs")
        return sqsclient_handle

    except botocore.exceptions.ClientError as boto_err:
        print("ERROR: Failed to establish connection with AWS SQS Queue - %s" % str(boto_err))
        return None

    except botocore.executions.ParamValidationError as param_err:
        print("ERROR: Parameter validation error: %s" % param_err)
        return None

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
                                                VisibilityTimeout=int(os.environ["SQS_MSG_VISIBILITY_TIMEOUT"]),
                                                WaitTimeSeconds=int(os.environ["SQS_MSG_POLL_TIME"])
                                            )
        print("INFO: Response received as part of \"receive_message\" request to SQS: %s" % response)
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
        print("INFO: Clone GIT Repo")
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
    print("INFO: Process the messages read from SQS")
    processes = list()
    if "Messages" in messages:
        for message in messages["Messages"]:
            team_name, team_id, test_id, url, scan_id, receipt_handle = retrieve_details(message)
            list_of_values_received = [team_name, team_id, test_id, url, scan_id]
            if any(val is None for val in list_of_values_received):
                print("ERROR: One of the value received from %s is not appropriate or in expected format" % message)
                break

            print("INFO: TeamName: %s, TeamID: %s, TestIDs: %s, URL: %s, Scan ID = %s, Receipt Handle: %s"
                  % (team_name, team_id, test_id, url, scan_id, receipt_handle))
            try:
                """ New process will be initiated per message/team """
                print("INFO: Start the thread for execution of Audit test-scripts per team")
                proc = multiprocessing.Process(
                                                target=audit_project,
                                                args=(team_id, team_name, test_id, url, scan_id, receipt_handle)
                                              )
                processes.append(proc)
                proc.start()
            except multiprocessing.ProcessError as proc_err:
                print("ERROR: Message processing failed for TeamId-TeamName => %s-%s due to %s"
                      % (team_id, team_name, str(proc_err)))
            try:
                for one_process in processes:
                    one_process.join(int(os.environ["MPROC_TIMEOUT"]))
                for process in processes:
                    if process.is_alive():
                        print("INFO: Exhausted the defined timeout value, "
                              "hence terminating the process which is still alive")
                        process.terminate()
            except multiprocessing.ProcessError as proc_err:
                print("ERROR: Encountered issue while closing child process(s) meant for %s - %s"
                      % (team_name, str(proc_err)))
            except Exception as mproc_err:
                print("ERROR: Encountered new issue while closing child process(s) meant for %s - %s"
                      % (team_name, str(mproc_err)))
    else:
        print("INFO: There was no message available for processing")


def retrieve_details(msg):
    """
    This method is to retrieve individual information available per message
    :param msg: one message dump from SQS Queue
    :return: team_name, team_id, test_id, url, scan_id, receipt_handle
    """
    print("INFO: Retrieve individual information available per message")
    team_name = msg["MessageAttributes"]["teamname"].get("StringValue", None)
    test_id = msg["MessageAttributes"]["testid"].get("StringValue", None)
    scan_id = msg["MessageAttributes"]["scanid"].get("StringValue", None)
    team_id = msg["MessageAttributes"]["teamid"].get("StringValue", None)
    url = msg["MessageAttributes"]["url"].get("StringValue", None)
    receipt_handle = msg.get("ReceiptHandle", None)

    scanid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    teamid_pattern = re.compile(r'(^P3:[0-9a-f]{32}$)|(^CAE:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)')
    url_pattern = re.compile(r'^https://((cae-np-.*.cisco.com)|(cae-prd-.*.cisco.com)|(cloud-.*-1.cisco.com:5000/v3))$')
    rh_pattern = re.compile(r'([a-zA-Z0-9]*[/]?[+]?[a-zA-Z0-9]*)*=')
    tc_pattern = re.compile(r'^(P3|CAE)[-A-Z0-9]*(, (P3|CAE)[-A-Z0-9]*)*')

    if tc_pattern.match(test_id):
        print("INFO: Received valid TestID")
    else:
        test_id = None
        print("ERROR: Received TestID is not valid")

    if scanid_pattern.match(scan_id):
        print("INFO: Received valid ScanID")
    else:
        scan_id = None
        print("ERROR: Received ScanID is not valid")

    if teamid_pattern.match(team_id):
        print("INFO: Received valid TeamID")
    else:
        team_id = None
        print("ERROR: Received TeamID is not valid")

    if url_pattern.match(url):
        print("INFO: Received valid URL")
    else:
        url = None
        print("ERROR: Received URL is not valid")

    if rh_pattern.match(receipt_handle):
        print("INFO: Received valid Receipt Handle")
    else:
        receipt_handle = None
        print("ERROR: Received Receipt Handle is not valid")

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
    print("INFO: Execute individual Audit test-scripts per team: %s" % team_name)
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
                results[audit_tc_script], summary_report = tc_script.main(url, team_name, scan_id, team_id)
                if results[audit_tc_script] is None:
                    print("INFO: Result for %s was received as None; retrying..." % audit_tc_script)
                    results[audit_tc_script] = tc_script.main(url, team_name, scan_id, team_id)
                    print("INFO: Second Attempt received result as %s" % results[audit_tc_script])
                    print("INFO: Continuing with next Audit Test-Script")
                    if results[audit_tc_script] is None:
                        del_flag = False
            except Exception as e:
                del_flag = False
                print("ERROR: Execution of %s Audit Test-script failed to return expected value - %s"
                      % (str(e), audit_tc_script))
        else:
            results[audit_tc_script] = "Script is not available"
            print("ERROR: Required Audit Test-Script is not available %s" % audit_tc_script)
            del_flag = False
    timestamp = datetime.datetime.now().strftime('%m%d%y_%H%M%S')
    print("INFO: %s Execution result for Team: %s \n%s" % (timestamp, team_name, results))

    if del_flag:
        delete_msg_from_sqs(receipt_handle)


def delete_msg_from_sqs(receipt_handle):
    """
    This method is meant to delete received message from SQS queue w.r.t. the Receipt handle
    :param receipt_handle: Receipt handle associated with the message meant for deletion
    :return: None
    """
    print("INFO: Delete message from SQS")
    try:
        sqsclient = sqs_client_handle()
        response = sqsclient.delete_message(
                                             QueueUrl=os.environ["SQS_URL"],
                                             ReceiptHandle=receipt_handle
                                            )
        print("INFO: Response while attempting to delete the message: %s" % response)
    except botocore.exceptions.ClientError as del_err:
        print("ERROR: Failed to delete the message from SQS Queue: %s" % str(del_err))


def set_credentials_env(e_type):
    """
    Method to set the environment in terms of credentials to be used during execution
    :return:
    """
    print("INFO: Decrypt credentials file. Then set environment variables w.r.t. required set of credentials")
    if e_type == "prod":
        cred_file = "csb_credentials.py.enc_prod"
    elif e_type == "nonprod":
        cred_file = "csb_credentials.py.enc_nonprod"
    else:
        print("ERROR: Didn't receive the expected value for ENV_TYPE - %s" % e_type)

    if decrypt_file(cred_file):
        print("INFO: Successfully decrypted Credential file")
        cred_file_handle = import_module("csb_credentials")
        for var, val in cred_file_handle.csb_credentials.items():
            os.environ[var] = val
        return True
    else:
        raise Exception("ERROR: Failed to decrypt %s file" % cred_file)
        return False


def main(env_type):
    """
    Method to drive the CSB function of auditing the P3 and CAE Cloud based Tenants
    :return:None
    """
    if set_credentials_env(env_type):
        """ Setting environment variables required for execution of CBS-CNT related scripts """
        if env_type == "prod":
            print("INFO: Set all required variables as part of ENV for ENV_TYPE = %s" % env_type)
            for var, val in prod_env_variables.items():
                os.environ[var] = val
        elif env_type == "nonprod":
            print("INFO: Set all required variables as part of ENV for ENV_TYPE = %s" % env_type)
            for var, val in nonprod_env_variables.items():
                os.environ[var] = val
        else:
            print("ERROR: Didn't receive the expected value for ENV_TYPE - %s" % env_type)

        """ Clone Git Repo for the audit test-scripts """
        if clone_git_repo():

            """ Generate Kube config file for cluster listed in landscape_of_execution.py """
            lib_mod_path = os.environ["CLONED_REPO_DIR"].split("/")[-1] + "." + "library"
            if os.path.isfile(os.environ["LIBRARY_DIR"] + "/cae_lib.py"):
                cae_lib_handle = import_module(".cae_lib", lib_mod_path)
                if cae_lib_handle.generate_kube_config_file():
                    print("INFO: Successfully generated the required Kube Config file for "
                          "each cluster listed in landscape_of_execution.py")
                else:
                    print("ERROR: Issue observed while generating Kube config file.")
                    print("WARNING: Overall execution for CAE Tenants will get affected")
            else:
                print("ERROR: Required CAE Library is not available")
                print("WARNING: Execution for CAE audit scripts will get affected")

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
                        print("INFO: Didn't receive any message from SQS to process")
                        print("INFO: Waiting for %s secs. before re-polling SQS Queue"
                              % os.environ["WAIT_TIME_FOR_NEXT_POLL"])
                        time.sleep(int(os.environ["WAIT_TIME_FOR_NEXT_POLL"]))
            else:
                print("ERROR: Failed to get SQS Handle")
        else:
            print("ERROR: Failed to Clone the required GIT Repo")

        """ Delete the decrypted files """
        print("INFO: Delete decrypted Credential file")
        os.remove(os.path.expanduser("~") + "/" + "csb_credentials.py")
        os.remove(os.path.expanduser("~") + "/" + "csb_credentials.pyc")

    else:
        raise Exception("ERROR: Failed to initialize the environment in terms of credentials to use.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Pass on the type of execution environment")
    parser.add_argument("-e", "--env_type", help="Environment Type(\"prod\" or \"nonprod\")", action="store", dest="env")
    args = parser.parse_args()

    if args.env and (args.env == "prod" or args.env == "nonprod"):
        env = args.env
        print("INFO: Execution will continue for %s ENV" % str(env).upper())
    else:
        env = "nonprod"
        print("WARNING: Received ENV Type is not appropriate. Expected ENV Type is either \"prod\" or \"nonprod\"")
        print("INFO: Continuing with ENV Type = \"nonprod\"")

    main(env)
