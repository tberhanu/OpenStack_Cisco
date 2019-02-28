#!/usr/bin/python
"""
--------------------------- copy_files_from_pods.py ---------------------------
Description: This python script is to copy over the files from logs dir under
             each POD running under specified CAE Cluster and NameSpace within.

Pre-requisite:
    OC_USERNAME & OC_PASSWORD should be initialized as part of ENV Variables
    and have required privilege to the NameSpace

Usage:
    python copy_files_from_pods.py -u <Cluster URL> -n <Namespace>
    -a <[csb|teamsdb]>

Author: Amardeep Kumar <amardkum@cisco.com>; February 27th, 2019

Copyright (c) 2019 Cisco Systems.
All rights reserved.
-------------------------------------------------------------------------------
"""


import argparse
import datetime
import os
import pexpect
import subprocess
import time


def copy_files_from_cae(cluster, namespace, app):
    """
    Method to copy the files under logs dir of each POD running under give namespace
    :param cluster:
    :param namespace:
    :param app:
    :return:
    """
    print("INFO: Cluster - %s & NameSpace - %s" % (cluster, namespace))
    out = subprocess.Popen([
                            '/usr/bin/oc', 'login', cluster,
                            '-u', os.environ["OC_USERNAME"],
                            '-p', os.environ["OC_PASSWORD"],
                            '--namespace', namespace,
                            '--insecure-skip-tls-verify'
                            ],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT
                          )
    stdout, stderr = out.communicate()
    print("DEBUG: STDOUT while logging into Cluster: %s - %s" % (cluster, stdout))
    if stderr:
        print("ERROR: stderr while logging in to Cluster: %s - %s" % (cluster, stderr))
        return False

    list_of_pods = list()

    if "Login successful" in stdout:
        out = subprocess.Popen(['/usr/bin/oc', 'get', 'pods'],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = out.communicate()
        if stderr:
            print("ERROR: STDERR while copying the file - %s" % stderr)
            return False
        else:
            pod_list = stdout.splitlines()
            for pod in pod_list[1:]:
                list_of_pods.append(pod.split(" ")[0])
            print("INFO: List of PODS: %s" % list_of_pods)

            prompt = '^.*$'
            for pod in list_of_pods:
                oc_rsh_pod = "/usr/bin/oc rsh " + pod
                deployment_name = pod.split("-")[0]
                tar_cmd = "/usr/bin/tar -cvf " + deployment_name + ".tar logs/"
                child = pexpect.spawn(oc_rsh_pod)
                child.expect(prompt, timeout=10)
                print("INFO: Successful login to Pod: %s" % pod)
                print("INFO: Generating tar for the logs generated on Pod: %s" % pod)
                child.sendline(tar_cmd)
                time.sleep(5)
                child.expect(prompt, timeout=10)
                child.sendline("exit")

            for pod in list_of_pods:
                date_stamp = datetime.datetime.now().strftime('%m%d%y')
                deployment_name = pod.split("-")[0]
                file_at_source = pod + ":/opt/app-root/src/" + deployment_name + ".tar"

                if app == "csb":
                    destination = os.path.expanduser("~") + "/logs/csbauditor_logs/" + date_stamp
                else:
                    destination = os.path.expanduser("~") + "/logs/teamsdbupdate_logs/" + date_stamp
                local_deployment_dir = destination + "/" + deployment_name

                try:
                    os.makedirs(local_deployment_dir)
                except OSError as os_err:
                    if "File exists" in str(os_err):
                        pass
                    else:
                        print("ERROR: Unknown Issue observed while attempting to create a directory - %s" % str(os_err))

                out = subprocess.Popen(['/usr/bin/oc', 'rsync', file_at_source, destination],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout, stderr = out.communicate()
                if stderr:
                    print("ERROR: STDERR while copying the file - %s" % stderr)
                    return False
                else:
                    print("INFO: Successfully copied over the Tar file from POD to local dir")

                out = subprocess.Popen(['/usr/bin/tar', '-xvf', destination + "/" + deployment_name + ".tar",
                                        "-C", local_deployment_dir],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout, stderr = out.communicate()
                if stderr:
                    print("ERROR: STDERR while extracting contents of the tar file - %s" % stderr)
                    return False
                else:
                    print("INFO: Required Tar file was successfully downloaded to local dir")
            return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Pull out the logs generated by the applications running on CAE")
    parser.add_argument("-u", "--cluster_url", action="store", dest="url")
    parser.add_argument("-n", "--namespace", action="store", dest="namespace")
    parser.add_argument("-a", "--application_name", action="store", dest="app", help="Application Type(\"csb\" or \"teamsdb\")")
    args = parser.parse_args()
    cluster = args.url
    namespace = args.namespace
    app = args.app

    if copy_files_from_cae(cluster, namespace, app):
        print("INFO: Successfully copied all files under logs dir of each POD running under %s" % namespace)
    else:
        print("ERROR: Failed to copy all files under logs dir of each POD running under %s" % namespace)
