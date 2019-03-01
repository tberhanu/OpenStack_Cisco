#!/bin/bash

#
# audit_projects.sh
#

TOOLS_DIR=$(cd `dirname $0`/../tools; pwd -P); cd $TOOLS_DIR

echo
echo "======================================================================="
echo "Python Version is `python -V`"
echo "======================================================================="

if [ $# -eq 0 ]; then
  echo -e "\nNeed Test_Id(s) as Arg(s). Example Arg: p3_identity_mgmt_tc_1\n"; exit 1
fi

cp ~/.csb/csb_credentials.py      $TOOLS_DIR
cp ~/.csb/csb_credentials.pyc     $TOOLS_DIR
cp ~/.csb/csb_credentials.py.enc  $TOOLS_DIR
cp ~/.csb/kube_config_rtp.enc     $TOOLS_DIR
cp ~/.csb/kube_config_rcdn.enc    $TOOLS_DIR
cp ~/.csb/kube_config_alln.enc    $TOOLS_DIR

cat >requirements.txt <<!
gitpython
pykube
pycrypto
openstacksdk
boto3
!

pip install -r requirements.txt

python audit_projects.py -t "$@"

