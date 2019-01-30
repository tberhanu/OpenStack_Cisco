#!/bin/bash

#
# audit_projects.sh
#

TOP=$(cd `dirname $0`; pwd -P); cd $TOP/../tools

echo
echo "======================================================================="
echo "Python Version is `python -V`"
echo "======================================================================="

if [ $# -eq 0 ]; then
  echo -e "\nNeed Test_Id(s) as Arg(s). Example Arg: p3_identity_mgmt_tc_1\n"; exit 1
fi

cp ~/.csb/{csb_credentials.py,csb_credentials.pyc} ~

cat >requirements.txt <<!
gitpython
pykube
pycrypto
openstacksdk
boto3
!

pip install -r requirements.txt

python audit_projects.py -t "$@"

