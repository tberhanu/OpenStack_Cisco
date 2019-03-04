repo_dir="$HOME/CiscoIT-CSB"
audit_script_dir="$HOME/CiscoIT-CSB/audit_scripts"
tools_dir="$HOME/CiscoIT-CSB/tools"
WORKING_DIR=$(pwd)
#echo $WORKING_DIR
RELEASE_DIR="./release"
TEAMSDB="./TeamsDb"
CSB_AUDITOR="./CsbAuditor"
if [ -d "$RELEASE_DIR" ]; then rm -Rf $RELEASE_DIR; fi
mkdir $RELEASE_DIR
cd $RELEASE_DIR
mkdir -p $TEAMSDB/nonprod
mkdir -p $TEAMSDB/prod
mkdir -p $CSB_AUDITOR/nonprod
mkdir -p $CSB_AUDITOR/prod
#for prod
cd $TEAMSDB/prod
cp $tools_dir/{p3_cae_list_projects_and_update_dynamoDB.py,teams_db_update_util.py,audit_projects.py} .
cp $tools_dir/supporting_files/{audit_tc_list.py,landscape_of_execution.py,requirements.txt,data_cae.xml,data_p3.xml,prod_env_variables.py,nonprod_env_variables.py} .
cp $tools_dir/docker_files/prod_teamsDb_Dockerfile .
mv prod_teamsDb_Dockerfile ./Dockerfile
cp $tools_dir/yaml_files/prod_teamsdbupdate.yaml .
cp $WORKING_DIR/{csb_credentials.py.enc_nonprod,csb_credentials.py.enc_prod,oc} .
#for non prod
cd $WORKING_DIR
cd $RELEASE_DIR
cd $TEAMSDB/nonprod
cp $tools_dir/{p3_cae_list_projects_and_update_dynamoDB.py,teams_db_update_util.py,audit_projects.py} .
cp $tools_dir/supporting_files/{audit_tc_list.py,landscape_of_execution.py,requirements.txt,data_cae.xml,data_p3.xml,prod_env_variables.py,nonprod_env_variables.py} .
cp $tools_dir/docker_files/nonprod_teamsdb_Dockerfile .
mv nonprod_teamsdb_Dockerfile ./Dockerfile
cp $tools_dir/yaml_files/nonprod_teamsdbupdate.yaml .
cp $WORKING_DIR/{csb_credentials.py.enc_nonprod,csb_credentials.py.enc_prod,oc} .
