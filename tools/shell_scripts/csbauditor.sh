repo_dir="$HOME/CiscoIT-CSB"
audit_script_dir="$HOME/CiscoIT-CSB/audit_scripts"
tools_dir="$HOME/CiscoIT-CSB/tools"
WORKING_DIR=$(pwd)
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
cd $CSB_AUDITOR/prod
cp $tools_dir/csb_auditor.py .
cp $tools_dir/supporting_files/{requirements.txt,prod_env_variables.py,nonprod_env_variables.py} .
cp $tools_dir/docker_files/prod_csbauditor_Dockerfile .
mv prod_csbauditor_Dockerfile ./Dockerfile
cp $tools_dir/yaml_files/prod_csbauditor1.yaml .
cp $WORKING_DIR/{csb_credentials.py.enc_nonprod,csb_credentials.py.enc_prod,oc} .
#for non prod
cd $WORKING_DIR
cd $RELEASE_DIR
cd $CSB_AUDITOR/nonprod
cp $tools_dir/csb_auditor.py .
cp $tools_dir/supporting_files/{requirements.txt,prod_env_variables.py,nonprod_env_variables.py} .
cp $tools_dir/docker_files/nonprod_csbauditor_Dockerfile .
mv nonprod_csbauditor_Dockerfile ./Dockerfile
cp $tools_dir/yaml_files/nonprod_csbauditor1.yaml .
cp $WORKING_DIR/{csb_credentials.py.enc_nonprod,csb_credentials.py.enc_prod,oc} .