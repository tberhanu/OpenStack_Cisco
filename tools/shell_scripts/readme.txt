make sure the folder contains below files before running the shell scripts
	csb_credentials.py.enc_nonprod
	csb_credentials.py.enc_prod
	oc
	
NOTE: Make sure the oc file is in +x(executable) mode before building docker image

NOTE: change the image name in YAML file, based on the image you build.

NOTE: Make sure the CiscoIT-CSB repo is cloned to $HOME 

NOTE: Inorder to run in the VM change the data_cae_vm to data_cae
NOTE: If you want to run for specific tenants, place the details in tenants file. <tenantsname>,<REGIONNAME>

      ex: phuoc_rtp,RTP
       its should be comma(,) seperated

NOTE: If yoy want to run audit_projects for all tenants, make sure to delete tenants file
