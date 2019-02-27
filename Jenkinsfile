node {
	stage('SCM Checkout') {
		git credentialsID: 'devcredentials', 
		url: 'https://e0c2cffb461018052e8bf31c8d139b9ca0b83a33@wwwin-github.cisco.com/CiscoIT-CSB/CiscoIT-CSB/',
		branch: 'csb_dev'
	}
	stage('docker image build') {
	sh 'docker build -t containers.cisco.com/devaacha/docker:NewImage .'
	}
}
