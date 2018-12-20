import os

from boto import dynamodb2
from boto.dynamodb2.table import Table


TABLE_NAME = "testprojectlist-ravi"
REGION = "us-east-1"

conn = dynamodb2.connect_to_region(
    REGION,
    aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
)
table = Table(
    TABLE_NAME,
    connection=conn
)


#uploading Rtpregion project list
def rtpupload():
	regionName = "RtpRegion"
	regionURL = "https://cloud-rtp-1.cisco.com:5000/v3"
	filename = regionName + '.txt'
	with open(filename) as projects:
		for pj in projects:
			x = pj.strip()
			y = x.split(" ")
			absolute_data = {
				"project-id": y[0],
				"project-name": y[1],
				"region": regionName,
				"Api-url": regionURL,
				"contact": "csb@cisco.com"
			}
			with table.batch_write() as table_batch:
				final_dynamo_data = dict(absolute_data.items())
				table_batch.put_item(data=final_dynamo_data)
		
   
    

def rcdnupload():
	regionName = "RcdnRegion"
	regionURL = "https://cloud-rcdn-1.cisco.com:5000/v3"
	filename = regionName + '.txt'
	with open(filename) as projects:
		for pj in projects:
			x = pj.strip()
			y = x.split(" ")
			absolute_data = {
				"project-id": y[0],
				"project-name": y[1],
				"region": regionName,
				"Api-url": regionURL,
				"contact": "csb@cisco.com"
			}
			with table.batch_write() as table_batch:
				final_dynamo_data = dict(absolute_data.items())
				table_batch.put_item(data=final_dynamo_data)
   
    


def allnupload():
	regionName = "AllnRegion"
	regionURL = "https://cloud-alln-1.cisco.com:5000/v3"
	filename = regionName + '.txt'
	with open(filename) as projects:
		for pj in projects:
			x = pj.strip()
			y = x.split(" ")
			absolute_data = {
				"project-id": y[0],
				"project-name": y[1],
				"region": regionName,
				"Api-url": regionURL,
				"contact": "csb@cisco.com"
			}
			with table.batch_write() as table_batch:
				final_dynamo_data = dict(absolute_data.items())
				table_batch.put_item(data=final_dynamo_data)
   
    


rtpupload()
rcdnupload()
allnupload()

