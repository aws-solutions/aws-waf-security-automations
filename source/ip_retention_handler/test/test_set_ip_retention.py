############################################################################## 
# Copyright Amazon.com, Inc. and its affiliates. All Rights Reserved. 
#                                                                            #
#  Licensed under the Amazon Software License (the "License"). You may not   #
#  use this file except in compliance with the License. A copy of the        #
#  License is located at                                                     #
#                                                                            #
#      http://aws.amazon.com/asl/                                            #
#                                                                            #
#  or in the "license" file accompanying this file. This file is distributed #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,        #
#  express or implied. See the License for the specific language governing   #
#  permissions and limitations under the License.                            #
##############################################################################

import logging
import os
from set_ip_retention import SetIPRetention

event ={
		"eventVersion": "1.08",
		"userIdentity": {
			"type": "AssumedRole",
			"principalId": "some-id",
			"arn": "some-arn",
			"accountId": "some-account",
			"accessKeyId": "some-key-id",
			"sessionContext": {
				"sessionIssuer": {
					"type": "Role",
					"principalId": "some-id",
					"arn": "some-arn",
					"accountId": "some-account",
					"userName": "some-username"
				},
				"webIdFederationData": {},
				"attributes": {
					"creationDate": "2021-07-26T17:42:52Z",
					"mfaAuthenticated": "false"
				}
			}
		},
		"eventTime": "2021-07-26T22:33:04Z",
		"eventSource": "wafv2.amazonaws.com",
		"eventName": "UpdateIPSet",
		"awsRegion": "us-east-1",
		"sourceIPAddress": "some-ip",
		"userAgent": "aws-internal/3 aws-sdk-java/1.11.1004 Linux/5.4.116-64.217.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.292-b10 java/1.8.0_292 vendor/Oracle_Corporation cfg/retry-mode/legacy",
		"requestParameters": {
			"name": "some-Whitelist-ip-set-name",
			"scope": "CLOUDFRONT",
			"id": "some-ip-set-id",
			"description": "Allow List for IPV4 addresses",
			"addresses": [
				"x.x.x.x/32",
				"y.y.y.y/32",
				"z.z.z.z/32"
			],
			"lockToken": "some-lock-token"
		},
		"responseElements": {
			"nextLockToken": "some-next-lock-token"
		},
		"requestID": "some-request-id",
		"eventID": "some-event-id",
		"readOnly": 'false',
		"eventType": "AwsApiCall",
		"apiVersion": "2019-04-23",
		"managementEvent": 'true',
		"recipientAccountId": "some-account",
		"eventCategory": "Management"
	}

log = logging.getLogger()
log.setLevel('INFO')
sipr = SetIPRetention(event, log)

os.environ["TABLE_NAME"] = 'test_table'
os.environ['IP_RETENTION_PEROID_ALLOWED_MINUTE'] = '5'
os.environ['STACK_NAME'] = 'waf-solution'

def test_get_expiration_time():
    epoch_time = sipr.get_expiration_time("2021-07-26T22:33:04Z", 5)
    assert epoch_time == 1627339084

def test_make_item():
	item = sipr.make_item(event)

	# Remove CreationTime as it is current timestamp that constantly changes
	del item['CreationTime'] 

	assert item == {'IPSetId': 'some-ip-set-id', 'IPSetName': 'some-Whitelist-ip-set-name', 'Scope': 'CLOUDFRONT', 'IPAdressList': ['x.x.x.x/32', 'y.y.y.y/32', 'z.z.z.z/32'], 'LockToken': 'some-lock-token', 'IPRetentionPeriodMinute': 15, 'ExpirationTime': 1627339684, 'CreatedByUser': 'waf-solution'}