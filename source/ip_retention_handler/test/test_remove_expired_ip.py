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
from decimal import Decimal
from remove_expired_ip import RemoveExpiredIP

event = {
		"Records": [{
			"eventID": "some-event-id",
			"eventName": "REMOVE",
			"eventVersion": "1.1",
			"eventSource": "aws:dynamodb",
			"awsRegion": "us-east-1",
			"dynamodb": {
				"ApproximateCreationDateTime": 1628203857.0,
				"Keys": {
					"ExpirationTime": {
						"N": "1628203246"
					},
					"IPSetId": {
						"S": "some-ips-set-id"
					}
				},
				"OldImage": {
					"IPSetName": {
						"S": "some-ip-set-name"
					},
					"CreatedByUser": {
						"S": "some-user"
					},
					"Scope": {
						"S": "CLOUDFRONT"
					},
					"CreationTime": {
						"N": "1628203216"
					},
					"LockToken": {
						"S": "some-lock_token"
					},
					"IPAdressList": {
						"L": [{
							"S": "x.x.x.x/32"
						}, {
							"S": "y.y.y.y/32"
						}]
					},
					"ExpirationTime": {
						"N": "1628203246"
					},
					"IPSetId": {
						"S": "some-ips-set-id"
					}
				},
				"SequenceNumber": "some-sequence-number",
				"SizeBytes": 339,
				"StreamViewType": "OLD_IMAGE"
			},
			"userIdentity": {
				"principalId": "dynamodb.amazonaws.com",
				"type": "Service"
			},
			"eventSourceARN": "arn:aws:dynamodb:us-east-1:some-account:table/some-ddb-table/stream/2021-07-26T22:26:39.107"
		}]
	}

user_identity = {
	"principalId": "dynamodb.amazonaws.com",
	"type": "Service"
}

log = logging.getLogger()
log.setLevel('INFO')
reip = RemoveExpiredIP(event, log)

def test_is_none():
	is_not_none = reip.is_none('some_value')
	is_none = reip.is_none(None)
	assert is_not_none == 'some_value' and is_none == 'None'

def test_is_ddb_stream_event():
	is_ddb_stream_event = reip.is_ddb_stream_event(user_identity)
	assert is_ddb_stream_event == True

def test_deserialize_ddb_data():
	record = event['Records'][0]
	ddb_ip_set = reip.is_none(record.get('dynamodb', {}).get('OldImage', {}))
	desiralized_ddb_ip_set = reip.deserialize_ddb_data(ddb_ip_set)
	expected_desiralized_ddb_ip_set = {'IPSetName': 'some-ip-set-name', 'CreatedByUser': 'some-user', 'Scope': 'CLOUDFRONT', 'CreationTime': Decimal('1628203216'), 'LockToken': 'some-lock_token', 'IPAdressList': ['x.x.x.x/32', 'y.y.y.y/32'], 'ExpirationTime': Decimal('1628203246'), 'IPSetId': 'some-ips-set-id'}
	assert desiralized_ddb_ip_set == expected_desiralized_ddb_ip_set

def test_make_ip_list():
	waf_ip_list = ['x.x.x.x/32', 'y.y.y.y/32']
	ddb_ip_list = ['x.x.x.x/32', 'y.y.y.y/32', 'z.z.z.z/32', 'x.y.y.y/32', 'x.x.y.y/32']
	keep_ip_list, remove_ip_list = reip.make_ip_list(log, waf_ip_list, ddb_ip_list)
	assert keep_ip_list == []
	assert len(remove_ip_list) > 0