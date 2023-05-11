######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import logging
from decimal import Decimal
from os import environ
from remove_expired_ip import RemoveExpiredIP, lambda_handler


REMOVE_IP_LIST = ["x.x.x.x", "y.y.y.y"]
EXPECTED_NONE_TYPE_ERROR_MESSAGE = "'NoneType' object has no attribute 'get'"
EXPECTED_NONE_TYPE_NO_ATTRIBUTE_MESSAGE = "'NoneType' object has no attribute 'status_code'"
EVENT = {
		"Records": [{
			"eventID": "fake-event-id",
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
						"S": "fake-ips-set-id"
					}
				},
				"OldImage": {
					"IPSetName": {
						"S": "fake-ip-set-name"
					},
					"CreatedByUser": {
						"S": "fake-user"
					},
					"Scope": {
						"S": "CLOUDFRONT"
					},
					"CreationTime": {
						"N": "1628203216"
					},
					"LockToken": {
						"S": "fake-lock_token"
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
						"S": "fake-ips-set-id"
					}
				},
				"SequenceNumber": "fake-sequence-number",
				"SizeBytes": 339,
				"StreamViewType": "OLD_IMAGE"
			},
			"userIdentity": {
				"principalId": "dynamodb.amazonaws.com",
				"type": "Service"
			},
			"eventSourceARN": "arn:aws:dynamodb:us-east-1:fake-account:table/fake-ddb-table/stream/2021-07-26T22:26:39.107"
		}]
	}

EVENT_NAME_NOT_REMOVE = {
		"Records": [{
			"eventID": "fake-event-id",
			"eventName": "ADD",
			"eventVersion": "1.1",
			"eventSource": "aws:dynamodb",
			"awsRegion": "us-east-1"
		}]
	}

USER_IDENTITY = {
	"principalId": "dynamodb.amazonaws.com",
	"type": "Service"
}

USER_IDENTITY_NOT_SERVICE = {
	"principalId": "dynamodb.amazonaws.com",
	"type": "Any"
}

log = logging.getLogger()
log.setLevel('INFO')
reip = RemoveExpiredIP(EVENT, log)


def test_is_none():
	is_not_none = reip.is_none('some_value')
	is_none = reip.is_none(None)
	assert is_not_none == 'some_value' and is_none == 'None'


def test_is_ddb_stream_event():
	is_ddb_stream_event = reip.is_ddb_stream_event(USER_IDENTITY)
	assert is_ddb_stream_event == True


def test_deserialize_ddb_data():
	record = EVENT['Records'][0]
	ddb_ip_set = reip.is_none(record.get('dynamodb', {}).get('OldImage', {}))
	desiralized_ddb_ip_set = reip.deserialize_ddb_data(ddb_ip_set)
	expected_desiralized_ddb_ip_set = {'IPSetName': 'fake-ip-set-name', 'CreatedByUser': 'fake-user', 'Scope': 'CLOUDFRONT', 'CreationTime': Decimal('1628203216'), 'LockToken': 'fake-lock_token', 'IPAdressList': ['x.x.x.x/32', 'y.y.y.y/32'], 'ExpirationTime': Decimal('1628203246'), 'IPSetId': 'fake-ips-set-id'}
	assert desiralized_ddb_ip_set == expected_desiralized_ddb_ip_set


def test_make_ip_list():
	waf_ip_list = ['x.x.x.x/32', 'y.y.y.y/32']
	ddb_ip_list = ['x.x.x.x/32', 'y.y.y.y/32', 'z.z.z.z/32', 'x.y.y.y/32', 'x.x.y.y/32']
	keep_ip_list, remove_ip_list = reip.make_ip_list(log, waf_ip_list, ddb_ip_list)
	assert keep_ip_list == []
	assert len(remove_ip_list) > 0


def test_make_ip_list_no_removed_ips():
	waf_ip_list = ['x.x.x.x/32', 'y.y.y.y/32']
	ddb_ip_list = ['z.z.z.z/32', 'x.y.y.y/32', 'x.x.y.y/32']
	keep_ip_list, remove_ip_list = reip.make_ip_list(log, waf_ip_list, ddb_ip_list)
	assert keep_ip_list == []
	assert len(remove_ip_list) == 0


def test_send_notification(sns_topic):
	topic_arn = str(sns_topic)
	result = False
	reip.send_notification(log, topic_arn, "fake_ip_set_name", "fake_ip_set_id", 30, "fake_lambda_name")
	result = True
	assert result == True


def test_send_anonymous_usage_data_allowed_list():
    try:
        reip.send_anonymous_usage_data(log, REMOVE_IP_LIST, 'Whitelist')
    except Exception as e:
        assert str(e) == EXPECTED_NONE_TYPE_NO_ATTRIBUTE_MESSAGE	


def test_send_anonymous_usage_data_denied_list():
    try:
        reip.send_anonymous_usage_data(log, REMOVE_IP_LIST, 'Blacklist')
    except Exception as e:
        assert str(e) == EXPECTED_NONE_TYPE_NO_ATTRIBUTE_MESSAGE


def test_send_anonymous_usage_data_other_list():
    try:
        reip.send_anonymous_usage_data(log, REMOVE_IP_LIST, 'Otherlist')
    except Exception as e:
        assert str(e) == EXPECTED_NONE_TYPE_NO_ATTRIBUTE_MESSAGE


def test_send_anonymous_usage_data_empty_list():
    try:
        reip.send_anonymous_usage_data(log, [], 'Otherlist')
    except Exception as e:
        assert str(e) == EXPECTED_NONE_TYPE_NO_ATTRIBUTE_MESSAGE


def test_no_send_anonymous_usage_data():
	environ['SEND_ANONYMOUS_USAGE_DATA'] = 'no'
	result = reip.send_anonymous_usage_data(log, [], 'Otherlist')
	result is not None


def test_none_ip_set():
	environ['SEND_ANONYMOUS_USAGE_DATA'] = 'no'
	result = reip.get_ip_set(log, None, 'fake-ip-set-name', 'fake-ip-set-id')
	result is None
        

def test_remove_expired_ip():
    try:
        lambda_handler(EVENT, {})
    except Exception as e:
        assert str(e) == EXPECTED_NONE_TYPE_ERROR_MESSAGE
		
