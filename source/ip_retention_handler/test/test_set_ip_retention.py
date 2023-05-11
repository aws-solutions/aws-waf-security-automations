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

from os import environ
from set_ip_retention import lambda_handler


SKIP_PROCESS_MESSAGE = "The event for UpdateIPSet API call was made by RemoveExpiredIP lambda instead of user. Skip."


def test_set_ip_retention(set_ip_retention_test_event_setup):
    environ['REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME'] = 'some_role'
    environ['IP_RETENTION_PERIOD_ALLOWED_MINUTE'] = '60'
    environ['IP_RETENTION_PERIOD_DENIED_MINUTE'] = '60'
    environ['TABLE_NAME'] = "test_table"
    event = set_ip_retention_test_event_setup
    result = lambda_handler(event, {})
    assert result is None


def test_ip_retention_not_activated(set_ip_retention_test_event_setup):
    environ['REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME'] = 'some_role'
    environ['IP_RETENTION_PERIOD_ALLOWED_MINUTE'] = '-1'
    environ['IP_RETENTION_PERIOD_DENIED_MINUTE'] = '-1'
    event = set_ip_retention_test_event_setup
    result = lambda_handler(event, {})
    assert result is not None

def test_missing_request_parameters_in_event(missing_request_parameters_test_event_setup):
	environ['REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME'] = 'some_role'
	environ['IP_RETENTION_PERIOD_ALLOWED_MINUTE'] = '60'
	environ['IP_RETENTION_PERIOD_DENIED_MINUTE'] = '60'
	event = missing_request_parameters_test_event_setup
	result = lambda_handler(event, {})
	assert result is None
        

def test_skip_process(set_ip_retention_test_event_setup):
	environ['REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME'] = 'fake-arn'
	event = set_ip_retention_test_event_setup
	result = {"Message": SKIP_PROCESS_MESSAGE}
	assert result == lambda_handler(event, {})
        

def test_put_item_exception(set_ip_retention_test_event_setup):
    try:
        environ['REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME'] = 'some_role'
        environ['IP_RETENTION_PERIOD_ALLOWED_MINUTE'] = '-1'
        environ['IP_RETENTION_PERIOD_DENIED_MINUTE'] = '60'
        environ.pop('TABLE_NAME')
        event = set_ip_retention_test_event_setup
        result = False
        lambda_handler(event, {})
        result = True
    except Exception as e:
        assert result == False