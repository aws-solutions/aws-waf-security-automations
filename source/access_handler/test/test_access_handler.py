##############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.   #
#                                                                            #
#  Licensed under the Apache License, Version 2.0 (the "License").           #
#  You may not use this file except in compliance                            #
#  with the License. A copy of the License is located at                     #
#                                                                            #
#      http://www.apache.org/licenses/LICENSE-2.0                            #
#                                                                            #
#  or in the "license" file accompanying this file. This file is             #
#  distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY  #
#  KIND, express or implied. See the License for the specific language       #
#  governing permissions  and limitations under the License.                 #
##############################################################################

from access_handler.access_handler import *
import os
import logging

log_level = 'DEBUG'
logging.getLogger().setLevel(log_level)
log = logging.getLogger('test_access_handler')


def test_access_handler_error(ipset_env_var_setup, badbot_event, expected_exception_access_handler_error):
    try:
        lambda_handler(badbot_event, {})
    except Exception as e:
        expected = expected_exception_access_handler_error
        assert str(e) == expected

def test_initialize_usage_data():
    os.environ['LOG_TYPE'] = 'LOG_TYPE'
    result = initialize_usage_data()
    expected = {
        "data_type": "bad_bot",
        "bad_bot_ip_set_size": 0,
        "allowed_requests": 0,
        "blocked_requests_all": 0,
        "blocked_requests_bad_bot": 0,
        "waf_type": 'LOG_TYPE',
        "provisioner": "cfn"
    }
    assert result == expected

def test_send_anonymous_usage_data(cloudwatch_client, expected_cw_resp):
    result = send_anonymous_usage_data(
        log=log,
        scope='ALB',
        ipset_name_v4='ipset_name_v4',
        ipset_arn_v4='ipset_arn_v4',
        ipset_name_v6='ipset_name_v6',
        ipset_arn_v6='ipset_arn_v6'
    )
    assert result == expected_cw_resp
