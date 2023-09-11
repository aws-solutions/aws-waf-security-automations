###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License, Version 2.0 (the "License").            #
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at                                        #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0                             #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permissions#
#  and limitations under the License.                                         #
###############################################################################

import pytest
from os import environ


@pytest.fixture(scope='module', autouse=True)
def test_environment_vars_setup():
    environ['IP_SET_NAME_REPUTATIONV4'] = 'test_ReputationListsSetIPV4'
    environ['IP_SET_NAME_REPUTATIONV6'] = 'test_ReputationListsSetIPV6'
    environ['IP_SET_ID_REPUTATIONV4'] = 'arn:aws:wafv2:us-east-1:11111111111:regional/ipset/test'
    environ['IP_SET_ID_REPUTATIONV6'] = 'arn:aws:wafv2:us-east-1:11111111111:regional/ipset/test'
    environ['SCOPE'] = 'REGIONAL'
    environ['SEND_ANONYMIZED_USAGE_DATA'] = 'Yes'
    environ['LOG_LEVEL'] = 'INFO'
    environ['UUID'] = 'test_uuid'
    environ['SOLUTION_ID'] = 'SO0006'
    environ['METRICS_URL'] = 'https://testurl.com/generic'