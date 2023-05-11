######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
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

from log_group_retention import LogGroupRetention
import logging

log_level = 'DEBUG'
logging.getLogger().setLevel(log_level)
log = logging.getLogger('test_log_group_retention')

lgr = LogGroupRetention(log)

def test_truncate_stack_name_empty():
    stack_name = ''
    expected = ''
    res = lgr.truncate_stack_name(stack_name)
    assert res == expected


def test_truncate_stack_name_short():
    stack_name = 'undertwentychars'
    expected = 'undertwentychars'
    res = lgr.truncate_stack_name(stack_name)
    assert res == expected


def test_truncate_stack_name_long():
    stack_name = 'thisisovertwentycharacts'
    expected = 'thisisovertwentychar'
    res = lgr.truncate_stack_name(stack_name)
    assert res == expected


def test_get_log_group_prefix():
    stack_name = 'stackname'
    expected = '/aws/lambda/stackname'
    res = lgr.get_log_group_prefix(stack_name)
    assert res == expected


def test_get_lambda_names():
    resource_props = {
        'CustomResourceLambdaName': 'TESTCustomResourceLambdaName',
        'MoveS3LogsForPartitionLambdaName': 'TESTMoveS3LogsForPartitionLambdaName',
        'AddAthenaPartitionsLambdaName': 'TESTAddAthenaPartitionsLambdaName',
        'SetIPRetentionLambdaName': 'TESTSetIPRetentionLambdaName',
        'RemoveExpiredIPLambdaName': 'TESTRemoveExpiredIPLambdaName',
        'ReputationListsParserLambdaName': 'TESTReputationListsParserLambdaName',
        'BadBotParserLambdaName': 'TESTBadBotParserLambdaName',
        'CustomResourceLambdaName': 'TESTCustomResourceLambdaName',
        'CustomTimerLambdaName': 'TESTCustomTimerLambdaName',
        'RandomProp': 'TESTRandomProp'
    }
    expected = {
        '/aws/lambda/TESTCustomResourceLambdaName',
        '/aws/lambda/TESTMoveS3LogsForPartitionLambdaName',
        '/aws/lambda/TESTAddAthenaPartitionsLambdaName',
        '/aws/lambda/TESTSetIPRetentionLambdaName',
        '/aws/lambda/TESTRemoveExpiredIPLambdaName',
        '/aws/lambda/TESTReputationListsParserLambdaName',
        '/aws/lambda/TESTBadBotParserLambdaName',
        '/aws/lambda/TESTCustomResourceLambdaName',
        '/aws/lambda/TESTCustomTimerLambdaName'
    }
    res = lgr.get_lambda_names(resource_props)
    assert res == expected
