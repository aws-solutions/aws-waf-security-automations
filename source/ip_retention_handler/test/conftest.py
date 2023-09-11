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

import boto3
import pytest
from os import environ
from moto import mock_dynamodb, mock_sns, mock_wafv2
from moto.core import DEFAULT_ACCOUNT_ID
from moto.sns import sns_backends


REGION = "us-east-1"
TABLE_NAME = "test_table"


@pytest.fixture(scope='module', autouse=True)
def test_aws_credentials_setup():
    """Mocked AWS Credentials for moto"""
    environ['AWS_ACCESS_KEY_ID'] = 'testing'
    environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    environ['AWS_SECURITY_TOKEN'] = 'testing'
    environ['AWS_SESSION_TOKEN'] = 'testing'
    environ['AWS_DEFAULT_REGION'] = 'us-east-1'
    environ['AWS_REGION'] = 'us-east-1'
    

@pytest.fixture(scope='module', autouse=True)
def test_environment_vars_setup():
    environ['TABLE_NAME'] = TABLE_NAME
    environ['STACK_NAME'] = 'waf_stack'
    environ['SNS_EMAIL'] = 'yes'
    environ['UUID'] = "waf_test_uuid"
    environ['SOLUTION_ID'] = "waf_test_solution_id"   
    environ['METRICS_URL'] = "https://testurl.com/generic"
    environ['SEND_ANONYMIZED_USAGE_DATA'] = 'yes'


@pytest.fixture(scope='module', autouse=True)
def ddb_resource():
    with mock_dynamodb():
        connection = boto3.resource("dynamodb", region_name=REGION)
        yield connection


@pytest.fixture(scope='module', autouse=True)
def ddb_table(ddb_resource):
    conn = ddb_resource
    conn.Table(TABLE_NAME)


@pytest.fixture(scope='module', autouse=True)
def sns_client():
    with mock_sns():
        connection = boto3.resource("sns", region_name=REGION)
        yield connection


@pytest.fixture(scope='module', autouse=True)
def sns_topic():
    sns_backend = sns_backends[DEFAULT_ACCOUNT_ID]["us-east-1"]  # Use the appropriate account/region
    topic_arn = sns_backend.create_topic("some_topic")
    return topic_arn


@pytest.fixture(scope='module', autouse=True)
def wafv2_client():
    with mock_wafv2():
        connection = boto3.client("wafv2", region_name=REGION)
        yield connection


# with patch('botocore.client.BaseClient._make_api_call', new=mock_make_api_call):
#     client = boto3.client('s3')
#     # Should return actual result
#     o = client.get_object(Bucket='my-bucket', Key='my-key')
#     # Should return mocked exception
#     e = client.upload_part_copy()

@pytest.fixture(scope='module', autouse=True)
def set_ip_retention_test_event_setup(ddb_resource):
    event = {
        "detail": {
            "userIdentity": {
                "arn": "fake-arn"
            },
            "eventTime": "2023-04-27T22:33:04Z",
            "requestParameters": {
                "name": "fake-Whitelist-ip-set-name",
                "scope": "CLOUDFRONT",
                "id": "fake-ip-set-id",
                "description": "Allow List for IPV4 addresses",
                "addresses": [
                    "x.x.x.x/32",
                    "y.y.y.y/32",
                    "z.z.z.z/32"
                ],
                "lockToken": "fake-lock-token"
            }
        }
    }
    return event


@pytest.fixture(scope='function')
def missing_request_parameters_test_event_setup():
    event = {
        "detail": {
            "userIdentity": {
                "arn": "fake-arn"
            },
            "eventTime": "2023-04-27T22:33:04Z"
        }
    }
    return event