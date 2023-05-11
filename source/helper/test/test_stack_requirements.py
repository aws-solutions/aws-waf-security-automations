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

from helper.stack_requirements import (
    StackRequirements, 
    WAF_FOR_CLOUDFRONT_EXCEPTION_MESSAGE,
    INVALID_FLOOD_THRESHOLD_MESSAGE,
    EMPTY_S3_BUCKET_NAME_EXCEPTION_MESSAGE,
    INCORRECT_REGION_S3_LAMBDA_EXCEPTION_MESSAGE,
    ACCESS_ISSUE_S3_BUCKET_EXCEPTION_MESSAGE
)
from moto import (
    mock_s3
)
from uuid import UUID
from lib.boto3_util import create_client
import logging
import boto3


log_level = 'DEBUG'
logging.getLogger().setLevel(log_level)
log = logging.getLogger('test_help')

stack_requirements = StackRequirements(log=log)


def test_create_delivery_stream_name():
    event = {
        'ResourceProperties': {
            'StackName': 'stack-name'
        }
    }
    response_data = {}
    stack_requirements.create_delivery_stream_name(event, response_data)

    expected = 'aws-waf-logs-stackname'
    # ingore randomly generated 7 char suffix
    assert response_data['DeliveryStreamName'][:-7] == expected


def test_normalize_stack_name():
    stack_name = 'test stack name_)(just over thirty two characters'
    suffix = 'adsf13'
    expected = 'test_stack_name_just_over'

    res = stack_requirements.normalize_stack_name(stack_name, suffix)

    assert res == expected

def test_create_db_name():
    event = {
        'ResourceProperties': {
            'StackName': 'stack_name'
        }
    }
    response_data = {}
    expected = 'stack_name'
    stack_requirements.create_db_name(event, response_data)

    # ingore randomly generated 7 char suffix
    assert response_data['DatabaseName'][:-7] == expected


def test_create_uuid():
    response_data = {}
    stack_requirements.create_uuid(response_data)
    try:
        UUID(response_data['UUID'], version=4)
        assert True
    except ValueError:
        assert False


def test_check_app_log_bucket_empty_bucket_name_exception():
    expected = EMPTY_S3_BUCKET_NAME_EXCEPTION_MESSAGE
    try:
        stack_requirements.check_app_log_bucket(region='us-east-1', bucket_name="")
    except Exception as e:
        assert str(e) == expected


@mock_s3
def test_check_app_log_bucket():
    conn = boto3.resource("s3", region_name="us-east-1")
    conn.create_bucket(Bucket="mybucket")

    expected = INCORRECT_REGION_S3_LAMBDA_EXCEPTION_MESSAGE
    try:
        stack_requirements.check_app_log_bucket(region='us-east-2', bucket_name="mybucket")
    except Exception as e:
        assert str(e) == expected


@mock_s3
def test_verify_bucket_region_access_issue():
    region = 'us-east-1'
    conn = boto3.resource("s3", region_name=region)
    conn.create_bucket(Bucket="mybucket1")
    
    expected = ACCESS_ISSUE_S3_BUCKET_EXCEPTION_MESSAGE
    try:
        stack_requirements.verify_bucket_region(
            bucket_name='nonexistent', 
            region=region)
    except Exception as e:
        assert str(e) == expected


def test_check_requirements_invalid_flood_threshold():
    resource_properties = {
        'HttpFloodProtectionLogParserActivated': "yes",
        'HttpFloodProtectionRateBasedRuleActivated': "yes",
        'EndpointType': 'cloudfront',
        'Region': 'us-east-1',
        'RequestThreshold': '10'
    }
    expected = INVALID_FLOOD_THRESHOLD_MESSAGE

    try:
        stack_requirements.check_requirements(resource_properties)
    except Exception as e:
        assert str(e) == expected


def test_is_waf_for_cloudfront():
    resource_properties = {
        'HttpFloodProtectionLogParserActivated': "yes",
        'EndpointType': 'cloudfront',
        'Region': 'us-east-2'
    }
    expected = True
    res = stack_requirements.is_waf_for_cloudfront(resource_properties)
    assert res == expected



def test_is_invalid_flood_threshold():
    resource_properties = {
        'HttpFloodProtectionRateBasedRuleActivated': "yes",
        'RequestThreshold': '10'
    }
    expected = True
    res = stack_requirements.is_invalid_flood_threshold(resource_properties)
    assert res == expected
