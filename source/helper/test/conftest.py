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

import pytest
import boto3
from moto import (
    mock_s3
)
class Context:
    def __init__(self, invoked_function_arn, log_group_name, log_stream_name):
       self.invoked_function_arn = invoked_function_arn
       self.log_group_name = log_group_name
       self.log_stream_name = log_stream_name

@pytest.fixture(scope="session")
def example_context():
    return Context(':::invoked_function_arn', 'log_group_name', 'log_stream_name')

@pytest.fixture(scope="session")
def successful_response():
    return '{"StatusCode": "200", "Body": {"message": "success"}}'

@pytest.fixture(scope="session")
def error_response():
    return '{"statusCode": "400", "body": {"message": "\'Region\'"}}'

@pytest.fixture(scope="session")
def s3_client():
    with mock_s3():
        s3 = boto3.client('s3')
        yield s3

@pytest.fixture(scope="session")
def s3_bucket(s3_client):
    my_bucket = 'bucket_name'
    s3_client.create_bucket(Bucket=my_bucket)
    return my_bucket

@pytest.fixture(scope="session")
def check_requirements_event():
    return {
        'LogicalResourceId': 'CheckRequirements',
        'RequestId': 'cf0d8086-5b6f-4758-a323-e723925fcb30',
        'RequestType': 'Create',
        'ResourceProperties': {
            'AppAccessLogBucket': 'wiq-wafohio424243-wafohio424243',
            'AthenaLogParser': 'yes',
            'EndpointType': 'ALB',
            'HttpFloodProtectionLogParserActivated': 'yes',
            'HttpFloodProtectionRateBasedRuleActivated': 'no',
            'ProtectionActivatedScannersProbes': 'yes',
            'Region': 'us-east-2',
            'RequestThreshold': '100',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio424243-Helper-xse5nh2WeWlc'},
        'ResourceType': 'Custom::CheckRequirements',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio424243-Helper-xse5nh2WeWlc',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio424243/276aee50-e2e9-11ed-89eb-067ac5804c7f'
    }

@pytest.fixture(scope="session")
def create_uuid_event():
    return {
        'LogicalResourceId': 'CreateUniqueID',
        'RequestId': 'f84694a1-87c0-4ad8-b483-f7b87147514f',
        'RequestType': 'Create',
        'ResourceProperties': {
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio424243-Helper-xse5nh2WeWlc'},
            'ResourceType': 'Custom::CreateUUID',
            'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio424243-Helper-xse5nh2WeWlc',
            'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio424243/276aee50-e2e9-11ed-89eb-067ac5804c7f'
        }

@pytest.fixture(scope="session")
def create_delivery_stream_name_event():
    return {
        'LogicalResourceId': 'CreateDeliveryStreamName',
        'RequestId': '323e36d8-d20b-446f-9b89-7a7895a30fab',
        'RequestType': 'Create',
        'ResourceProperties': {
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio424243-Helper-xse5nh2WeWlc',
            'StackName': 'wafohio424243'
        },
        'ResourceType': 'Custom::CreateDeliveryStreamName',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio424243-Helper-xse5nh2WeWlc',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio424243/276aee50-e2e9-11ed-89eb-067ac5804c7f'
    }


@pytest.fixture(scope="session")
def create_db_name_event():
    return {
        'LogicalResourceId': 'CreateGlueDatabaseName',
        'RequestId': 'e5a8e6c9-3f75-4da9-bcce-c0ac3d2ba823',
        'RequestType': 'Create',
        'ResourceProperties': {
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio424243-Helper-xse5nh2WeWlc',
            'StackName': 'wafohio424243'
        },
        'ResourceType': 'Custom::CreateGlueDatabaseName',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio424243-Helper-xse5nh2WeWlc',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio424243/276aee50-e2e9-11ed-89eb-067ac5804c7f'
    }

@pytest.fixture(scope="session")
def erroneous_check_requirements_event():
    return {
        'LogicalResourceId': 'CheckRequirements',
        'RequestId': 'cf0d8086-5b6f-4758-a323-e723925fcb30',
        'RequestType': 'Create',
        'ResourceProperties': {
            'AthenaLogParser': 'yes',
            'EndpointType': 'ALB',
            'HttpFloodProtectionLogParserActivated': 'yes',
            'HttpFloodProtectionRateBasedRuleActivated': 'no',
            'ProtectionActivatedScannersProbes': 'yes',
            'RequestThreshold': '100',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio424243-Helper-xse5nh2WeWlc'},
        'ResourceType': 'Custom::CheckRequirements',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio424243-Helper-xse5nh2WeWlc',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio424243/276aee50-e2e9-11ed-89eb-067ac5804c7f'
    }
