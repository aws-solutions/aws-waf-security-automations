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

class Context:
    def __init__(self, invoked_function_arn, log_group_name, log_stream_name):
       self.invoked_function_arn = invoked_function_arn
       self.log_group_name = log_group_name
       self.log_stream_name = log_stream_name


@pytest.fixture(scope="session")
def example_context():
    return Context(':::invoked_function_arn', 'log_group_name', 'log_stream_name')


@pytest.fixture(scope="session")
def timer_event():
    return {
        'LogicalResourceId': 'Timer',
        'RequestId': '25d75d10-c5fa-48da-a79a-d827bfe0a465',
        'RequestType': 'Create',
        'ResourceProperties': {
            'DeliveryStreamArn': 'arn:aws:firehose:us-east-2:XXXXXXXXXXXX:deliverystream/aws-waf-logs-wafohio_xToOQk',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
            'WAFWebACLArn': 'arn:aws:wafv2:us-east-2:XXXXXXXXXXXX:regional/webacl/wafohio/c2e77a1b-6bb3-4d9d-86f9-0bfd9b6fdcaf'
            },
        'ResourceType': 'Custom::Timer',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }