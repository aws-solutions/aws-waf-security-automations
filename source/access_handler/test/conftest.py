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

import pytest
import boto3
from os import environ
from moto import (
    mock_wafv2,
    mock_cloudwatch
)

@pytest.fixture(scope='module', autouse=True)
def aws_credentials():
    """Mocked AWS Credentials for moto"""
    environ['AWS_ACCESS_KEY_ID'] = 'testing'
    environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    environ['AWS_SECURITY_TOKEN'] = 'testing'
    environ['AWS_SESSION_TOKEN'] = 'testing'
    environ['AWS_DEFAULT_REGION'] = 'us-east-1'
    environ['AWS_REGION'] = 'us-east-1'

@pytest.fixture(scope='session')
def ipset_env_var_setup():
    environ["SCOPE"] = 'ALB'
    environ['IP_SET_NAME_BAD_BOTV4'] = 'IP_SET_NAME_BAD_BOTV4'
    environ['IP_SET_NAME_BAD_BOTV6'] = 'IP_SET_NAME_BAD_BOTV6'
    environ["IP_SET_ID_BAD_BOTV4"] = 'IP_SET_ID_BAD_BOTV4'
    environ['IP_SET_ID_BAD_BOTV6'] = 'IP_SET_ID_BAD_BOTV6'

@pytest.fixture(scope="session")
def wafv2_client():
    with mock_wafv2():
        wafv2_client = boto3.client('wafv2')
        yield wafv2_client

@pytest.fixture(scope="session")
def cloudwatch_client():
    with mock_cloudwatch():
        cloudwatch_client = boto3.client('cloudwatch')
        yield cloudwatch_client

@pytest.fixture(scope="session")
def expected_exception_access_handler_error():
    return "'NoneType' object is not subscriptable"

@pytest.fixture(scope="session") 
def expected_cw_resp():
    return None

@pytest.fixture(scope="session")
def badbot_event():
    return {
        'body': None,
        'headers': {
            'Host': '0xxxx0xx0.execute-api.us-east-2.amazonaws.com',
            'Referer': 'https://us-east-2.console.aws.amazon.com/',
        },
        'httpMethod': 'GET',
        'isBase64Encoded': False,
        'multiValueHeaders': {
            'Accept': [   'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'],
            'Accept-Encoding': ['gzip, deflate, br'],
            'Accept-Language': ['en-US,en;q=0.5'],
            'CloudFront-Forwarded-Proto': ['https'],
            'CloudFront-Is-Desktop-Viewer': ['true'],
            'CloudFront-Is-Mobile-Viewer': ['false'],
            'CloudFront-Is-SmartTV-Viewer': ['false'],
            'CloudFront-Is-Tablet-Viewer': ['false'],
            'CloudFront-Viewer-ASN': ['16509'],
            'CloudFront-Viewer-Country': ['US'],
            'Host': [   '0xxxx0xx0.execute-api.us-east-2.amazonaws.com'],
            'Referer': [   'https://us-east-2.console.aws.amazon.com/'],
            'User-Agent': [   'Mozilla/5.0 (Macintosh; Intel '
                            'Mac OS X 10.15; rv:102.0) '
                            'Gecko/20100101 Firefox/102.0'],
            'Via': [   '2.0 '
                        'fde752a2d4e95c2353cf5fc17ef7bf2a.cloudfront.net '
                        '(CloudFront)'],
            'X-Amz-Cf-Id': [   'eee9ZGRfH0AhZToSkR1ubIekS_uz5ZoaJRvYCg6cMrBnF090iUyIQg=='],
            'X-Amzn-Trace-Id': [   'Root=1-61196a2b-1c401acb6e744c82255d9844'],
            'X-Forwarded-For': ['99.99.99.99, 99.99.99.99'],
            'X-Forwarded-Port': ['443'],
            'X-Forwarded-Proto': ['https'],
            'sec-fetch-dest': ['document'],
            'sec-fetch-mode': ['navigate'],
            'sec-fetch-site': ['cross-site'],
            'sec-fetch-user': ['?1'],
            'upgrade-insecure-requests': ['1']
        },
        'multiValueQueryStringParameters': None,
        'path': '/',
        'pathParameters': None,
        'queryStringParameters': None,
        'requestContext': {
            'accountId': 'xxxxxxxxxxxx',
            'apiId': '0xxxx0xx0',
            'domainName': '0xxxx0xx0.execute-api.us-east-2.amazonaws.com',
            'domainPrefix': '0xxxx0xx0',
            'extendedRequestId': 'D_2GyFwDiYcFofg=',
            'httpMethod': 'GET',
            'identity': {
                'accessKey': None,
                'accountId': None,
                'caller': None,
                'cognitoAuthenticationProvider': None,
                'cognitoAuthenticationType': None,
                'cognitoIdentityId': None,
                'cognitoIdentityPoolId': None,
                'principalOrgId': None,
                'sourceIp': '99.99.99.99',
                'user': None,
                'userAgent': 'Mozilla/5.0 '
                            '(Macintosh; Intel Mac '
                            'OS X 10.15; rv:102.0) '
                            'Gecko/20100101 '
                            'Firefox/102.0',
                'userArn': None
            },
            'path': '/ProdStage',
            'protocol': 'HTTP/1.1',
            'requestId': '4375792d-c6d0-4f84-8a40-d52f5d18dedd',
            'requestTime': '26/Apr/2023:18:15:07 +0000',
            'requestTimeEpoch': 1682532907129,
            'resourceId': 'yw40vqjfia',
            'resourcePath': '/',
            'stage': 'ProdStage'
        },
        'resource': '/',
        'stageVariables': None
    }