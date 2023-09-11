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
from os import environ
from moto import (
    mock_s3,
    mock_logs,
    mock_wafv2
)

class Context:
    def __init__(self, invoked_function_arn, log_group_name, log_stream_name):
       self.invoked_function_arn = invoked_function_arn
       self.log_group_name = log_group_name
       self.log_stream_name = log_stream_name

@pytest.fixture(scope='module', autouse=True)
def aws_credentials():
    """Mocked AWS Credentials for moto"""
    environ['AWS_ACCESS_KEY_ID'] = 'testing'
    environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    environ['AWS_SECURITY_TOKEN'] = 'testing'
    environ['AWS_SESSION_TOKEN'] = 'testing'
    environ['AWS_DEFAULT_REGION'] = 'us-east-1'
    environ['AWS_REGION'] = 'us-east-1'
 
@pytest.fixture(scope="session")
def example_context():
    return Context(':::invoked_function_arn', 'log_group_name', 'log_stream_name')

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
def cloudwatch_client():
    with mock_logs():
        cw_client = boto3.client('logs')
        yield cw_client

@pytest.fixture(scope="session")
def wafv2_client():
    with mock_wafv2():
        wafv2_client = boto3.client('wafv2')
        yield wafv2_client

@pytest.fixture(scope="session")
def configure_cloud_watch_group_retention_event():
    return {
        'LogicalResourceId': 'SetCloudWatchLogGroupRetention',
        'RequestId': 'ea233805-3fcc-4cd3-b27b-72ee1de37fd4',
        'RequestType': 'Create',
        'ResourceProperties': {   
            'AddAthenaPartitionsLambdaName': 'wafohio-AddAthenaPartitions-ECWYudO8kRMS',
            'BadBotParserLambdaName': 'wafohio-BadBotParser-rperXcaWortz',
            'CustomResourceLambdaName': 'wafohio-CustomResource-WnfNLnBqtXPF',
            'CustomTimerLambdaName': 'wafohio-WebACLStack-1218MNWFWK1BN-CustomTimer-FTgDc0Lar0fj',
            'HelperLambdaName': 'wafohio-Helper-QC0crJu0nSgs',
            'LogGroupRetention': '150',
            'LogParserLambdaName': 'wafohio-LogParser-jjx2HJSF27ji',
            'MoveS3LogsForPartitionLambdaName': 'wafohio-MoveS3LogsForPartition-EkJByFiC8sHw',
            'RemoveExpiredIPLambdaName': 'wafohio-RemoveExpiredIP-oZSLjeCA8SKF',
            'ReputationListsParserLambdaName': 'wafohio-ReputationListsParser-uCaQ9xUSb3O5',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
            'SetIPRetentionLambdaName': 'wafohio-SetIPRetention-AhUUa7ZMwuIN',
            'SolutionVersion': 'v4.0-feature-wiq_integrationtestingfix',
            'StackName': 'wafohio'
        },
        'ResourceType': 'Custom::SetCloudWatchLogGroupRetention',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }

@pytest.fixture(scope="session")
def configure_app_access_log_bucket_create_error_event():
    return {
        'LogicalResourceId': 'ConfigureAppAccessLogBucket',
        'RequestId': 'ed758acd-e94b-4f2b-9a3a-935efb325f91',
        'RequestType': 'Create',
        'ResourceProperties': {
            'AccessLoggingBucket': '',
            'AppAccessLogBucket': 'wiq424231042-wafohio-wiq424231042',
            'AppAccessLogBucketPrefix': 'AWSLogs/',
            'LogParser': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-LogParser-jjx2HJSF27ji',
            'MoveS3LogsForPartition': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-MoveS3LogsForPartition-EkJByFiC8sHw',
            'Region': 'us-east-2',
            'ScannersProbesAthenaLogParser': 'yes',
            'ScannersProbesLambdaLogParser': 'no',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF'
        },
        'ResourceType': 'Custom::ConfigureAppAccessLogBucket',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }

@pytest.fixture(scope="session")
def configure_app_access_log_bucket_create_event():
    return {
        'LogicalResourceId': 'ConfigureAppAccessLogBucket',
        'RequestId': 'ed758acd-e94b-4f2b-9a3a-935efb325f91',
        'RequestType': 'Create',
        'ResourceProperties': {
            'AccessLoggingBucket': 'bucket_name',
            'AppAccessLogBucket': 'wiq424231042-wafohio-wiq424231042',
            'AppAccessLogBucketPrefix': 'AWSLogs/',
            'LogParser': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-LogParser-jjx2HJSF27ji',
            'MoveS3LogsForPartition': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-MoveS3LogsForPartition-EkJByFiC8sHw',
            'Region': 'us-east-2',
            'ScannersProbesAthenaLogParser': 'yes',
            'ScannersProbesLambdaLogParser': 'no',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF'
        },
        'ResourceType': 'Custom::ConfigureAppAccessLogBucket',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }

@pytest.fixture(scope="session")
def add_athena_partitions_create_event():
    return {
        'LogicalResourceId': 'CustomAddAthenaPartitions',
        'RequestId': 'e0b5586c-b42d-4e64-b637-8d3eb19b1ff5',
        'RequestType': 'Create',
        'ResourceProperties': {
           'AddAthenaPartitionsLambda': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-AddAthenaPartitions-ECWYudO8kRMS',
            'AppAccessLogBucket': 'wiq424231042-wafohio-wiq424231042',
            'AthenaWorkGroup': 'WAFAddPartitionAthenaQueryWorkGroup-b1af171d-e483-4fbc-a494-43492bfb214a',
            'GlueAccessLogsDatabase': 'wafohio_gon4pq',
            'GlueAppAccessLogsTable': 'app_access_logs',
            'GlueWafAccessLogsTable': 'waf_access_logs',
            'ResourceType': 'CustomResource',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
            'WafLogBucket': 'wafohio-waflogbucket-l1a9qllrsfv4'},
        'ResourceType': 'Custom::AddAthenaPartitions',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }

@pytest.fixture(scope="session")
def generate_waf_log_parser_conf_create_event():
    return {
        'LogicalResourceId': 'GenerateWafLogParserConfFile',
        'RequestId': '142546c5-25e1-48ca-b35f-51cb0f3c41f0',
        'RequestType': 'Create',
        'ResourceProperties': {
            'RequestThreshold': '100',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafmilan424319-CustomResource-oSlRnpIEvNrS',
            'StackName': 'wafmilan424319',
            'WAFBlockPeriod': '240',
            'WafAccessLogBucket': 'bucket_name'
        },
        'ResourceType': 'Custom::GenerateWafLogParserConfFile',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafmilan424319-CustomResource-oSlRnpIEvNrS',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafmilan424319/3736de70-e2ee-11ed-b571-0a54c0d659fa'
    }

@pytest.fixture(scope="session")
def generate_waf_log_parser_conf_update_event():
    return {
        'LogicalResourceId': 'GenerateWafLogParserConfFile',
        'RequestId': '142546c5-25e1-48ca-b35f-51cb0f3c41f0',
        'RequestType': 'Update',
        'ResourceProperties': {
            'RequestThreshold': '100',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafmilan424319-CustomResource-oSlRnpIEvNrS',
            'StackName': 'wafmilan424319',
            'WAFBlockPeriod': '240',
            'WafAccessLogBucket': 'bucket_name'
        },
        'ResourceType': 'Custom::GenerateWafLogParserConfFile',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafmilan424319-CustomResource-oSlRnpIEvNrS',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafmilan424319/3736de70-e2ee-11ed-b571-0a54c0d659fa'
    }

@pytest.fixture(scope="session")
def generate_app_log_parser_conf_create_event():
    return {
        'LogicalResourceId': 'GenerateAppLogParserConfFile',
        'RequestId': '68dde83a-9359-490e-8ddd-dfb513595519',
        'RequestType': 'Create',
        'ResourceProperties': {
            'AppAccessLogBucket': 'bucket_name',
            'ErrorThreshold': '50',
            'ServiceToken': 'arn:aws:lambda:eu-south-1:XXXXXXXXXXXX:function:wafmilan424319-CustomResource-oSlRnpIEvNrS',
            'StackName': 'wafmilan424319',
            'WAFBlockPeriod': '240'
        },
        'ResourceType': 'Custom::GenerateAppLogParserConfFile',
        'ResponseURL': 'https://cloudformation-custom-resource-response-eusouth1.s3.eu-south-1.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:eu-south-1:XXXXXXXXXXXX:function:wafmilan424319-CustomResource-oSlRnpIEvNrS',
        'StackId': 'arn:aws:cloudformation:eu-south-1:XXXXXXXXXXXX:stack/wafmilan424319/3736de70-e2ee-11ed-b571-0a54c0d659fa'
    }

@pytest.fixture(scope="session")
def generate_app_log_parser_conf_update_event():
    return {
        'LogicalResourceId': 'GenerateAppLogParserConfFile',
        'RequestId': '68dde83a-9359-490e-8ddd-dfb513595519',
        'RequestType': 'Update',
        'ResourceProperties': {
            'AppAccessLogBucket': 'bucket_name',
            'ErrorThreshold': '50',
            'ServiceToken': 'arn:aws:lambda:eu-south-1:XXXXXXXXXXXX:function:wafmilan424319-CustomResource-oSlRnpIEvNrS',
            'StackName': 'wafmilan424319',
            'WAFBlockPeriod': '240'
        },
        'ResourceType': 'Custom::GenerateAppLogParserConfFile',
        'ResponseURL': 'https://cloudformation-custom-resource-response-eusouth1.s3.eu-south-1.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:eu-south-1:XXXXXXXXXXXX:function:wafmilan424319-CustomResource-oSlRnpIEvNrS',
        'StackId': 'arn:aws:cloudformation:eu-south-1:XXXXXXXXXXXX:stack/wafmilan424319/3736de70-e2ee-11ed-b571-0a54c0d659fa'
    }

@pytest.fixture(scope="session")
def configure_aws_waf_logs_create_event():
    return {
        'LogicalResourceId': 'ConfigureAWSWAFLogs',
        'RequestId': '25d75d10-c5fa-48da-a79a-d827bfe0a465',
        'RequestType': 'Create',
        'ResourceProperties': {
            'DeliveryStreamArn': 'arn:aws:firehose:us-east-2:XXXXXXXXXXXX:deliverystream/aws-waf-logs-wafohio_xToOQk',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
            'WAFWebACLArn': 'arn:aws:wafv2:us-east-2:XXXXXXXXXXXX:regional/webacl/wafohio/c2e77a1b-6bb3-4d9d-86f9-0bfd9b6fdcaf'
            },
        'ResourceType': 'Custom::ConfigureAWSWAFLogs',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }

@pytest.fixture(scope="session")
def configure_aws_waf_logs_update_event():
    return {
        'LogicalResourceId': 'ConfigureAWSWAFLogs',
        'RequestId': '25d75d10-c5fa-48da-a79a-d827bfe0a465',
        'RequestType': 'Update',
        'ResourceProperties': {
            'DeliveryStreamArn': 'arn:aws:firehose:us-east-2:XXXXXXXXXXXX:deliverystream/aws-waf-logs-wafohio_xToOQk',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
            'WAFWebACLArn': 'arn:aws:wafv2:us-east-2:XXXXXXXXXXXX:regional/webacl/wafohio/c2e77a1b-6bb3-4d9d-86f9-0bfd9b6fdcaf'
            },
        'ResourceType': 'Custom::ConfigureAWSWAFLogs',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }

@pytest.fixture(scope="session")
def configure_aws_waf_logs_delete_event():
    return {
        'LogicalResourceId': 'ConfigureAWSWAFLogs',
        'RequestId': '25d75d10-c5fa-48da-a79a-d827bfe0a465',
        'RequestType': 'Delete',
        'ResourceProperties': {
            'DeliveryStreamArn': 'arn:aws:firehose:us-east-2:XXXXXXXXXXXX:deliverystream/aws-waf-logs-wafohio_xToOQk',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
            'WAFWebACLArn': 'arn:aws:wafv2:us-east-2:XXXXXXXXXXXX:regional/webacl/wafohio/c2e77a1b-6bb3-4d9d-86f9-0bfd9b6fdcaf'
            },
        'ResourceType': 'Custom::ConfigureAWSWAFLogs',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }

@pytest.fixture(scope="session")
def configure_web_acl_delete():
    environ['SCOPE'] = 'REGIONAL'
    return {
        'LogicalResourceId': 'ConfigureWebAcl',
        'RequestId': 'c11604fb-09d1-4d33-a893-ce58369b24dd',
        'RequestType': 'Create',
        'ResourceProperties': {
            'ActivateAWSManagedAIPParam': 'no',
            'ActivateAWSManagedAPParam': 'no',
            'ActivateAWSManagedIPRParam': 'yes',
            'ActivateAWSManagedKBIParam': 'no',
            'ActivateAWSManagedLinuxParam': 'no',
            'ActivateAWSManagedPHPParam': 'no',
            'ActivateAWSManagedPOSIXParam': 'no',
            'ActivateAWSManagedRulesParam': 'no',
            'ActivateAWSManagedSQLParam': 'no',
            'ActivateAWSManagedWPParam': 'no',
            'ActivateAWSManagedWindowsParam': 'no',
            'ActivateBadBotProtectionParam': 'yes',
            'ActivateCrossSiteScriptingProtectionParam': 'yes',
            'ActivateHttpFloodProtectionParam': 'yes - '
                                                'Amazon '
                                                'Athena log '
                                                'parser',
            'ActivateReputationListsProtectionParam': 'yes',
            'ActivateScannersProbesProtectionParam': 'yes - '
                                                    'Amazon '
                                                    'Athena '
                                                    'log '
                                                    'parser',
            'ActivateSqlInjectionProtectionParam': 'yes',
            'ApiGatewayBadBotCWRoleParam': 'no',
            'AppAccessLogBucketLoggingStatusParam': 'yes',
            'AthenaQueryRunTimeScheduleParam': '5',
            'ErrorThreshold': '50',
            'HTTPFloodAthenaQueryGroupByParam': 'None',
            'IPRetentionPeriodAllowedParam': '15',
            'IPRetentionPeriodDeniedParam': '15',
            'KeepDataInOriginalS3Location': 'No',
            'Provisioner': 'cfn',
            'Region': 'us-east-2',
            'RequestThreshold': '100',
            'RequestThresholdByCountryParam': 'no',
            'SNSEmailParam': 'no',
            'SendAnonymizedUsageData': 'Yes',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
            'UUID': 'b1af171d-e483-4fbc-a494-43492bfb214a',
            'UserDefinedAppAccessLogBucketPrefixParam': 'no',
            'Version': 'v4.0-feature-wiq_integrationtestingfix',
            'WAFBadBotSetIPV4': '3fa70158-6584-469a-8ec1-eeb15963752b',
            'WAFBadBotSetIPV4Name': 'wafohioIPBadBotSetIPV4',
            'WAFBadBotSetIPV6': '165dfaa5-edf8-4ad2-8abe-659495875371',
            'WAFBadBotSetIPV6Name': 'wafohioIPBadBotSetIPV6',
            'WAFBlacklistSetIPV4': '5f0c3b63-87d0-481e-869d-afc8d80b1f9b',
            'WAFBlacklistSetIPV4Name': 'wafohioBlacklistSetIPV4',
            'WAFBlacklistSetIPV6': 'aa8d3cb4-d7bc-4ac0-860d-a5214270ebc9',
            'WAFBlacklistSetIPV6Name': 'wafohioBlacklistSetIPV6',
            'WAFBlockPeriod': '240',
            'WAFHttpFloodSetIPV4': '0ce433f3-1d4d-4ab8-a363-312bfeeceab7',
            'WAFHttpFloodSetIPV4Name': 'wafohioHTTPFloodSetIPV4',
            'WAFHttpFloodSetIPV6': 'bc21f6aa-5d0a-4153-9a8b-b8d78e038ba7',
            'WAFHttpFloodSetIPV6Name': 'wafohioHTTPFloodSetIPV6',
            'WAFReputationListsSetIPV4': '81039705-5dcd-4c50-bcf1-de4b37e3019d',
            'WAFReputationListsSetIPV4Name': 'wafohioIPReputationListsSetIPV4',
            'WAFReputationListsSetIPV6': '8238e089-b15e-432d-9983-c8830ffe3cb1',
            'WAFReputationListsSetIPV6Name': 'wafohioIPReputationListsSetIPV6',
            'WAFScannersProbesSetIPV4': '690ebdd5-d5f3-4755-a3cd-005dddd8b114',
            'WAFScannersProbesSetIPV4Name': 'wafohioScannersProbesSetIPV4',
            'WAFScannersProbesSetIPV6': 'd304df05-8a0e-46ae-9b43-e4f0360643c3',
            'WAFScannersProbesSetIPV6Name': 'wafohioScannersProbesSetIPV6',
            'WAFWebACL': 'wafohio|c2e77a1b-6bb3-4d9d-86f9-0bfd9b6fdcaf|REGIONAL',
            'WAFWhitelistSetIPV4': '2c0ff79d-f314-40fa-8dab-cd3d0715d478',
            'WAFWhitelistSetIPV4Name': 'wafohioWhitelistSetIPV4',
            'WAFWhitelistSetIPV6': '6e7dcc41-e6e4-4b44-a2b4-3cfc4278ae52',
            'WAFWhitelistSetIPV6Name': 'wafohioWhitelistSetIPV6'},
        'ResourceType': 'Custom::ConfigureWebAcl',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }

@pytest.fixture(scope="session")
def configure_waf_log_bucket_create_event():
    return {
        'LogicalResourceId': 'ConfigureWafLogBucket',
        'RequestId': '8a93cdcf-bf5f-4a81-89fe-0e7d2e1d4c50',
        'RequestType': 'Create',
        'ResourceProperties': {
            'HttpFloodAthenaLogParser': 'yes',
            'HttpFloodLambdaLogParser': 'no',
            'LogParser': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-LogParser-jjx2HJSF27ji',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
            'WafLogBucket': 'wafohio-waflogbucket-l1a9qllrsfv4'
        },
        'ResourceType': 'Custom::ConfigureWafLogBucket',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }

@pytest.fixture(scope="session")
def configure_waf_log_bucket_delete_event():
    return {
        'LogicalResourceId': 'ConfigureWafLogBucket',
        'PhysicalResourceId': 'ConfigureWafLogBucket',
        'RequestId': '5519325d-9beb-4c68-9ce9-825c8af6e63b',
        'RequestType': 'Delete',
        'ResourceProperties': {
            'HttpFloodAthenaLogParser': 'yes',
            'HttpFloodLambdaLogParser': 'no',
            'LogParser': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-LogParser-jjx2HJSF27ji',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
            'WafLogBucket': 'wafohio-waflogbucket-l1a9qllrsfv4'},
        'ResourceType': 'Custom::ConfigureWafLogBucket',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }

@pytest.fixture(scope="session")
def successful_response():
    return '{"StatusCode": "200", "Body": {"message": "success"}}'

@pytest.fixture(scope="session")
def app_access_log_bucket_create_event_error_response():
    return '{"statusCode": "500", "body": {"message": "An error occurred (MalformedXML) when calling the PutBucketLogging operation: The XML you provided was not well-formed or did not validate against our published schema"}}'

@pytest.fixture(scope="session")
def configure_app_access_log_bucket_delete_event():
    return {
        'LogicalResourceId': 'ConfigureAppAccessLogBucket',
        'PhysicalResourceId': 'ConfigureAppAccessLogBucket',
        'RequestId': '5bd57115-37d7-448e-8e24-863bd66821f9',
        'RequestType': 'Delete',
        'ResourceProperties': {
            'AppAccessLogBucket': 'wiq424231042-wafohio-wiq424231042',
            'AppAccessLogBucketPrefix': 'AWSLogs/',
            'LogParser': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-LogParser-jjx2HJSF27ji',
            'MoveS3LogsForPartition': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-MoveS3LogsForPartition-EkJByFiC8sHw',
            'Region': 'us-east-2',
            'ScannersProbesAthenaLogParser': 'yes',
            'ScannersProbesLambdaLogParser': 'no',
            'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF'
        },
        'ResourceType': 'Custom::ConfigureAppAccessLogBucket',
        'ResponseURL': 'https://cloudformation-custom-resource-response-useast2.s3.us-east-2.amazonaws.com/',
        'ServiceToken': 'arn:aws:lambda:us-east-2:XXXXXXXXXXXX:function:wafohio-CustomResource-WnfNLnBqtXPF',
        'StackId': 'arn:aws:cloudformation:us-east-2:XXXXXXXXXXXX:stack/wafohio/70c177d0-e2c7-11ed-9e83-02ff465f0e71'
    }