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

from lib.boto3_util import create_client

TRUNC_STACK_NAME_MAX_LEN = 20

class LogGroupRetention:
    def __init__(self, log):
        self.log = log

    def update_retention(self, event):
        cloudwatch = create_client('logs')

        log_group_prefix = self.get_log_group_prefix(
            stack_name=event['ResourceProperties']['StackName']
        )

        log_groups = cloudwatch.describe_log_groups(
            logGroupNamePrefix=log_group_prefix
        )
        
        lambda_names = self.get_lambda_names(
            resource_props=event['ResourceProperties']
        )

        self.set_log_group_retention(
            client=cloudwatch,
            log_groups=log_groups,
            lambda_names=lambda_names,
            retention_period=int(event['ResourceProperties']['LogGroupRetention'])
        )


    def get_lambda_names(self, resource_props):
        lambdas = [
            'CustomResourceLambdaName', 
            'MoveS3LogsForPartitionLambdaName',
            'AddAthenaPartitionsLambdaName',
            'SetIPRetentionLambdaName',
            'RemoveExpiredIPLambdaName',
            'ReputationListsParserLambdaName',
            'BadBotParserLambdaName',
            'HelperLambdaName',
            'LogParserLambdaName',
            'CustomTimerLambdaName'
        ]
        lambda_names = set()
        for lam in lambdas:
            lambda_name = resource_props.get(lam,'')
            if lambda_name:
                lambda_names.add(f'/aws/lambda/{lambda_name}')
        return lambda_names


    def truncate_stack_name(self, stack_name):
        # in case StackName is too long (up to 128 chars), 
        # lambda function name (up to 64 chars) will use a truncated StackName
        if len(stack_name) < TRUNC_STACK_NAME_MAX_LEN:
            return stack_name
        return stack_name[0:TRUNC_STACK_NAME_MAX_LEN]


    def get_log_group_prefix(self, stack_name):
        truncated_stack_name = self.truncate_stack_name(stack_name)
        return f'/aws/lambda/{truncated_stack_name}'


    def set_log_group_retention(self, client, log_groups, lambda_names, retention_period):
        for log_group in log_groups['logGroups']:
            if log_group['logGroupName'] in lambda_names:
                client.put_retention_policy(
                    logGroupName = log_group['logGroupName'],
                    retentionInDays = int(retention_period) 
                )
                self.log.info(f'put retention for log group {log_group["logGroupName"]}')