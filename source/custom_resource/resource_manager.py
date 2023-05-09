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

import json
import botocore
import os
from logging import Logger
from lib.waflibv2 import WAFLIBv2
from lib.boto3_util import create_client
from lib.s3_util import S3
from lib.solution_metrics import send_metrics

AWS_LOGS_PATH_PREFIX = 'AWSLogs/'
S3_OBJECT_CREATED = 's3:ObjectCreated:*'
EMPTY_BUCKET_NAME_EXCEPTION = Exception('Failed to configure access log bucket. Name cannot be empty!')


class ResourceManager:
    def __init__(self, log: Logger):
        self.log = log
        self.waflib = WAFLIBv2()
        self.s3 = S3(log)

    def update_waf_log_bucket(self, event: dict) -> None:
        bucket_lambda_params = self.get_params_bucket_lambda_update_event(event)
        waf_params = self.get_params_waf_event(event)
        self.remove_s3_bucket_lambda_event(**bucket_lambda_params)
        self.add_s3_bucket_lambda_event(**waf_params)

    def update_app_access_log_bucket(self, event: dict) -> None:
        bucket_lambda_params = self.get_params_app_access_update_event(event)
        app_access_params = self.get_params_app_access_update(event)
        self.remove_s3_bucket_lambda_event(**bucket_lambda_params)
        self.add_s3_bucket_lambda_event(**app_access_params)

    def get_params_waf_event(self, event: dict) -> dict:
        params = {}
        resource_props = event.get('ResourceProperties', {})
        params['bucket_name'] = resource_props['WafLogBucket']
        params['lambda_function_arn'] = resource_props.get('LogParser', None)
        params['lambda_log_partition_function_arn'] = None
        params['lambda_parser'] = resource_props['HttpFloodLambdaLogParser'] == 'yes'
        params['athena_parser'] = resource_props['HttpFloodAthenaLogParser'] == 'yes'
        params['bucket_prefix'] = AWS_LOGS_PATH_PREFIX
        return params

    def get_params_app_access_update(self, event: dict) -> dict:
        params = {}
        resource_props = event.get('ResourceProperties', {})
        params['bucket_name'] = resource_props['AppAccessLogBucket']
        params['lambda_function_arn'] = resource_props.get('LogParser', None)
        params['lambda_log_partition_function_arn'] = resource_props.get('MoveS3LogsForPartition', None)
        params['lambda_parser'] = resource_props['ScannersProbesLambdaLogParser'] == 'yes'
        params['athena_parser'] = resource_props['ScannersProbesAthenaLogParser'] == 'yes'
        if resource_props['AppAccessLogBucketPrefix'] != AWS_LOGS_PATH_PREFIX:
            params['bucket_prefix'] = resource_props['AppAccessLogBucketPrefix'] 
        else:
            params['bucket_prefix'] = AWS_LOGS_PATH_PREFIX
        return params

    def get_params_app_access_create_event(self, event: dict) -> dict:
        params = {}
        resource_props = event.get('ResourceProperties', {})
        params['lambda_function_arn'] = resource_props.get('LogParser', None)
        params['lambda_log_partition_function_arn'] = resource_props.get('MoveS3LogsForPartition', None)
        params['bucket_name'] = resource_props['AppAccessLogBucket']
        params['lambda_parser'] = resource_props['ScannersProbesLambdaLogParser'] == 'yes'
        params['athena_parser'] = resource_props['ScannersProbesAthenaLogParser'] == 'yes'
        if resource_props['AppAccessLogBucketPrefix'] != AWS_LOGS_PATH_PREFIX:
            params['bucket_prefix'] = resource_props['AppAccessLogBucketPrefix']
        else:
            params['bucket_prefix'] = AWS_LOGS_PATH_PREFIX
        return params

    # ----------------------------------------------------------------------------------------------------------------------
    # Configure bucket event to call Log Parser whenever a new gz log or athena result file is added to the bucket;
    # call partition s3 log function whenever athena log parser is chosen and a log file is added to the bucket
    # ----------------------------------------------------------------------------------------------------------------------
    
    def add_s3_bucket_lambda_event(self, bucket_name: str, lambda_function_arn: str, lambda_log_partition_function_arn: str, lambda_parser: str,
                               athena_parser: str, bucket_prefix: str) -> None:
        self.log.info("[add_s3_bucket_lambda_event] Start")

        try:
            if lambda_function_arn is not None and (lambda_parser or athena_parser):
                notification_conf = self.s3.get_bucket_notification_configuration(bucket_name)

                self.log.info("[add_s3_bucket_lambda_event] notification_conf:\n %s"
                        % (notification_conf))

                new_conf = {}
                new_conf['LambdaFunctionConfigurations'] = []
        
                if 'TopicConfigurations' in notification_conf:
                    new_conf['TopicConfigurations'] = notification_conf['TopicConfigurations']
        
                if 'QueueConfigurations' in notification_conf:
                    new_conf['QueueConfigurations'] = notification_conf['QueueConfigurations']

                if lambda_parser:
                    new_conf['LambdaFunctionConfigurations'].append({
                        'Id': 'Call Log Parser',
                        'LambdaFunctionArn': lambda_function_arn,
                        'Events': [S3_OBJECT_CREATED],
                        'Filter': {'Key': {'FilterRules': [{'Name': 'suffix', 'Value': 'gz'}]}}
                    })
        
                if athena_parser:
                    new_conf['LambdaFunctionConfigurations'].append({
                        'Id': 'Call Athena Result Parser',
                        'LambdaFunctionArn': lambda_function_arn,
                        'Events': [S3_OBJECT_CREATED],
                        'Filter': {'Key': {'FilterRules': [{'Name': 'prefix', 'Value': 'athena_results/'},
                                                        {'Name': 'suffix', 'Value': 'csv'}]}}
                    })
        
                if lambda_log_partition_function_arn is not None:
                    new_conf['LambdaFunctionConfigurations'].append({
                        'Id': 'Call s3 log partition function',
                        'LambdaFunctionArn': lambda_log_partition_function_arn,
                        'Events': [S3_OBJECT_CREATED],
                        'Filter': {'Key': {
                            'FilterRules': [{'Name': 'prefix', 'Value': bucket_prefix}, {'Name': 'suffix', 'Value': 'gz'}]}}
                    })
        
                self.log.info("[add_s3_bucket_lambda_event] LambdaFunctionConfigurations:\n %s"
                        % (new_conf['LambdaFunctionConfigurations']))
        
                self.s3.put_bucket_notification_configuration(bucket_name=bucket_name, new_conf=new_conf)
        except Exception as error:
            self.log.error(error)
    
        self.log.info("[add_s3_bucket_lambda_event] End")

    def contains_old_app_access_resources(self, event: dict) -> bool:
        resource_props = event.get('ResourceProperties', {})
        old_resource_props = event.get('OldResourceProperties', {})
        old_lambda_app_log_parser_function = old_resource_props.get('LogParser', None)
        old_lambda_partition_s3_logs_function = old_resource_props.get('MoveS3LogsForPartition', None)
        old_lambda_parser = old_resource_props['ScannersProbesLambdaLogParser'] == 'yes'
        old_athena_parser = old_resource_props['ScannersProbesAthenaLogParser'] == 'yes'
        lambda_log_parser_function = resource_props.get('LogParser', None)
        lambda_partition_s3_logs_function = resource_props.get('MoveS3LogsForPartition', None)
        lambda_parser = resource_props['ScannersProbesLambdaLogParser'] == 'yes'
        athena_parser = resource_props['ScannersProbesAthenaLogParser'] == 'yes'

        return old_resource_props['AppAccessLogBucket'] != resource_props['AppAccessLogBucket'] or \
            old_lambda_app_log_parser_function != lambda_log_parser_function or \
            old_lambda_partition_s3_logs_function != lambda_partition_s3_logs_function or \
            old_lambda_parser != lambda_parser or \
            old_athena_parser != athena_parser or \
            ('AppAccessLogBucketPrefix' in resource_props  \
                and ('AppAccessLogBucketPrefix' not in old_resource_props \
                    or old_resource_props['AppAccessLogBucketPrefix']   \
                    != resource_props['AppAccessLogBucketPrefix']  \
                    )
            )
    
    def waf_has_old_resources(self, event: dict) -> bool: 
        resource_props = event.get('ResourceProperties', {})
        old_resource_props = event.get('OldResourceProperties', {})
        lambda_log_parser_function = resource_props.get('LogParser', None)
        lambda_parser = resource_props['HttpFloodLambdaLogParser'] == 'yes'
        athena_parser = resource_props['HttpFloodAthenaLogParser'] == 'yes'
        old_lambda_app_log_parser_function = old_resource_props.get('LogParser', None)
        old_lambda_parser = old_resource_props['HttpFloodLambdaLogParser'] == 'yes'
        old_athena_parser = old_resource_props['HttpFloodAthenaLogParser'] == 'yes'
        old_waf_bucket = old_resource_props['WafLogBucket']
        new_waf_bucket = resource_props['WafLogBucket']

        return old_waf_bucket != new_waf_bucket or \
            old_lambda_app_log_parser_function != lambda_log_parser_function or \
            old_lambda_parser != lambda_parser or \
            old_athena_parser != athena_parser

    # ----------------------------------------------------------------------------------------------------------------------
    # Enable access logging on the App access log bucket
    # ----------------------------------------------------------------------------------------------------------------------
    def put_s3_bucket_access_logging(self, bucket_name: str, access_logging_bucket_name: str) -> None:
        self.log.info("[put_s3_bucket_access_logging] Start") 

        response = self.s3.get_bucket_logging(bucket_name)

        # Enable access logging if not already exists
        if response.get('LoggingEnabled') is None:
            self.s3.put_bucket_logging(
                bucket_name=bucket_name,
                bucket_logging_status={
                    'LoggingEnabled': {
                        'TargetBucket': access_logging_bucket_name,
                        'TargetPrefix': 'AppAccess_Logs/'
                    }
                }
            )
        self.log.info("[put_s3_bucket_access_logging] End")
        

    # ======================================================================================================================
    # Configure Access Log Bucket
    # ======================================================================================================================
    # ----------------------------------------------------------------------------------------------------------------------
    # Create a bucket (if not exist) and configure an event to call Log Parser lambda funcion when new Access log file is
    # created (and stored on this S3 bucket).
    #
    # This function can raise exception if:
    # 01. A empty bucket name is used
    # 02. The bucket already exists and was created in a account that you cant access
    # 03. The bucket already exists and was created in a different region.
    #     You can't trigger log parser lambda function from another region.
    #
    # All those requirements are pre-verified by helper function.
    # ----------------------------------------------------------------------------------------------------------------------
    def configure_s3_bucket(self, event: dict) -> None:
        self.log.info("[configure_s3_bucket] Start")

        region = event['ResourceProperties']['Region']
        bucket_name = event['ResourceProperties']['AppAccessLogBucket']
        access_logging_bucket_name = event.get('ResourceProperties', {}).get('AccessLoggingBucket', None)        

        if bucket_name.strip() == "":
            raise EMPTY_BUCKET_NAME_EXCEPTION

        # ------------------------------------------------------------------------------------------------------------------
        # Create the S3 bucket (if not exist)
        # ------------------------------------------------------------------------------------------------------------------
        try:
            self.s3.head_bucket(bucket_name=bucket_name)

            # Enable access logging if needed
            if access_logging_bucket_name is not None:
                self.put_s3_bucket_access_logging(bucket_name, access_logging_bucket_name)
        except botocore.exceptions.ClientError as e:
            # If a client error is thrown, then check that it was a 404 error.
            # If it was a 404 error, then the bucket does not exist.
            error_code = int(e.response['Error']['Code'])
            if error_code == 404:
                self.create_bucket(bucket_name, region, access_logging_bucket_name)

        self.log.info("[configure_s3_bucket] End")


    def create_bucket(self, bucket_name: str, region: str, access_logging_bucket_name: str):
        self.log.info("[configure_s3_bucket]: %s doesn't exist. Create bucket." % bucket_name)
        
        self.s3.create_bucket(bucket_name, 'private', region)

        # Begin waiting for the S3 bucket, mybucket, to exist
        self.s3.wait_bucket(bucket_name=bucket_name, waiter_name='bucket_exists')

        # Enable server side encryption on the S3 bucket
        self.s3.put_bucket_encryption(
            bucket_name=bucket_name,
            server_side_encryption_conf={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    },
                ]
            }
        )
        
        # block public access
        self.s3.put_public_access_block(
            bucket_name=bucket_name,
            public_access_block_conf={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )

        # Enable access logging
        self.put_s3_bucket_access_logging(bucket_name, access_logging_bucket_name)

    def get_params_bucket_lambda_delete_event(self, event: dict) -> dict:
        params = {}
        resource_props = event.get('ResourceProperties', {})
        params['bucket_name'] = resource_props["WafLogBucket"]
        params['lambda_function_arn'] = resource_props.get('LogParser', None)
        params['lambda_log_partition_function_arn'] = None
        return params
    
    def get_params_bucket_lambda_update_event(self, event: dict) -> dict:
        params = {}
        old_resource_props = event.get('OldResourceProperties', {})
        params['bucket_name'] = old_resource_props["WafLogBucket"]
        params['lambda_function_arn'] = old_resource_props.get('LogParser', None)
        params['lambda_log_partition_function_arn'] = None
        return params
    
    def get_params_app_access_delete_event(self, event: dict) -> dict:
        params = {}
        resource_props = event.get('ResourceProperties', {})
        params['bucket_name'] = resource_props["AppAccessLogBucket"]
        params['lambda_function_arn'] = resource_props.get('LogParser', None)
        params['lambda_log_partition_function_arn'] = resource_props.get('MoveS3LogsForPartition', None)
        return params
    
    def get_params_app_access_update_event(self, event: dict) -> dict:
        params = {}
        old_resource_props = event.get('OldResourceProperties', {})
        params['bucket_name'] = old_resource_props["AppAccessLogBucket"]
        params['lambda_function_arn'] = old_resource_props.get('LogParser', None)
        params['lambda_log_partition_function_arn'] = old_resource_props.get('MoveS3LogsForPartition', None)
        return params

    
    # ----------------------------------------------------------------------------------------------------------------------
    # Clean access log bucket event
    # ----------------------------------------------------------------------------------------------------------------------
    def remove_s3_bucket_lambda_event(self, bucket_name: str, lambda_function_arn: str, lambda_log_partition_function_arn: str) -> None:
        if not lambda_function_arn:
            return
        
        self.log.info("[remove_s3_bucket_lambda_event] Start")

        try:
            new_conf = {}
            notification_conf = self.s3.get_bucket_notification_configuration(bucket_name)

            self.log.info("[remove_s3_bucket_lambda_event]notification_conf:\n {notification_conf}")

            if 'TopicConfigurations' in notification_conf:
                new_conf['TopicConfigurations'] = notification_conf['TopicConfigurations']
            if 'QueueConfigurations' in notification_conf:
                new_conf['QueueConfigurations'] = notification_conf['QueueConfigurations']

            if 'LambdaFunctionConfigurations' in notification_conf:
                new_conf['LambdaFunctionConfigurations'] = []
                self.update_lambda_config(
                    notification_conf,
                    new_conf,
                    lambda_function_arn,
                    lambda_log_partition_function_arn
                    )
                
            self.log.info(f"[remove_s3_bucket_lambda_event]new_conf:\n {new_conf}")
                        
            self.s3.put_bucket_notification_configuration(bucket_name, new_conf)

        except Exception as error:
            self.log.error(
                "Failed to remove S3 Bucket lambda event. Check if the bucket still exists, you own it and has proper access policy.")
            self.log.error(str(error))

        self.log.info("[remove_s3_bucket_lambda_event] End")


    def update_lambda_config(self, notification_conf: dict, new_conf: dict, lambda_function_arn: str, lambda_log_partition_function_arn: str) -> None:
        for lfc in notification_conf['LambdaFunctionConfigurations']:
            if lfc['LambdaFunctionArn'] in {lambda_function_arn, lambda_log_partition_function_arn}:
                self.log.info("[remove_s3_bucket_lambda_event]%s match found, continue." %lfc['LambdaFunctionArn'])
            else:
                new_conf['LambdaFunctionConfigurations'].append(lfc)
                self.log.info("[remove_s3_bucket_lambda_event]lfc appended: %s" %lfc)


    # ======================================================================================================================
    # Configure AWS WAF Logs
    # ======================================================================================================================
    def put_logging_configuration(self, event: dict) -> None:
        self.log.debug("[waflib:put_logging_configuration] Start")

        self.waflib.put_logging_configuration(
            log=self.log,
            web_acl_arn=event['ResourceProperties']['WAFWebACLArn'], 
            delivery_stream_arn=event['ResourceProperties']['DeliveryStreamArn'])

        self.log.debug("[waflib:put_logging_configuration] End")


    def delete_logging_configuration(self, event: dict) -> None:
        self.log.debug("[waflib:delete_logging_configuration] Start")

        self.waflib.delete_logging_configuration(
            log=self.log,
            web_acl_arn=event['ResourceProperties']['WAFWebACLArn'])

        self.log.debug("[waflib:delete_logging_configuration] End")
    

    def update_app_log_parser_conf(self, default_conf: dict, app_access_log_bucket: str, remote_file:str ) -> None:
        try:
            remote_conf = self.s3.read_json_config_file_from_s3(app_access_log_bucket, remote_file)

            if 'general' in remote_conf and 'errorCodes' in remote_conf['general']:
                default_conf['general']['errorCodes'] = remote_conf['general']['errorCodes']

            if 'uriList' in remote_conf:
                default_conf['uriList'] = remote_conf['uriList']

        except Exception as e:
            self.log.debug("[generate_app_log_parser_conf_file] \tFailed to merge existing conf file data.")
            self.log.debug(e)


    # ======================================================================================================================
    # Generate Log Parser Config File
    # ======================================================================================================================
    def generate_app_log_parser_conf_file(self, event: dict, overwrite: bool) -> None:
        stack_name = event['ResourceProperties']['StackName']
        error_threshold = int(event['ResourceProperties']['ErrorThreshold'])
        block_period = int(event['ResourceProperties']['WAFBlockPeriod'])
        app_access_log_bucket = event['ResourceProperties']['AppAccessLogBucket']

        self.log.debug("[generate_app_log_parser_conf_file] Start")

        local_file = '/tmp/' + stack_name + '-app_log_conf_LOCAL.json'
        remote_file = stack_name + '-app_log_conf.json'
        default_conf = {
            'general': {
                'errorThreshold': error_threshold,
                'blockPeriod': block_period,
                'errorCodes': ['400', '401', '403', '404', '405']
            },
            'uriList': {
            }
        }

        if not overwrite:
            self.update_app_log_parser_conf(default_conf, app_access_log_bucket, remote_file)

        with open(local_file, 'w') as outfile:
            json.dump(default_conf, outfile)

        self.s3.upload_file_to_s3(local_file, app_access_log_bucket, remote_file, extra_args={'ContentType': "application/json"})

        self.log.debug("[generate_app_log_parser_conf_file] End")


    def delete_ip_sets(self, event: dict) -> None:
        resource_props = event['ResourceProperties']
        scope = os.getenv('SCOPE')
        if 'WAFWhitelistSetIPV4' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFWhitelistSetIPV4Name'],
                resource_props['WAFWhitelistSetIPV4'])
        if 'WAFBlacklistSetIPV4' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFBlacklistSetIPV4Name'],
                resource_props['WAFBlacklistSetIPV4'])
        if 'WAFHttpFloodSetIPV4' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFHttpFloodSetIPV4Name'],
                resource_props['WAFHttpFloodSetIPV4'])
        if 'WAFScannersProbesSetIPV4' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFScannersProbesSetIPV4Name'],
                resource_props['WAFScannersProbesSetIPV4'])
        if 'WAFReputationListsSetIPV4' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFReputationListsSetIPV4Name'],
                resource_props['WAFReputationListsSetIPV4'])
        if 'WAFBadBotSetIPV4' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFBadBotSetIPV4Name'],
                resource_props['WAFBadBotSetIPV4'])
        if 'WAFWhitelistSetIPV6' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFWhitelistSetIPV6Name'],
                resource_props['WAFWhitelistSetIPV6'])                    
        if 'WAFBlacklistSetIPV6' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFBlacklistSetIPV6Name'],
                resource_props['WAFBlacklistSetIPV6'])
        if 'WAFHttpFloodSetIPV6' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFHttpFloodSetIPV6Name'],
                resource_props['WAFHttpFloodSetIPV6'])
        if 'WAFScannersProbesSetIPV6' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFScannersProbesSetIPV6Name'],
                resource_props['WAFScannersProbesSetIPV6'])
        if 'WAFReputationListsSetIPV6' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFReputationListsSetIPV6Name'],
                resource_props['WAFReputationListsSetIPV6'])                    
        if 'WAFBadBotSetIPV6' in resource_props:
            self.waflib.delete_ip_set(
                self.log,
                scope,
                resource_props['WAFBadBotSetIPV6Name'],
                resource_props['WAFBadBotSetIPV6'])

    
    def update_waf_log_parser_conf(self, default_conf: dict, waf_access_log_bucket: str) -> None:
        try:
            remote_conf = self.s3.read_json_config_file_from_s3(waf_access_log_bucket, remote_conf)

            if 'general' in remote_conf and 'ignoredSufixes' in remote_conf['general']:
                default_conf['general']['ignoredSufixes'] = remote_conf['general']['ignoredSufixes']

            if 'uriList' in remote_conf:
                default_conf['uriList'] = remote_conf['uriList']

        except Exception as e:
            self.log.debug("[generate_waf_log_parser_conf_file] \tFailed to merge existing conf file data.")
            self.log.debug(e)


    def generate_waf_log_parser_conf_file(self, event: dict, overwrite: bool) -> None:
        self.log.debug("[generate_waf_log_parser_conf_file] Start")

        resource_props = event['ResourceProperties']
        stack_name = resource_props['StackName']
        request_threshold = int(resource_props['RequestThreshold'])
        block_period = int(resource_props['WAFBlockPeriod'])
        waf_access_log_bucket = resource_props['WafAccessLogBucket']

        local_file = '/tmp/' + stack_name + '-waf_log_conf_LOCAL.json'
        remote_file = stack_name + '-waf_log_conf.json'
        default_conf = {
            'general': {
                'requestThreshold': request_threshold,
                'blockPeriod': block_period,
                'ignoredSufixes': []
            },
            'uriList': {
            }
        }

        if not overwrite:
            self.update_waf_log_parser_conf(default_conf, waf_access_log_bucket)

        with open(local_file, 'w') as outfile:
            json.dump(default_conf, outfile)

        self.s3.upload_file_to_s3(local_file, waf_access_log_bucket, remote_file, extra_args={'ContentType': "application/json"})

        self.log.debug("[generate_waf_log_parser_conf_file] End")
    
    # ======================================================================================================================
    # Add Athena Partitions
    # ======================================================================================================================
    def add_athena_partitions(self, event: dict) ->  None:
        self.log.info("[add_athena_partitions] Start")
        resource_props = event['ResourceProperties']

        lambda_client = create_client('lambda')
        response = lambda_client.invoke(
            FunctionName=resource_props['AddAthenaPartitionsLambda'].rsplit(":", 1)[-1],
            Payload="""{
                "resourceType":"%s",
                "glueAccessLogsDatabase":"%s",
                "accessLogBucket":"%s",
                "glueAppAccessLogsTable":"%s",
                "glueWafAccessLogsTable":"%s",
                "wafLogBucket":"%s",
                "athenaWorkGroup":"%s"
             }""" % (
                resource_props['ResourceType'],
                resource_props['GlueAccessLogsDatabase'],
                resource_props['AppAccessLogBucket'],
                resource_props['GlueAppAccessLogsTable'], 
                resource_props['GlueWafAccessLogsTable'],
                resource_props['WafLogBucket'], 
                resource_props['AthenaWorkGroup']
                )
        )
        self.log.info("[add_athena_partitions] Lambda invocation response:\n%s" % response)
        self.log.info("[add_athena_partitions] End")
    
    
    # ======================================================================================================================
    # Auxiliary Functions
    # ======================================================================================================================
    def send_anonymous_usage_data(self, action_type, resource_properties):
        try:
            if 'SendAnonymousUsageData' not in resource_properties or resource_properties[
                'SendAnonymousUsageData'].lower() != 'yes':
                return
            self.log.info("[send_anonymous_usage_data] Start")

            usage_data = {
                        "version": resource_properties['Version'],
                        "data_type": "custom_resource",
                        "region": resource_properties['Region'],
                        "action": action_type,
                        "sql_injection_protection": resource_properties['ActivateSqlInjectionProtectionParam'],
                        "xss_scripting_protection": resource_properties['ActivateCrossSiteScriptingProtectionParam'],
                        "http_flood_protection": resource_properties['ActivateHttpFloodProtectionParam'],
                        "scanners_probes_protection": resource_properties['ActivateScannersProbesProtectionParam'],
                        "reputation_lists_protection": resource_properties['ActivateReputationListsProtectionParam'],
                        "bad_bot_protection": resource_properties['ActivateBadBotProtectionParam'],
                        "existing_api_gateway_badbot_cw_role": resource_properties['ApiGatewayBadBotCWRoleParam'],
                        "request_threshold": resource_properties['RequestThreshold'],
                        "error_threshold": resource_properties['ErrorThreshold'],
                        "waf_block_period": resource_properties['WAFBlockPeriod'],
                        "aws_managed_rules": resource_properties['ActivateAWSManagedRulesParam'],
                        "amr_admin_protection": resource_properties['ActivateAWSManagedAPParam'],
                        "amr_known_bad_input": resource_properties['ActivateAWSManagedKBIParam'],
                        "amr_ip_reputation": resource_properties['ActivateAWSManagedIPRParam'],
                        "amr_anonymous_ip": resource_properties['ActivateAWSManagedAIPParam'],
                        "amr_sql": resource_properties['ActivateAWSManagedSQLParam'],
                        "amr_linux": resource_properties['ActivateAWSManagedLinuxParam'],
                        "amr_posix": resource_properties['ActivateAWSManagedPOSIXParam'],
                        "amr_windows": resource_properties['ActivateAWSManagedWindowsParam'],
                        "amr_php": resource_properties['ActivateAWSManagedPHPParam'],
                        "amr_wordpress": resource_properties['ActivateAWSManagedWPParam'],
                        "keep_original_s3_data": resource_properties['KeepDataInOriginalS3Location'],
                        "allowed_ip_retention_period_minute": resource_properties['IPRetentionPeriodAllowedParam'],
                        "denied_ip_retention_period_minute": resource_properties['IPRetentionPeriodDeniedParam'],
                        "sns_email_notification": resource_properties['SNSEmailParam'],
                        "user_defined_app_access_log_bucket_prefix":
                            resource_properties['UserDefinedAppAccessLogBucketPrefixParam'],
                        "app_access_log_bucket_logging_enabled_by_user":
                            resource_properties['AppAccessLogBucketLoggingStatusParam'],
                        "request_threshold_by_country":
                            resource_properties['RequestThresholdByCountryParam'],                    
                        "http_flood_athena_query_group_by":
                            resource_properties['HTTPFloodAthenaQueryGroupByParam'],
                        "athena_query_run_time_schedule":
                            resource_properties['AthenaQueryRunTimeScheduleParam'],
                        "provisioner": resource_properties['Provisioner'] if "Provisioner" in resource_properties else "cfn" 
            }

            # --------------------------------------------------------------------------------------------------------------
            self.log.info("[send_anonymous_usage_data] Send Data")
            # --------------------------------------------------------------------------------------------------------------
            response = send_metrics(data=usage_data)
            response_code = response.status_code
            self.log.info('[send_anonymous_usage_data] Response Code: {}'.format(response_code))
            self.log.info("[send_anonymous_usage_data] End")

        except Exception as error:
            self.log.debug("[send_anonymous_usage_data] Failed to Send Data")
            self.log.debug(str(error))
