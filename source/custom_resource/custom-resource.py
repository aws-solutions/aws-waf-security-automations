######################################################################################################################
#  Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
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

import boto3
import botocore
import json
import logging
import datetime
import requests
import os
import time
from lib.waflibv2 import WAFLIBv2
from lib.solution_metrics import send_metrics

waflib = WAFLIBv2()

logging.getLogger().debug('Loading function')


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
def configure_s3_bucket(log, region, bucket_name):
    log.info("[configure_s3_bucket] Start")

    if bucket_name.strip() == "":
        raise Exception('Failed to configure access log bucket. Name cannot be empty!')

    # ------------------------------------------------------------------------------------------------------------------
    # Create the S3 bucket (if not exist)
    # ------------------------------------------------------------------------------------------------------------------
    s3_client = boto3.client('s3')

    try:
        response = s3_client.head_bucket(Bucket=bucket_name)
        log.info("[configure_s3_bucket]response head_bucket: \n%s" % response)
    except botocore.exceptions.ClientError as e:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            log.info("[configure_s3_bucket]: %s doesn't exist. Create bucket." % bucket_name)
            if region == 'us-east-1':
                s3_client.create_bucket(Bucket=bucket_name, ACL='private')
            else:
                s3_client.create_bucket(Bucket=bucket_name, ACL='private',
                                        CreateBucketConfiguration={'LocationConstraint': region})

            # Begin waiting for the S3 bucket, mybucket, to exist
            s3_bucket_exists_waiter = s3_client.get_waiter('bucket_exists')
            s3_bucket_exists_waiter.wait(Bucket=bucket_name)

            # Enable server side encryption on the S3 bucket
            response = s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        },
                    ]
                }
            )
            log.info("[configure_s3_bucket]response put_bucket_encryption: \n%s" % response)
            
            # block public access
            response = s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            log.info("[configure_s3_bucket]response put_public_access_block: \n%s" % response)
    log.info("[configure_s3_bucket] End")


# ----------------------------------------------------------------------------------------------------------------------
# Configure bucket event to call Log Parser whenever a new gz log or athena result file is added to the bucket;
# call partition s3 log function whenever athena log parser is chosen and a log file is added to the bucket
# ----------------------------------------------------------------------------------------------------------------------
def add_s3_bucket_lambda_event(log, bucket_name, lambda_function_arn, lambda_log_partition_function_arn, lambda_parser,
                               athena_parser):
    log.info("[add_s3_bucket_lambda_event] Start")
    
    try:
        s3_client = boto3.client('s3')
        if lambda_function_arn is not None and (lambda_parser or athena_parser):
            notification_conf = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)

            log.info("[add_s3_bucket_lambda_event] notification_conf:\n %s"
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
                    'Events': ['s3:ObjectCreated:*'],
                    'Filter': {'Key': {'FilterRules': [{'Name': 'suffix', 'Value': 'gz'}]}}
                })
    
            if athena_parser:
                new_conf['LambdaFunctionConfigurations'].append({
                    'Id': 'Call Athena Result Parser',
                    'LambdaFunctionArn': lambda_function_arn,
                    'Events': ['s3:ObjectCreated:*'],
                    'Filter': {'Key': {'FilterRules': [{'Name': 'prefix', 'Value': 'athena_results/'},
                                                       {'Name': 'suffix', 'Value': 'csv'}]}}
                })
    
            if lambda_log_partition_function_arn is not None:
                new_conf['LambdaFunctionConfigurations'].append({
                    'Id': 'Call s3 log partition function',
                    'LambdaFunctionArn': lambda_log_partition_function_arn,
                    'Events': ['s3:ObjectCreated:*'],
                    'Filter': {'Key': {
                        'FilterRules': [{'Name': 'prefix', 'Value': 'AWSLogs/'}, {'Name': 'suffix', 'Value': 'gz'}]}}
                })
    
            log.info("[add_s3_bucket_lambda_event] LambdaFunctionConfigurations:\n %s"
                     % (new_conf['LambdaFunctionConfigurations']))
    
            s3_client.put_bucket_notification_configuration(Bucket=bucket_name, NotificationConfiguration=new_conf)
    except Exception as error:
        log.error(error)
 
    log.info("[add_s3_bucket_lambda_event] End")


# ----------------------------------------------------------------------------------------------------------------------
# Clean access log bucket event
# ----------------------------------------------------------------------------------------------------------------------
def remove_s3_bucket_lambda_event(log, bucket_name, lambda_function_arn, lambda_log_partition_function_arn):
    if lambda_function_arn != None:
        log.info("[remove_s3_bucket_lambda_event] Start")

        s3_client = boto3.client('s3')
        try:
            new_conf = {}
            notification_conf = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)

            log.info("[remove_s3_bucket_lambda_event]notification_conf:\n %s"
                    % (notification_conf))

            if 'TopicConfigurations' in notification_conf:
                new_conf['TopicConfigurations'] = notification_conf['TopicConfigurations']
            if 'QueueConfigurations' in notification_conf:
                new_conf['QueueConfigurations'] = notification_conf['QueueConfigurations']

            if 'LambdaFunctionConfigurations' in notification_conf:
                new_conf['LambdaFunctionConfigurations'] = []
                for lfc in notification_conf['LambdaFunctionConfigurations']:
                    if lfc['LambdaFunctionArn'] == lambda_function_arn or  \
                       lfc['LambdaFunctionArn'] == lambda_log_partition_function_arn:
                        log.info("[remove_s3_bucket_lambda_event]%s match found, continue." %lfc['LambdaFunctionArn'])
                        continue  # remove all references
                    else:
                        new_conf['LambdaFunctionConfigurations'].append(lfc)
                        log.info("[remove_s3_bucket_lambda_event]lfc appended: %s" %lfc)

            log.info("[remove_s3_bucket_lambda_event]new_conf:\n %s"
                     % (new_conf))
                        
            s3_client.put_bucket_notification_configuration(Bucket=bucket_name, NotificationConfiguration=new_conf)

        except Exception as error:
            log.error(
                "Failed to remove S3 Bucket lambda event. Check if the bucket still exists, you own it and has proper access policy.")
            log.error(str(error))

        log.info("[remove_s3_bucket_lambda_event] End")


#======================================================================================================================
# Configure Web ACl
#======================================================================================================================
def delete_ip_set(log, scope, ip_set_name, ip_set_id):
    try:
        log.info("[delete_ip_set] Start deleting IP set: name - %s, id - %s"%(ip_set_name, ip_set_id))

        response = waflib.delete_ip_set(log, scope, ip_set_name, ip_set_id)
        if response is None:
            log.info("[delete_ip_set] IP set has already been deleted: name - %s, id - %s"%(ip_set_name, ip_set_id))
            return None

        log.info(response)
        log.info("[delete_ip_set] End deleting IP set: name - %s, id - %s"%(ip_set_name, ip_set_id))

        # sleep for a few seconds at the end of each call to avoid API throttling
        time.sleep(8)
    except Exception as error:
        log.info("[delete_ip_set] Failed to delete IP set: name - %s, id - %s"%(ip_set_name, ip_set_id))
        log.error(str(error))


# ======================================================================================================================
# Configure AWS WAF Logs
# ======================================================================================================================
def put_logging_configuration(log, web_acl_arn, delivery_stream_arn):
    log.debug("[waflib:put_logging_configuration] Start")

    waflib.put_logging_configuration(log, web_acl_arn, delivery_stream_arn)

    log.debug("[waflib:put_logging_configuration] End")


def delete_logging_configuration(log, web_acl_arn):
    log.debug("[waflib:delete_logging_configuration] Start")

    waflib.delete_logging_configuration(log, web_acl_arn)

    log.debug("[waflib:delete_logging_configuration] End")


# ======================================================================================================================
# Generate Log Parser Config File
# ======================================================================================================================
def generate_app_log_parser_conf_file(log, stack_name, error_threshold, block_period, app_access_log_bucket, overwrite):
    log.debug("[generate_app_log_parser_conf_file] Start")

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
        try:
            s3 = boto3.resource('s3')
            file_obj = s3.Object(app_access_log_bucket, remote_file)
            file_content = file_obj.get()['Body'].read()
            remote_conf = json.loads(file_content)

            if 'general' in remote_conf and 'errorCodes' in remote_conf['general']:
                default_conf['general']['errorCodes'] = remote_conf['general']['errorCodes']

            if 'uriList' in remote_conf:
                default_conf['uriList'] = remote_conf['uriList']

        except Exception as e:
            log.debug("[generate_app_log_parser_conf_file] \tFailed to merge existing conf file data.")
            log.debug(e)

    with open(local_file, 'w') as outfile:
        json.dump(default_conf, outfile)

    s3_client = boto3.client('s3')
    s3_client.upload_file(local_file, app_access_log_bucket, remote_file, ExtraArgs={'ContentType': "application/json"})

    log.debug("[generate_app_log_parser_conf_file] End")


def generate_waf_log_parser_conf_file(log, stack_name, request_threshold, block_period, waf_access_log_bucket,
                                      overwrite):
    log.debug("[generate_waf_log_parser_conf_file] Start")

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
        try:
            s3 = boto3.resource('s3')
            file_obj = s3.Object(waf_access_log_bucket, remote_file)
            file_content = file_obj.get()['Body'].read()
            remote_conf = json.loads(file_content)

            if 'general' in remote_conf and 'ignoredSufixes' in remote_conf['general']:
                default_conf['general']['ignoredSufixes'] = remote_conf['general']['ignoredSufixes']

            if 'uriList' in remote_conf:
                default_conf['uriList'] = remote_conf['uriList']

        except Exception as e:
            log.debug("[generate_waf_log_parser_conf_file] \tFailed to merge existing conf file data.")
            log.debug(e)

    with open(local_file, 'w') as outfile:
        json.dump(default_conf, outfile)

    s3_client = boto3.client('s3')
    s3_client.upload_file(local_file, waf_access_log_bucket, remote_file, ExtraArgs={'ContentType': "application/json"})

    log.debug("[generate_waf_log_parser_conf_file] End")


# ======================================================================================================================
# Add Athena Partitions
# ======================================================================================================================
def add_athena_partitions(log, add_athena_partition_lambda_function, resource_type,
                          glue_database, access_log_bucket, glue_access_log_table,
                          glue_waf_log_table, waf_log_bucket, athena_work_group):
    log.info("[add_athena_partitions] Start")

    lambda_client = boto3.client('lambda')
    response = lambda_client.invoke(
        FunctionName=add_athena_partition_lambda_function.rsplit(":", 1)[-1],
        Payload="""{
                "resourceType":"%s",
                "glueAccessLogsDatabase":"%s",
                "accessLogBucket":"%s",
                "glueAppAccessLogsTable":"%s",
                "glueWafAccessLogsTable":"%s",
                "wafLogBucket":"%s",
                "athenaWorkGroup":"%s"
            }""" % (resource_type, glue_database, access_log_bucket,
                    glue_access_log_table, glue_waf_log_table,
                    waf_log_bucket, athena_work_group)
    )
    log.info("[add_athena_partitions] Lambda invocation response:\n%s" % response)
    log.info("[add_athena_partitions] End")


# ======================================================================================================================
# Auxiliary Functions
# ======================================================================================================================
def send_response(log, event, context, responseStatus, responseData, resourceId, reason=None):
    log.debug("[send_response] Start")

    responseUrl = event['ResponseURL']
    cw_logs_url = "https://console.aws.amazon.com/cloudwatch/home?region=%s#logEventViewer:group=%s;stream=%s" % (
        context.invoked_function_arn.split(':')[3], context.log_group_name, context.log_stream_name)

    log.info(responseUrl)
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = reason or ('See the details in CloudWatch Logs: ' + cw_logs_url)
    responseBody['PhysicalResourceId'] = resourceId
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = False
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)
    log.debug("Response body:\n" + json_responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        log.debug("Status code: " + response.reason)

    except Exception as error:
        log.error("[send_response] Failed executing requests.put(..)")
        log.error(str(error))

    log.debug("[send_response] End")


def send_anonymous_usage_data(log, action_type, resource_properties):
    try:
        if 'SendAnonymousUsageData' not in resource_properties or resource_properties[
            'SendAnonymousUsageData'].lower() != 'yes':
            return
        log.info("[send_anonymous_usage_data] Start")

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
                    "request_threshold": resource_properties['RequestThreshold'],
                    "error_threshold": resource_properties['ErrorThreshold'],
                    "waf_block_period": resource_properties['WAFBlockPeriod'],
                    "aws_managed_rules": resource_properties['ActivateAWSManagedRulesParam'],
                    "keep_original_s3_data": resource_properties['KeepDataInOriginalS3Location']
        }

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Send Data")
        # --------------------------------------------------------------------------------------------------------------
        response = send_metrics(data=usage_data)
        response_code = response.status_code
        log.info('[send_anonymous_usage_data] Response Code: {}'.format(response_code))
        log.info("[send_anonymous_usage_data] End")

    except Exception as error:
        log.debug("[send_anonymous_usage_data] Failed to Send Data")
        log.debug(str(error))


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
def lambda_handler(event, context):
    log = logging.getLogger()
    responseStatus = 'SUCCESS'
    reason = None
    responseData = {}
    resourceId = event['PhysicalResourceId'] if 'PhysicalResourceId' in event else event['LogicalResourceId']
    result = {
        'StatusCode': '200',
        'Body': {'message': 'success'}
    }

    try:
        # ------------------------------------------------------------------
        # Set Log Level
        # ------------------------------------------------------------------
        log_level = str(os.getenv('LOG_LEVEL').upper())
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            log_level = 'ERROR'
        log.setLevel(log_level)

        # ----------------------------------------------------------
        # Read inputs parameters
        # ----------------------------------------------------------
        log.info(event)
        request_type = event['RequestType'].upper() if ('RequestType' in event) else ""
        log.info(request_type)

        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        if event['ResourceType'] == "Custom::ConfigureAppAccessLogBucket":
            lambda_log_parser_function = event['ResourceProperties']['LogParser'] if 'LogParser' in event[
                'ResourceProperties'] else None
            lambda_partition_s3_logs_function = event['ResourceProperties'][
                'MoveS3LogsForPartition'] if 'MoveS3LogsForPartition' in event['ResourceProperties'] else None
            lambda_parser = True if event['ResourceProperties']['ScannersProbesLambdaLogParser'] == 'yes' else False
            athena_parser = True if event['ResourceProperties']['ScannersProbesAthenaLogParser'] == 'yes' else False

            if 'CREATE' in request_type:
                configure_s3_bucket(log, event['ResourceProperties']['Region'],
                                    event['ResourceProperties']['AppAccessLogBucket'])
                add_s3_bucket_lambda_event(log, event['ResourceProperties']['AppAccessLogBucket'],
                                           lambda_log_parser_function,
                                           lambda_partition_s3_logs_function,
                                           lambda_parser,
                                           athena_parser)

            elif 'UPDATE' in request_type:
                old_lambda_app_log_parser_function = event['OldResourceProperties']['LogParser'] if 'LogParser' in \
                                                                                                    event[
                                                                                                        'OldResourceProperties'] else None
                old_lambda_partition_s3_logs_function = event['OldResourceProperties']['MoveS3LogsForPartition'] \
                    if 'MoveS3LogsForPartition' in event['OldResourceProperties'] else None
                old_lambda_parser = True if event['OldResourceProperties'][
                                                'ScannersProbesLambdaLogParser'] == 'yes' else False
                old_athena_parser = True if event['OldResourceProperties'][
                                                'ScannersProbesAthenaLogParser'] == 'yes' else False

                if (event['OldResourceProperties']['AppAccessLogBucket'] != event['ResourceProperties'][
                    'AppAccessLogBucket'] or
                        old_lambda_app_log_parser_function != lambda_log_parser_function or
                        old_lambda_partition_s3_logs_function != lambda_partition_s3_logs_function or
                        old_lambda_parser != lambda_parser or
                        old_athena_parser != athena_parser):

                    remove_s3_bucket_lambda_event(log, event['OldResourceProperties']["AppAccessLogBucket"],
                                                  old_lambda_app_log_parser_function,
                                                  old_lambda_partition_s3_logs_function)
                    add_s3_bucket_lambda_event(log, event['ResourceProperties']['AppAccessLogBucket'],
                                               lambda_log_parser_function,
                                               lambda_partition_s3_logs_function,
                                               lambda_parser,
                                               athena_parser)

            elif 'DELETE' in request_type:
                remove_s3_bucket_lambda_event(log, event['ResourceProperties']["AppAccessLogBucket"],
                                              lambda_log_parser_function, lambda_partition_s3_logs_function)
        elif event['ResourceType'] == "Custom::ConfigureWafLogBucket":
            lambda_log_parser_function = event['ResourceProperties']['LogParser'] if 'LogParser' in event[
                'ResourceProperties'] else None
            lambda_partition_s3_logs_function = None
            lambda_parser = True if event['ResourceProperties']['HttpFloodLambdaLogParser'] == 'yes' else False
            athena_parser = True if event['ResourceProperties']['HttpFloodAthenaLogParser'] == 'yes' else False

            if 'CREATE' in request_type:
                add_s3_bucket_lambda_event(log, event['ResourceProperties']['WafLogBucket'],
                                           lambda_log_parser_function,
                                           lambda_partition_s3_logs_function,
                                           lambda_parser,
                                           athena_parser)

            elif 'UPDATE' in request_type:
                old_lambda_app_log_parser_function = event['OldResourceProperties']['LogParser'] if 'LogParser' in \
                                                                                                    event[
                                                                                                        'OldResourceProperties'] else None
                old_lambda_parser = True if event['OldResourceProperties'][
                                                'HttpFloodLambdaLogParser'] == 'yes' else False
                old_athena_parser = True if event['OldResourceProperties'][
                                                'HttpFloodAthenaLogParser'] == 'yes' else False

                if (event['OldResourceProperties']['WafLogBucket'] != event['ResourceProperties']['WafLogBucket'] or
                        old_lambda_app_log_parser_function != lambda_log_parser_function or
                        old_lambda_parser != lambda_parser or
                        old_athena_parser != athena_parser):
                    remove_s3_bucket_lambda_event(log, event['OldResourceProperties']["WafLogBucket"],
                                                  old_lambda_app_log_parser_function,
                                                  lambda_partition_s3_logs_function)
                    add_s3_bucket_lambda_event(log, event['ResourceProperties']['WafLogBucket'],
                                               lambda_log_parser_function,
                                               lambda_partition_s3_logs_function,
                                               lambda_parser,
                                               athena_parser)

            elif 'DELETE' in request_type:
                remove_s3_bucket_lambda_event(log, event['ResourceProperties']["WafLogBucket"],
                                              lambda_log_parser_function,
                                              lambda_partition_s3_logs_function)

        elif event['ResourceType'] == "Custom::ConfigureWebAcl":
            # Manually delete ip sets to avoid throttling occurred during stack deletion due to API call limit 
            if 'DELETE' in request_type:
                scope = os.getenv('SCOPE')
                if 'WAFWhitelistSetIPV4' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFWhitelistSetIPV4Name'],
                                  event['ResourceProperties']['WAFWhitelistSetIPV4'])
                if 'WAFBlacklistSetIPV4' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFBlacklistSetIPV4Name'],
                                  event['ResourceProperties']['WAFBlacklistSetIPV4'])
                if 'WAFHttpFloodSetIPV4' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFHttpFloodSetIPV4Name'],
                                  event['ResourceProperties']['WAFHttpFloodSetIPV4'])
                if 'WAFScannersProbesSetIPV4' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFScannersProbesSetIPV4Name'],
                                  event['ResourceProperties']['WAFScannersProbesSetIPV4'])
                if 'WAFReputationListsSetIPV4' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFReputationListsSetIPV4Name'],
                                  event['ResourceProperties']['WAFReputationListsSetIPV4'])
                if 'WAFBadBotSetIPV4' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFBadBotSetIPV4Name'],
                                  event['ResourceProperties']['WAFBadBotSetIPV4'])
                if 'WAFWhitelistSetIPV6' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFWhitelistSetIPV6Name'],
                                  event['ResourceProperties']['WAFWhitelistSetIPV6'])                    
                if 'WAFBlacklistSetIPV6' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFBlacklistSetIPV6Name'],
                                  event['ResourceProperties']['WAFBlacklistSetIPV6'])
                if 'WAFHttpFloodSetIPV6' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFHttpFloodSetIPV6Name'],
                                  event['ResourceProperties']['WAFHttpFloodSetIPV6'])
                if 'WAFScannersProbesSetIPV6' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFScannersProbesSetIPV6Name'],
                                  event['ResourceProperties']['WAFScannersProbesSetIPV6'])
                if 'WAFReputationListsSetIPV6' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFReputationListsSetIPV6Name'],
                                  event['ResourceProperties']['WAFReputationListsSetIPV6'])                    
                if 'WAFBadBotSetIPV6' in event['ResourceProperties']:
                    delete_ip_set(log, scope,
                                  event['ResourceProperties']['WAFBadBotSetIPV6Name'],
                                  event['ResourceProperties']['WAFBadBotSetIPV6'])

            send_anonymous_usage_data(log, event['RequestType'], event['ResourceProperties'])

        elif event['ResourceType'] == "Custom::ConfigureAWSWAFLogs":
            if 'CREATE' in request_type:
                put_logging_configuration(log, event['ResourceProperties']['WAFWebACLArn'],
                                          event['ResourceProperties']['DeliveryStreamArn'])

            elif 'UPDATE' in request_type:
                delete_logging_configuration(log, event['OldResourceProperties']['WAFWebACLArn'])
                put_logging_configuration(log, event['ResourceProperties']['WAFWebACLArn'],
                                          event['ResourceProperties']['DeliveryStreamArn'])

            elif 'DELETE' in request_type:
                delete_logging_configuration(log, event['ResourceProperties']['WAFWebACLArn'])

        elif event['ResourceType'] == "Custom::GenerateAppLogParserConfFile":
            stack_name = event['ResourceProperties']['StackName']
            error_threshold = int(event['ResourceProperties']['ErrorThreshold'])
            block_period = int(event['ResourceProperties']['WAFBlockPeriod'])
            app_access_log_bucket = event['ResourceProperties']['AppAccessLogBucket']

            if 'CREATE' in request_type:
                generate_app_log_parser_conf_file(log, stack_name, error_threshold, block_period, app_access_log_bucket,
                                                  True)
            elif 'UPDATE' in request_type:
                generate_app_log_parser_conf_file(log, stack_name, error_threshold, block_period, app_access_log_bucket,
                                                  False)

            # DELETE: do nothing

        elif event['ResourceType'] == "Custom::GenerateWafLogParserConfFile":
            stack_name = event['ResourceProperties']['StackName']
            request_threshold = int(event['ResourceProperties']['RequestThreshold'])
            block_period = int(event['ResourceProperties']['WAFBlockPeriod'])
            waf_access_log_bucket = event['ResourceProperties']['WafAccessLogBucket']

            if 'CREATE' in request_type:
                generate_waf_log_parser_conf_file(log, stack_name, request_threshold, block_period,
                                                  waf_access_log_bucket,
                                                  True)
            elif 'UPDATE' in request_type:
                generate_waf_log_parser_conf_file(log, stack_name, request_threshold, block_period,
                                                  waf_access_log_bucket,
                                                  False)
            # DELETE: do nothing

        elif event['ResourceType'] == "Custom::AddAthenaPartitions":
            if 'CREATE' in request_type or 'UPDATE' in request_type:
                add_athena_partitions(
                    log,
                    event['ResourceProperties']['AddAthenaPartitionsLambda'],
                    event['ResourceProperties']['ResourceType'],
                    event['ResourceProperties']['GlueAccessLogsDatabase'],
                    event['ResourceProperties']['AppAccessLogBucket'],
                    event['ResourceProperties']['GlueAppAccessLogsTable'],
                    event['ResourceProperties']['GlueWafAccessLogsTable'],
                    event['ResourceProperties']['WafLogBucket'],
                    event['ResourceProperties']['AthenaWorkGroup'])

            # DELETE: do nothing

    except Exception as error:
        log.error(error)
        responseStatus = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '500',
            'body': {'message': reason}
        }

    finally:
        # ------------------------------------------------------------------
        # Send Result
        # ------------------------------------------------------------------
        if 'ResponseURL' in event:
            send_response(log, event, context, responseStatus, responseData, resourceId, reason)

        return json.dumps(result)
