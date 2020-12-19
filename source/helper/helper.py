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
import uuid
import re
import string
import random
import requests
import os
from lib.waflibv2 import WAFLIBv2

logging.getLogger().debug('Loading function')


# ======================================================================================================================
# Configure Access Log Bucket
# ======================================================================================================================
# ----------------------------------------------------------------------------------------------------------------------
# Check S3 bucket requirements. This function raises exception if:
#
# 01. A empty bucket name is used
# 02. The bucket already exists and was created in a account that you cant access
# 03. The bucket already exists and was created in a different region.
#     You can't trigger log parser lambda function from another region.
# ----------------------------------------------------------------------------------------------------------------------
def check_app_log_bucket(log, region, bucket_name):
    log.info("[check_app_log_bucket] Start")

    if bucket_name.strip() == "":
        raise Exception('Failed to configure access log bucket. Name cannot be empty!')

    # ------------------------------------------------------------------------------------------------------------------
    # Check if bucket exists (and inside the specified region)
    # ------------------------------------------------------------------------------------------------------------------
    exists = True
    s3_client = boto3.client('s3')
    try:
        response = s3_client.head_bucket(Bucket=bucket_name)
        log.info("[check_app_log_bucket]response: \n%s" % response)

    except botocore.exceptions.ClientError as e:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            exists = False
        log.info("[check_app_log_bucket]error_code: %s." % error_code)
    # ------------------------------------------------------------------------------------------------------------------
    # Check if the bucket was created in the specified Region or create one (if not exists)
    # ------------------------------------------------------------------------------------------------------------------
    if exists:
        response = None
        try:
            response = s3_client.get_bucket_location(Bucket=bucket_name)
        except Exception as e:
            raise Exception(
                'Failed to access the existing bucket information. Check if you own this bucket and if it has proper access policy.')

        if response['LocationConstraint'] == None:
            response['LocationConstraint'] = 'us-east-1'
        elif response['LocationConstraint'] == 'EU':
            # Fix for github issue #72
            response['LocationConstraint'] = 'eu-west-1'

        if response['LocationConstraint'] != region:
            raise Exception(
                'Bucket located in a different region. S3 bucket and Log Parser Lambda (and therefore, you CloudFormation Stack) must be created in the same Region.')

    log.info("[check_app_log_bucket] End")


# ======================================================================================================================
# Check AWS Service Dependencies
# ======================================================================================================================
def check_service_dependencies(log, resource_properties):
    log.debug("[check_service_dependencies] Start")

    unavailable_services = []
    SCOPE = os.getenv('SCOPE')
    waflib = WAFLIBv2()
    # ------------------------------------------------------------------------------------------------------------------
    # AWS WAF Resource TEST
    # ------------------------------------------------------------------------------------------------------------------
    try:
        waflib.list_web_acls(log, SCOPE)
    except botocore.exceptions.EndpointConnectionError:
        unavailable_services.append('AWS WAF')
    except Exception:
        log.debug("[check_service_dependencies] AWS WAF tested")

    # ------------------------------------------------------------------------------------------------------------------
    # Amazon Athena
    # ------------------------------------------------------------------------------------------------------------------
    if resource_properties['AthenaLogParser'] == "yes":
        try:
            athena_client = boto3.client('athena')
            athena_client.list_named_queries()
        except botocore.exceptions.EndpointConnectionError:
            unavailable_services.append('Amazon Athena')
        except Exception:
            log.debug("[check_service_dependencies] Amazon Athena tested")

    # ------------------------------------------------------------------------------------------------------------------
    # AWS Glue
    # ------------------------------------------------------------------------------------------------------------------
    if resource_properties['AthenaLogParser'] == "yes":
        try:
            glue_client = boto3.client('glue')
            glue_client.get_databases()
        except botocore.exceptions.EndpointConnectionError:
            unavailable_services.append('AWS Glue')
        except Exception:
            log.debug("[check_service_dependencies] AWS Glue")

    # ------------------------------------------------------------------------------------------------------------------
    # Amazon Kinesis Data Firehose
    # ------------------------------------------------------------------------------------------------------------------
    if resource_properties['HttpFloodProtectionLogParserActivated'] == "yes":
        try:
            firehose_client = boto3.client('firehose')
            firehose_client.list_delivery_streams()
        except botocore.exceptions.EndpointConnectionError:
            unavailable_services.append('Amazon Kinesis Data Firehose')
        except Exception:
            log.debug("[check_service_dependencies] Amazon Kinesis Data Firehose tested")

    if unavailable_services:
        raise Exception(
            "Failed to access the following service(s): %s. Please check if this region supports all required services: https://amzn.to/2SzWJXj" % '; '.join(
                unavailable_services))

    log.debug("[check_service_dependencies] End")


def check_requirements(log, resource_properties):
    log.debug("[check_requirements] Start")

    # ------------------------------------------------------------------------------------------------------------------
    # Logging Web ACL Traffic for CloudFront distribution
    # ------------------------------------------------------------------------------------------------------------------
    if (resource_properties['HttpFloodProtectionLogParserActivated'] == "yes" and
            resource_properties['EndpointType'].lower() == 'cloudfront' and
            resource_properties['Region'] != 'us-east-1'):
        raise Exception(
            "If you are capturing AWS WAF logs for a Amazon CloudFront distribution, create the stack in US East (N. Virginia). More info: https://amzn.to/2F5L1Ae")

    # ------------------------------------------------------------------------------------------------------------------
    # Logging Web ACL Traffic for CloudFront distribution
    # ------------------------------------------------------------------------------------------------------------------
    if (resource_properties['HttpFloodProtectionRateBasedRuleActivated'] == "yes" and
            int(resource_properties['RequestThreshold']) < 100):
        raise Exception(
            "The minimum rate-based rule rate limit per 5 minute period is 100. If need to use values below that, please select AWS Lambda or Amazon Athena log parser.")

    log.debug("[check_requirements] End")


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

    # ------------------------------------------------------------------
    # Set Log Level
    # ------------------------------------------------------------------
    log_level = str(os.getenv('LOG_LEVEL').upper())
    if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        log_level = 'ERROR'
    log.setLevel(log_level)

    try:
        # ----------------------------------------------------------
        # Read inputs parameters
        # ----------------------------------------------------------
        log.info(event)
        request_type = event['RequestType'].upper() if ('RequestType' in event) else ""
        log.info(request_type)

        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        if event['ResourceType'] == "Custom::CheckRequirements":
            if 'CREATE' in request_type or 'UPDATE' in request_type:
                check_service_dependencies(log, event['ResourceProperties'])

                if event['ResourceProperties']['ProtectionActivatedScannersProbes'] == 'yes':
                    check_app_log_bucket(log, event['ResourceProperties']['Region'],
                                         event['ResourceProperties']['AppAccessLogBucket'])

                check_requirements(log, event['ResourceProperties'])

            # DELETE: do nothing

        elif event['ResourceType'] == "Custom::CreateUUID":
            if 'CREATE' in request_type:
                responseData['UUID'] = str(uuid.uuid4())
                log.debug("UUID: %s" % responseData['UUID'])

            # UPDATE: do nothing
            # DELETE: do nothing

        elif event['ResourceType'] == "Custom::CreateDeliveryStreamName":
            # --------------------------------------------------------------------------
            # Delivery stream names acceptable characters are:
            #  - Uppercase and lowercase letters
            #  - Numbers
            #  - Underscores
            #  - Hyphens
            #  - Periods
            # Also:
            #  - It must be between 1 and 64 characters long
            #  - AWS WAF requires a name starting with the prefix "aws-waf-logs-"
            # --------------------------------------------------------------------------
            if 'CREATE' in request_type:
                prefix = "aws-waf-logs-"
                suffix = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(6)])
                stack_name = event['ResourceProperties']['StackName']

                # remove spaces
                stack_name = stack_name.replace(" ", "_")

                # remove everything that is not [a-zA-Z0-9] or '_' and strip '_'
                # note: remove hypens and periods for convenience
                stack_name = re.sub(r'\W', '', stack_name).strip('_')

                delivery_stream_name = prefix + "_" + suffix
                if len(stack_name) > 0:
                    max_len = 64 - len(prefix) - 1 - len(suffix)
                    delivery_stream_name = prefix + stack_name[:max_len] + "_" + suffix

                responseData['DeliveryStreamName'] = delivery_stream_name
                log.debug("DeliveryStreamName: %s" % responseData['DeliveryStreamName'])

            # UPDATE: do nothing
            # DELETE: do nothing

        elif event['ResourceType'] == "Custom::CreateGlueDatabaseName":
            # --------------------------------------------------------------------------
            # Delivery stream names acceptable characters are:
            #  - Lowercase letters
            #  - Numbers
            #  - Underscores
            # Also:
            #  - It must be between 1 and 32 characters long. Names longer than that
            #    break AWS::Athena::NamedQuery database parameter
            # --------------------------------------------------------------------------
            if 'CREATE' in request_type:
                suffix = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(6)]).lower()
                stack_name = event['ResourceProperties']['StackName']

                # remove spaces
                stack_name = stack_name.replace(" ", "_")

                # remove everything that is not [a-z0-9] or '_' and strip '_'
                stack_name = re.sub(r'\W', '', stack_name).strip('_').lower()

                # reduce to max_len (considering random sufix + '_')
                max_len = 32 - 1 - len(suffix)
                stack_name = stack_name[:max_len].strip('_')

                # define database name
                database_name = suffix
                if len(stack_name) > 0:
                    database_name = stack_name + '_' + suffix

                responseData['DatabaseName'] = database_name
                log.debug("DatabaseName: %s" % responseData['DatabaseName'])

            # UPDATE: do nothing
            # DELETE: do nothing

    except Exception as error:
        log.error(error)
        responseStatus = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '400',
            'body': {'message': reason}
        }

    finally:
        # ------------------------------------------------------------------
        # Send Result
        # ------------------------------------------------------------------
        if 'ResponseURL' in event:
            send_response(log, event, context, responseStatus, responseData, resourceId, reason)

        return json.dumps(result)
