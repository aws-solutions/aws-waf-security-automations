#####################################################################################################################
# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
#                                                                                                                   #
# Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance        #
# with the License. A copy of the License is located at                                                             #
#                                                                                                                   #
#     http://aws.amazon.com/asl/                                                                                    #
#                                                                                                                   #
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
# OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
# and limitations under the License.                                                                                #
######################################################################################################################

import boto3
import botocore
import json
import logging
import math
import time
import datetime
import uuid
from urllib.request import Request, urlopen
from botocore.vendored import requests
from os import environ

logging.getLogger().debug('Loading function')

#======================================================================================================================
# Constants
#======================================================================================================================
API_CALL_NUM_RETRIES = 3
LIST_LIMIT  = 50
BATCH_DELETE_LIMIT = 1000
RULE_SUFIX_RATE_BASED = "-HTTP Flood Rule"


#======================================================================================================================
# Configure Access Log Bucket
#======================================================================================================================
#----------------------------------------------------------------------------------------------------------------------
# Create a bucket (if not exist) and configure an event to call Log Parser lambda funcion when new Access log file is
# created (and stored on this S3 bucket).
#
# Its important to not that this function can raise exception when:
# 01. The bucket name already exist
# 02. The bucket already exist and was created in tha different region than the specified
# 03. When PutBucketNotificationConfiguration is called using ambiguously configuration. S3 Cannot have overlapping
#       suffixes in two rules if the prefixes are overlapping for the same event type.
#----------------------------------------------------------------------------------------------------------------------
def configure_s3_bucket(region, bucket_name, lambda_function_arn):
    logging.getLogger().debug("[configure_s3_bucket] Start")

    if bucket_name.strip() == "":
        raise Exception('Failed to configure access log bucket. Name cannot be empty!')

    #------------------------------------------------------------------------------------------------------------------
    # Check if bucket exists (and inside the specified region)
    #------------------------------------------------------------------------------------------------------------------
    exists = True
    s3 = boto3.resource('s3')
    s3_client = boto3.client('s3')
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except botocore.exceptions.ClientError as e:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            exists = False

    #------------------------------------------------------------------------------------------------------------------
    # Check if the bucket was created in the specified Region or create one (if not exists)
    #------------------------------------------------------------------------------------------------------------------
    if exists:
        response = None
        try:
            response = s3_client.get_bucket_location(Bucket=bucket_name)
        except Exception as e:
            raise Exception('Failed to access the existing bucket information. Check if you own this bucket and if it has proper access policy.')

        if response['LocationConstraint'] == None:
            response['LocationConstraint'] = 'us-east-1'
        if response['LocationConstraint'] != region:
            raise Exception('Bucket located in a different region. S3 bucket and Log Parser Lambda (and therefore, you CloudFormation Stack) must be created in the same Region.')


    else:
        if region == 'us-east-1':
            response = s3_client.create_bucket(Bucket=bucket_name)
        else:
            response = s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})

        # Begin waiting for the S3 bucket, mybucket, to exist
        s3_bucket_exists_waiter = s3_client.get_waiter('bucket_exists')
        s3_bucket_exists_waiter.wait(Bucket=bucket_name)

    #------------------------------------------------------------------------------------------------------------------
    # Configure bucket event to call Log Parser whenever a new gz log file is added to the bucket
    #------------------------------------------------------------------------------------------------------------------
    lambda_already_configured = False
    notification_conf = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
    if 'LambdaFunctionConfigurations' in notification_conf:
        for lfc in notification_conf['LambdaFunctionConfigurations']:
            for e in lfc['Events']:
                if "ObjectCreated" in e:
                    if lfc['LambdaFunctionArn'] == lambda_function_arn:
                        lambda_already_configured = True

    if lambda_already_configured:
        logging.getLogger().info("[configure_s3_bucket] Skiping bucket event configuration. It is already configured to trigger Log Parser Lambda function.")
    else:
        new_conf = {}
        new_conf['LambdaFunctionConfigurations'] = []
        if 'TopicConfigurations' in notification_conf:
            new_conf['TopicConfigurations'] = notification_conf['TopicConfigurations']
        if 'QueueConfigurations' in notification_conf:
            new_conf['QueueConfigurations'] = notification_conf['QueueConfigurations']
        if 'LambdaFunctionConfigurations' in notification_conf:
            new_conf['LambdaFunctionConfigurations'] = notification_conf['LambdaFunctionConfigurations']

        new_conf['LambdaFunctionConfigurations'].append({
            'Id': 'Call Log Parser',
            'LambdaFunctionArn': lambda_function_arn,
            'Events': ['s3:ObjectCreated:*'],
            'Filter': {'Key': {'FilterRules': [{'Name': 'suffix','Value': 'gz'}]}}
        })
        response = s3_client.put_bucket_notification_configuration(Bucket=bucket_name, NotificationConfiguration=new_conf)

    logging.getLogger().debug("[configure_s3_bucket] End")

#----------------------------------------------------------------------------------------------------------------------
# Clean access log bucket event
#----------------------------------------------------------------------------------------------------------------------
def remove_s3_bucket_lambda_event(bucket_name, lambda_function_arn):
    logging.getLogger().debug("[remove_s3_bucket_lambda_event] Start")

    s3_client = boto3.client('s3')
    try:
        new_conf = {}
        notification_conf = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        if 'TopicConfigurations' in notification_conf:
            new_conf['TopicConfigurations'] = notification_conf['TopicConfigurations']
        if 'QueueConfigurations' in notification_conf:
            new_conf['QueueConfigurations'] = notification_conf['QueueConfigurations']

        if 'LambdaFunctionConfigurations' in notification_conf:
            new_conf['LambdaFunctionConfigurations'] = []
            for lfc in notification_conf['LambdaFunctionConfigurations']:
                if lfc['LambdaFunctionArn'] == lambda_function_arn:
                    continue #remove all references for Log Parser event
                else:
                    new_conf['LambdaFunctionConfigurations'].append(lfc)

        response = s3_client.put_bucket_notification_configuration(Bucket=bucket_name, NotificationConfiguration=new_conf)

    except Exception as error:
        logging.getLogger().error("Failed to remove S3 Bucket lambda event. Check if the bucket still exists, you own it and has proper access policy.")
        logging.getLogger().error(str(error))

    logging.getLogger().debug("[remove_s3_bucket_lambda_event] End")


#======================================================================================================================
# Configure Rate Based Rule
#======================================================================================================================
def create_rate_based_rule(stack_name, request_threshold, metric_name_prefix):
    logging.getLogger().debug("[create_rate_based_rule] Start")

    rule_id = ""
    waf_client = boto3.client(environ['API_TYPE'])

    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf_client.create_rate_based_rule(
                Name = stack_name + RULE_SUFIX_RATE_BASED,
                MetricName = metric_name_prefix + 'HttpFloodRule',
                RateKey='IP',
                RateLimit=int(request_threshold.replace(",","")),
                ChangeToken=waf_client.get_change_token()['ChangeToken']
            )
            rule_id = response['Rule']['RuleId'].strip()

        except Exception as error:
            logging.getLogger().error(str(error))
            delay = math.pow(2, attempt)
            logging.getLogger().info("[create_rate_based_rule] Retrying in %d seconds..." % (delay))
            time.sleep(delay)

        else:
            break

    else:
        raise Exception("[create_rate_based_rule] Failed ALL attempts to create rate based rule")

    logging.getLogger().debug("[create_rate_based_rule] End")
    return rule_id

def update_rate_based_rule(rule_id, request_threshold):
    logging.getLogger().debug("[update_rate_based_rule] Start")

    waf_client = boto3.client(environ['API_TYPE'])
    #------------------------------------------------------------------------------------------------------------------
    # Create Update List
    #------------------------------------------------------------------------------------------------------------------
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            waf_client.update_rate_based_rule(
                RuleId=rule_id,
                Updates=[],
                RateLimit=int(request_threshold.replace(",","")),
                ChangeToken=waf_client.get_change_token()['ChangeToken']
            )

        except waf_client.exceptions.WAFNonexistentItemException as error:
            raise Exception("Rate based rule %s doesn't exist (already deleted or failed to create)"%rule_id)

        except Exception as error:
            logging.getLogger().error(str(error))
            delay = math.pow(2, attempt)
            logging.getLogger().info("[update_rate_based_rule] Retrying in %d seconds..." % (delay))
            time.sleep(delay)

        else:
            break
    else:
        raise Exception("[update_rate_based_rule] Failed to update rule '%s'."%rule_id)

    logging.getLogger().debug("[update_rate_based_rule] End")

def delete_rate_based_rule(rule_id):
    logging.getLogger().debug("[delete_rate_based_rule] Start")

    waf_client = boto3.client(environ['API_TYPE'])
    #--------------------------------------------------------------------------
    # Create Update List
    #--------------------------------------------------------------------------
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            waf_client.delete_rate_based_rule(
                RuleId=rule_id,
                ChangeToken=waf_client.get_change_token()['ChangeToken']
            )

        except waf_client.exceptions.WAFNonexistentItemException as error:
            logging.getLogger().debug("[delete_rate_based_rule] Rate based rule %s doesn't exist (already deleted or failed to create)"%rule_id)
            break

        except Exception as error:
            logging.getLogger().error(str(error))
            delay = math.pow(2, attempt)
            logging.getLogger().info("[delete_rate_based_rule] Retrying in %d seconds..." % (delay))
            time.sleep(delay)

        else:
            break
    else:
        logging.getLogger().error("[delete_rate_based_rule] Failed to delete rule '%s'."%rule_id)

    logging.getLogger().debug("[delete_rate_based_rule] End")


#======================================================================================================================
# Configure Web ACl
#======================================================================================================================
def update_web_acl(web_acl_id, updates):
    logging.getLogger().debug("[update_web_acl] Start")

    waf_client = boto3.client(environ['API_TYPE'])
    if updates != []:
        for attempt in range(API_CALL_NUM_RETRIES):
            try:
                response = waf_client.update_web_acl(
                    WebACLId = web_acl_id,
                    ChangeToken = waf_client.get_change_token()['ChangeToken'],
                    Updates = updates
                )

            except Exception as error:
                logging.getLogger().error(str(error))
                delay = math.pow(2, attempt)
                logging.getLogger().info("[update_web_acl] Retrying in %d seconds..." % (delay))
                time.sleep(delay)

            else:
                break

        else:
            raise Exception("[update_web_acl] Failed ALL attempts to update Web ACL")

    logging.getLogger().debug("[update_web_acl] End")

def process_rule_inclusion(priority, action, rule_type, protection_tag_name, rule_name, resource_properties, current_rules):
    update = None
    is_activated = True if (protection_tag_name == None or resource_properties[protection_tag_name] == "yes") else False
    rule_id = resource_properties[rule_name] if rule_name in resource_properties else None

    if is_activated and rule_id not in current_rules:
        update = {
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': priority,
                'RuleId': rule_id,
                'Action': {'Type': action},
                'Type': rule_type
            }
        }
    return update

def process_rule_exclusion(protection_tag_name, rule_name, resource_properties, old_resource_properties, current_rules):
    update = None
    rule_id = old_resource_properties[rule_name] if rule_name in old_resource_properties else None
    rule_data = current_rules[rule_id] if rule_id in current_rules else None
    is_activated = resource_properties[protection_tag_name] == "yes"
    was_activated = old_resource_properties[protection_tag_name] == "yes"

    if was_activated and (not is_activated) and rule_id in current_rules:
        update = {
            'Action': 'DELETE',
            'ActivatedRule': {
                'Priority': rule_data['Priority'],
                'RuleId': rule_id,
                'Action': rule_data['Action'],
                'Type': rule_data['Type']
            }
        }

    return update

def configure_web_acl(resource_properties, old_resource_properties):
    logging.getLogger().debug("[configure_web_acl] Start")

    #------------------------------------------------------------------------------------------------------------------
    # Get Current Rule List
    #------------------------------------------------------------------------------------------------------------------
    current_rules = {}
    waf_client = boto3.client(environ['API_TYPE'])
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf_client.get_web_acl(WebACLId=resource_properties['WAFWebACL'])
            for rule in response['WebACL']['Rules']:
                current_rules[rule['RuleId']] = {
                    'Type': rule['Type'],
                    'Priority': rule['Priority'],
                    'Action': rule['Action'],
                }

        except Exception as error:
            logging.getLogger().error(str(error))
            delay = math.pow(2, attempt)
            logging.getLogger().info("[configure_web_acl] Retrying in %d seconds..." % (delay))
            time.sleep(delay)

        else:
            break

    else:
        raise Exception("[configure_web_acl] Failed ALL attempts to retrieve current rule list")

    #------------------------------------------------------------------------------------------------------------------
    # For each protection, check if the rule needs to added to the web_acl
    #------------------------------------------------------------------------------------------------------------------
    updates = []
    updates.append(process_rule_inclusion(10, 'ALLOW', 'REGULAR', None, 'WAFWhitelistRule', resource_properties, current_rules))
    updates.append(process_rule_inclusion(20, 'BLOCK', 'REGULAR', None, 'WAFBlacklistRule', resource_properties, current_rules))
    updates.append(process_rule_inclusion(30, 'BLOCK', 'REGULAR', 'SqlInjectionProtectionActivated', 'WAFSqlInjectionRule', resource_properties, current_rules))
    updates.append(process_rule_inclusion(40, 'BLOCK', 'REGULAR', 'CrossSiteScriptingProtectionActivated', 'WAFXssRule', resource_properties, current_rules))
    updates.append(process_rule_inclusion(50, 'BLOCK', 'RATE_BASED', 'HttpFloodProtectionActivated', 'RateBasedRule', resource_properties, current_rules))
    updates.append(process_rule_inclusion(60, 'BLOCK', 'REGULAR', 'ScannersProbesProtectionActivated', 'WAFScannersProbesRule', resource_properties, current_rules))
    updates.append(process_rule_inclusion(70, 'BLOCK', 'REGULAR', 'ReputationListsProtectionActivated', 'WAFIPReputationListsRule', resource_properties, current_rules))
    updates.append(process_rule_inclusion(90, 'BLOCK', 'REGULAR', 'BadBotProtectionActivated', 'WAFBadBotRule', resource_properties, current_rules))

    if old_resource_properties:
        updates.append(process_rule_exclusion('SqlInjectionProtectionActivated', 'WAFSqlInjectionRule', resource_properties, old_resource_properties, current_rules))
        updates.append(process_rule_exclusion('CrossSiteScriptingProtectionActivated', 'WAFXssRule', resource_properties, old_resource_properties, current_rules))
        updates.append(process_rule_exclusion('HttpFloodProtectionActivated', 'RateBasedRule', resource_properties, old_resource_properties, current_rules))
        updates.append(process_rule_exclusion('ScannersProbesProtectionActivated', 'WAFScannersProbesRule', resource_properties, old_resource_properties, current_rules))
        updates.append(process_rule_exclusion('ReputationListsProtectionActivated', 'WAFIPReputationListsRule', resource_properties, old_resource_properties, current_rules))
        updates.append(process_rule_exclusion('BadBotProtectionActivated', 'WAFBadBotRule', resource_properties, old_resource_properties, current_rules))

    #------------------------------------------------------------------------------------------------------------------
    # Clean invalid update elements
    #------------------------------------------------------------------------------------------------------------------
    updates = [u for u in updates if u is not None]

    #------------------------------------------------------------------------------------------------------------------
    # Clean IP sets before delete them
    #------------------------------------------------------------------------------------------------------------------
    if old_resource_properties:
        rule_ids = [u['ActivatedRule']['RuleId'] for u in updates if u['Action'] == 'DELETE']
        if ('WAFScannersProbesRule' in old_resource_properties and old_resource_properties['WAFScannersProbesRule'] in rule_ids):
            clean_ip_set(old_resource_properties['WAFScannersProbesSet'])
        if ('WAFIPReputationListsRule' in old_resource_properties and old_resource_properties['WAFIPReputationListsRule'] in rule_ids):
            clean_ip_set(old_resource_properties['WAFReputationListsSet'])
        if ('WAFBadBotRule' in old_resource_properties and old_resource_properties['WAFBadBotRule'] in rule_ids):
            clean_ip_set(old_resource_properties['WAFBadBotSet'])

    #------------------------------------------------------------------------------------------------------------------
    # Update WebACL
    #------------------------------------------------------------------------------------------------------------------
    update_web_acl(resource_properties['WAFWebACL'], updates)

    logging.getLogger().debug("[configure_web_acl] End")

def clean_web_acl(web_acl_id):
    logging.getLogger().debug("[clean_web_acl] Start")

    #------------------------------------------------------------------------------------------------------------------
    # Get current rule list to be removed from the web ACL
    #------------------------------------------------------------------------------------------------------------------
    updates = []
    waf_client = boto3.client(environ['API_TYPE'])
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf_client.get_web_acl(WebACLId=web_acl_id)
            for rule in response['WebACL']['Rules']:
                updates.append({
                    'Action': 'DELETE',
                    'ActivatedRule': {
                        'Priority': rule['Priority'],
                        'RuleId': rule['RuleId'],
                        'Action': rule['Action'],
                        'Type': rule['Type']
                    }
                })

        except Exception as error:
            logging.getLogger().error(str(error))
            delay = math.pow(2, attempt)
            logging.getLogger().info("[clean_web_acl] Retrying in %d seconds..." % (delay))
            time.sleep(delay)

        else:
            break

    else:
        raise Exception("[clean_web_acl] Failed ALL attempts to retrieve current rule list")

    #------------------------------------------------------------------------------------------------------------------
    # Update WebACL
    #------------------------------------------------------------------------------------------------------------------
    update_web_acl(web_acl_id, updates)

    logging.getLogger().debug("[clean_web_acl] End")

def clean_ip_set(ip_set_id):
    logging.getLogger().debug("[clean_ip_set] Clean IP Set %s"%ip_set_id)

    waf_client = boto3.client(environ['API_TYPE'])
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf_client.get_ip_set(IPSetId=ip_set_id)
            while len(response['IPSet']['IPSetDescriptors']) > 0:
                counter = 0
                updates = []
                for ip in response['IPSet']['IPSetDescriptors']:
                    updates.append({
                        'Action': 'DELETE',
                        'IPSetDescriptor': {
                            'Type': ip['Type'],
                            'Value': ip['Value']
                        }
                    })
                    counter += 1
                    if counter >= BATCH_DELETE_LIMIT:
                        break

                logging.getLogger().debug("[clean_ip_set] Deleting %d IPs..."%len(updates))
                waf_client.update_ip_set(
                    IPSetId=ip_set_id,
                    ChangeToken=waf_client.get_change_token()['ChangeToken'],
                    Updates=updates
                )
                response = waf_client.get_ip_set(IPSetId=ip_set_id)

        except Exception as error:
            logging.getLogger().error(str(error))
            delay = math.pow(2, attempt)
            logging.getLogger().info("[clean_ip_set] Retrying in %d seconds..." % (delay))
            time.sleep(delay)

        else:
            break
    else:
        logging.getLogger().debug("[clean_ip_set] Failed ALL attempts to call API")

#======================================================================================================================
# Populate Reputation List
#======================================================================================================================
def populate_reputation_list(region, reputation_lists_parser_function, reputation_list_set):
    logging.getLogger().debug("[populate_reputation_list] Start")

    try:
        lambda_client = boto3.client('lambda')
        response = lambda_client.invoke(
            FunctionName=reputation_lists_parser_function.rsplit(":",1)[-1],
            Payload="""{
                  "lists": [
                    {
                        "url": "https://www.spamhaus.org/drop/drop.txt"
                    },
                    {
                        "url": "https://check.torproject.org/exit-addresses",
                        "prefix": "ExitAddress "
                    },
                    {
                        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
                    }
                  ],
                  "apiType":"%s",
                  "region":"%s",
                  "ipSetIds": [
                        "%s"
                  ]
                }"""%(environ['API_TYPE'], region, reputation_list_set)
        )

    except Exception as error:
        logging.getLogger().error("[create_stack] Failed to call IP Reputation List function")
        logging.getLogger().error(str(error))

    logging.getLogger().debug("[populate_reputation_list] End")

def send_response(event, context, responseStatus, responseData, resourceId, reason=None):
    logging.getLogger().debug("[send_response] Start")

    responseUrl = event['ResponseURL']
    cw_logs_url = "https://console.aws.amazon.com/cloudwatch/home?region=%s#logEventViewer:group=%s;stream=%s"%(context.invoked_function_arn.split(':')[3], context.log_group_name, context.log_stream_name)

    logging.getLogger().info(responseUrl)
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = reason or ('See the details in CloudWatch Logs: ' +  cw_logs_url)
    responseBody['PhysicalResourceId'] = resourceId
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = False
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)
    logging.getLogger().debug("Response body:\n" + json_responseBody)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        logging.getLogger().debug("Status code: " + response.reason)

    except Exception as error:
        logging.getLogger().error("[send_response] Failed executing requests.put(..)")
        logging.getLogger().error(str(error))

    logging.getLogger().debug("[send_response] End")

def send_anonymous_usage_data(action_type, resource_properties):
    if resource_properties['SendAnonymousUsageData'] != 'yes':
        return

    try:
        logging.getLogger().debug("[send_anonymous_usage_data] Start")
        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().debug("[send_anonymous_usage_data] Send Data")
        #--------------------------------------------------------------------------------------------------------------
        time_now = datetime.datetime.utcnow().isoformat()
        time_stamp = str(time_now)
        usage_data = {
            "Solution": "SO0006",
            "UUID": resource_properties['UUID'],
            "TimeStamp": time_stamp,
            "Data":
            {
                "Version": "2",
                "data_type" : "custom_resource",
                "region" : resource_properties['Region'],
                "action" : action_type,
                "sql_injection_protection": resource_properties['SqlInjectionProtectionActivated'],
                "xss_scripting_protection": resource_properties['CrossSiteScriptingProtectionActivated'],
                "http_flood_protection": resource_properties['HttpFloodProtectionActivated'],
                "scanners_probes_protection": resource_properties['ScannersProbesProtectionActivated'],
                "reputation_lists_protection": resource_properties['ReputationListsProtectionActivated'],
                "bad_bot_protection": resource_properties['BadBotProtectionActivated'],
                "request_threshold": resource_properties['RequestThreshold'],
                "error_threshold": resource_properties['ErrorThreshold'],
                "waf_block_period": resource_properties['WAFBlockPeriod'],
                "lifecycle" : 0
            }
        }

        url = 'https://metrics.awssolutionsbuilder.com/generic'
        req = Request(url, method='POST', data=bytes(json.dumps(usage_data), encoding='utf8'), headers={'Content-Type': 'application/json'})
        rsp = urlopen(req)
        rspcode = rsp.getcode()
        logging.getLogger().debug('[send_anonymous_usage_data] Response Code: {}'.format(rspcode))
        logging.getLogger().debug("[send_anonymous_usage_data] End")

    except Exception as error:
        logging.getLogger().error("[send_anonymous_usage_data] Failed to Send Data")
        logging.getLogger().error(str(error))

#======================================================================================================================
# Lambda Entry Point
#======================================================================================================================
def lambda_handler(event, context):
    responseStatus = 'SUCCESS'
    reason = None
    responseData = {}
    resourceId = event['PhysicalResourceId'] if 'PhysicalResourceId' in event else event['LogicalResourceId']
    result = {
        'StatusCode': '200',
        'Body':  {'message': 'success'}
    }

    try:
        #------------------------------------------------------------------
        # Set Log Level
        #------------------------------------------------------------------
        global log_level
        log_level = str(environ['LOG_LEVEL'].upper())
        if log_level not in ['DEBUG', 'INFO','WARNING', 'ERROR','CRITICAL']:
            log_level = 'ERROR'
        logging.getLogger().setLevel(log_level)

        #----------------------------------------------------------
        # Read inputs parameters
        #----------------------------------------------------------
        logging.getLogger().info(event)
        request_type = event['RequestType'].upper() if ('RequestType' in event) else ""
        logging.getLogger().info(request_type)

        #----------------------------------------------------------
        # Process event
        #----------------------------------------------------------
        if event['ResourceType'] == "Custom::CreateUUID":
            if 'CREATE' in request_type:
                responseData['UUID'] = str(uuid.uuid4())
                logging.getLogger().debug("UUID: %s"%responseData['UUID'])

            # UPDATE: do nothing
            # DELETE: do nothing

        elif event['ResourceType'] == "Custom::ConfigureAccessLogBucket":
            if 'CREATE' in request_type:
                configure_s3_bucket(event['ResourceProperties']['Region'],
                    event['ResourceProperties']['AccessLogBucket'],
                    event['ResourceProperties']['LambdaWAFLogParserFunction'])

            elif 'UPDATE' in request_type:
                if (event['OldResourceProperties']['AccessLogBucket'] != event['ResourceProperties']['AccessLogBucket'] or
                        event['OldResourceProperties']['LambdaWAFLogParserFunction'] != event['ResourceProperties']['LambdaWAFLogParserFunction']):

                    remove_s3_bucket_lambda_event(event['OldResourceProperties']["AccessLogBucket"],
                        event['OldResourceProperties']['LambdaWAFLogParserFunction'])
                    configure_s3_bucket(event['ResourceProperties']['Region'],
                        event['ResourceProperties']['AccessLogBucket'],
                        event['ResourceProperties']['LambdaWAFLogParserFunction'])

            elif 'DELETE' in request_type:
                remove_s3_bucket_lambda_event(event['ResourceProperties']["AccessLogBucket"],
                    event['ResourceProperties']['LambdaWAFLogParserFunction'])

        elif event['ResourceType'] == "Custom::ConfigureRateBasedRule":
            if 'CREATE' in request_type:
                rbr_id = create_rate_based_rule(event['ResourceProperties']['StackName'], event['ResourceProperties']['RequestThreshold'], event['ResourceProperties']['MetricNamePrefix'])
                if (rbr_id != ""):
                    resourceId = rbr_id
                    responseData['RateBasedRuleId'] = rbr_id

            elif 'UPDATE' in request_type:
                responseData['RateBasedRuleId'] = event['PhysicalResourceId']
                if (event['OldResourceProperties']['RequestThreshold'] != event['ResourceProperties']['RequestThreshold']):
                    update_rate_based_rule(event['PhysicalResourceId'], event['ResourceProperties']['RequestThreshold'])

            elif 'DELETE' in request_type:
                delete_rate_based_rule(event['PhysicalResourceId'])

        elif event['ResourceType'] == "Custom::ConfigureWebAcl":
            if 'CREATE' in request_type:
                configure_web_acl(event['ResourceProperties'], None)

            elif 'UPDATE' in request_type:
                configure_web_acl(event['ResourceProperties'], event['OldResourceProperties'])

            elif 'DELETE' in request_type:
                clean_web_acl(event['ResourceProperties']['WAFWebACL'])
                clean_ip_set(event['ResourceProperties']['WAFWhitelistSet'])
                clean_ip_set(event['ResourceProperties']['WAFBlacklistSet'])
                if 'WAFScannersProbesSet' in event['ResourceProperties']:
                    clean_ip_set(event['ResourceProperties']['WAFScannersProbesSet'])
                if 'WAFReputationListsSet' in event['ResourceProperties']:
                    clean_ip_set(event['ResourceProperties']['WAFReputationListsSet'])
                if 'WAFBadBotSet' in event['ResourceProperties']:
                    clean_ip_set(event['ResourceProperties']['WAFBadBotSet'])

            send_anonymous_usage_data(event['RequestType'], event['ResourceProperties'])

        elif event['ResourceType'] == "Custom::PopulateReputationList":
            if 'CREATE' in request_type or 'UPDATE' in request_type:
                populate_reputation_list(event['ResourceProperties']['Region'],
                    event['ResourceProperties']['LambdaWAFReputationListsParserFunction'],
                    event['ResourceProperties']['WAFReputationListsSet'])

            # DELETE: do nothing

    except Exception as error:
        logging.getLogger().error(error)
        responseStatus = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '500',
            'body':  {'message': reason}
        }

    finally:
        #------------------------------------------------------------------
        # Send Result
        #------------------------------------------------------------------
        if 'ResponseURL' in event:
            send_response(event, context, responseStatus, responseData, resourceId, reason)

        return json.dumps(result)
