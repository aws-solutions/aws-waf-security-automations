'''
Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

import boto3
import botocore
import json
import math
import time
import requests
import datetime
from urllib2 import Request
from urllib2 import urlopen

print('Loading function')

#======================================================================================================================
# Constants
#======================================================================================================================
API_CALL_NUM_RETRIES = 3

#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================
def update_web_acl(web_acl_id, updates):
    if updates != []:
        waf = boto3.client('waf')
        for attempt in range(API_CALL_NUM_RETRIES):
            try:
                response = waf.update_web_acl(
                    WebACLId=web_acl_id,
                    ChangeToken=waf.get_change_token()['ChangeToken'],
                    Updates=updates,
                    DefaultAction={'Type': 'ALLOW'}
                )
            except Exception, e:
                print(e)
                delay = math.pow(2, attempt)
                print("[update_web_acl] Retrying in %d seconds..." % (delay))
                time.sleep(delay)
            else:
                break
        else:
            print("[update_web_acl] Failed ALL attempts to call API")

#==================================================================================================
# Create a bucket (if not exist) and configure an event to call Log Parser lambda funcion when
# new CloudFront access log file is created (and stored on this S3 bucket).
#
# Its important to not that this function can raise exception when:
# 01. The bucket name already exist
# 02. The bucket already exist and was created in tha different region than the specified
# 03. When PutBucketNotificationConfiguration is called using ambiguously configuration.
#       S3 Cannot have overlapping suffixes in two rules if the prefixes are overlapping for the
#       same event type.
#==================================================================================================
def configure_s3_bucket(region, bucket_name, lambda_function_arn):
    #----------------------------------------------------------------------------------------------
    # Check if bucket exists (and inside the specified region)
    #----------------------------------------------------------------------------------------------
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

    #----------------------------------------------------------------------------------------------
    # Check if the bucket was created in the specified Region or create one (if not exists)
    #----------------------------------------------------------------------------------------------
    if exists:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        if response['LocationConstraint'] == None:
            response['LocationConstraint'] = 'us-east-1'
        if response['LocationConstraint'] != region:
            raise Exception('bucket located in a different region. S3 bucket and Log Parser Lambda (and therefore, you CloudFormation Stack) must be created in the same Region.')

    else:
        if region == 'us-east-1':
            response = s3_client.create_bucket(Bucket=bucket_name)
        else:
            response = s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})

        # Begin waiting for the S3 bucket, mybucket, to exist
        s3_bucket_exists_waiter = s3_client.get_waiter('bucket_exists')
        s3_bucket_exists_waiter.wait(Bucket=bucket_name)

    #----------------------------------------------------------------------------------------------
    # Configure bucket event to call Log Parser whenever a new gz log file is added to the bucket
    #----------------------------------------------------------------------------------------------
    lambda_already_configured = False
    notification_conf = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
    if 'LambdaFunctionConfigurations' in notification_conf:
        for lfc in notification_conf['LambdaFunctionConfigurations']:
            for e in lfc['Events']:
                if "ObjectCreated" in e:
                    if lfc['LambdaFunctionArn'] == lambda_function_arn:
                        lambda_already_configured = True

    if lambda_already_configured:
        print("[INFO] Skiping bucket event configuration. It is already configured to trigger Log Parser Lambda function.")
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

def remove_s3_bucket_lambda_event(bucket_name, lambda_function_arn):
    s3 = boto3.resource('s3')
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

    except Exception, e:
        print(e)
        print("[ERROR] Error to remove S3 Bucket lambda event")

def create_stack(resource_properties):
    print("[create_stack] Start")

    #--------------------------------------------------------------------------
    # Configure S3 Bucket
    #--------------------------------------------------------------------------
    if 'CloudFrontAccessLogBucket' in resource_properties:
        configure_s3_bucket(resource_properties['Region'],
            resource_properties['CloudFrontAccessLogBucket'],
            resource_properties['LambdaWAFLogParserFunction'])

    #--------------------------------------------------------------------------
    # Create Update List
    #--------------------------------------------------------------------------
    updates = []
    if 'WAFBlacklistRule' in resource_properties:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 20,
                'RuleId': resource_properties['WAFBlacklistRule'],
                'Action': {'Type': 'BLOCK'}
            }
        })

    if 'WAFAutoBlockRule' in resource_properties:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 30,
                'RuleId': resource_properties['WAFAutoBlockRule'],
                'Action': {'Type': 'BLOCK'}
            }
        })

    if 'WAFIPReputationListsRule1' in resource_properties:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 40,
                'RuleId': resource_properties['WAFIPReputationListsRule1'],
                'Action': {'Type': 'BLOCK'}
            }
        })

    if 'WAFIPReputationListsRule2' in resource_properties:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 50,
                'RuleId': resource_properties['WAFIPReputationListsRule2'],
                'Action': {'Type': 'BLOCK'}
            }
        })

    if 'WAFBadBotRule' in resource_properties:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 60,
                'RuleId': resource_properties['WAFBadBotRule'],
                'Action': {'Type': 'BLOCK'}
            }
        })

    if 'WAFSqlInjectionRule' in resource_properties:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 70,
                'RuleId': resource_properties['WAFSqlInjectionRule'],
                'Action': {'Type': 'BLOCK'}
            }
        })

    if 'WAFXssRule' in resource_properties:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 80,
                'RuleId': resource_properties['WAFXssRule'],
                'Action': {'Type': 'BLOCK'}
            }
        })

    #--------------------------------------------------------------------------
    # Update WebACL
    #--------------------------------------------------------------------------
    update_web_acl(resource_properties['WAFWebACL'], updates)

    #--------------------------------------------------------------------------
    # Call IP Reputation List
    #--------------------------------------------------------------------------
    if 'LambdaWAFReputationListsParserFunction' in resource_properties:
        try:
            lambda_client = boto3.client('lambda')
            response = lambda_client.invoke(
                FunctionName=resource_properties['LambdaWAFReputationListsParserFunction'].rsplit(":",1)[-1],
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
                      "ipSetIds": [
                            "%s",
                            "%s"
                      ]
                    }"""%(resource_properties['WAFReputationListsSet1'], resource_properties['WAFReputationListsSet2'])
            )
        except Exception, e:
            print(e)
            print("[ERROR] Failed to call IP Reputation List function")

    print("[create_stack] End")

def update_stack(stack_name, resource_properties):
    print("[update_stack] Start")
    delete_stack(stack_name, resource_properties)
    create_stack(resource_properties)
    print("[update_stack] End")

def delete_stack(stack_name, resource_properties):
    print("[update_stack] Start")
    updates = []

    waf = boto3.client('waf')

    #--------------------------------------------------------------------------
    # Update S3 Event configuration
    #--------------------------------------------------------------------------
    if 'CloudFrontAccessLogBucket' in resource_properties and resource_properties['LambdaWAFLogParserFunction']:
        remove_s3_bucket_lambda_event(resource_properties['CloudFrontAccessLogBucket'],
            resource_properties['LambdaWAFLogParserFunction'])

    #--------------------------------------------------------------------------
    # Create Update List
    #--------------------------------------------------------------------------
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.get_web_acl(WebACLId=resource_properties['WAFWebACL'])

            for rule in response['WebACL']['Rules']:
                rule_id = rule['RuleId'].encode('utf8')
                if can_delete_rule(stack_name, rule_id):
                    updates.append({
                        'Action': 'DELETE',
                        'ActivatedRule': {
                            'Priority': rule['Priority'],
                            'RuleId': rule_id,
                            'Action': rule['Action']
                        }
                    })

        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print("[create_stack] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print("[create_stack] Failed ALL attempts to call API")

    #--------------------------------------------------------------------------
    # Update WebACL
    #--------------------------------------------------------------------------
    update_web_acl(resource_properties['WAFWebACL'], updates)

    print("[update_stack] End")

def can_delete_rule(stack_name, rule_id):
    result = False
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            waf = boto3.client('waf')
            rule_detail = waf.get_rule(RuleId=rule_id)
            result = (stack_name == None or (rule_detail['Rule']['Name'].startswith(stack_name + " - ") and rule_detail['Rule']['Name'] != (stack_name + " - Whitelist Rule") ))
        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print("[can_delete_rule] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print("[can_delete_rule] Failed ALL attempts to call API")

    return result

def send_response(event, context, responseStatus, responseData):
    responseBody = {'Status': responseStatus,
                    'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
                    'PhysicalResourceId': context.log_stream_name,
                    'StackId': event['StackId'],
                    'RequestId': event['RequestId'],
                    'LogicalResourceId': event['LogicalResourceId'],
                    'Data': responseData}

    req = None
    try:
        req = requests.put(event['ResponseURL'], data=json.dumps(responseBody))

        if req.status_code != 200:
            print(req.text)
            raise Exception('Recieved non 200 response while sending response to CFN.')
        return

    except requests.exceptions.RequestException as e:
        if req != None:
            print(req.text)
        print(e)
        raise

def send_anonymous_usage_data(action_type, resource_properties):
    if resource_properties['SendAnonymousUsageData'] != 'yes':
        return

    try:
        print("[send_anonymous_usage_data] Start")
        #--------------------------------------------------------------------------------------------------------------
        print("[send_anonymous_usage_data] Send Data")
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
                "sql_injection_protection": resource_properties['SqlInjectionProtection'],
                "xss_scripting_protection": resource_properties['CrossSiteScriptingProtection'],
                "http_flood_protection": resource_properties['ActivateHttpFloodProtection'],
                "scans_probes_protection": resource_properties['ActivateScansProbesProtection'],
                "reputation_lists_protection": resource_properties['ActivateReputationListsProtection'],
                "bad_bot_protection": resource_properties['ActivateBadBotProtection'],
                "request_threshold": resource_properties['RequestThreshold'],
                "error_threshold": resource_properties['ErrorThreshold'],
                "waf_block_period": resource_properties['WAFBlockPeriod'],
                "lifecycle" : 0
            }
        }

        url = 'https://metrics.awssolutionsbuilder.com/generic'
        data = json.dumps(usage_data)
        headers = {'content-type': 'application/json'}
        print("[send_anonymous_usage_data] %s"%data)
        req = Request(url, data, headers)
        rsp = urlopen(req)
        content = rsp.read()
        rspcode = rsp.getcode()
        print('[send_anonymous_usage_data] Response Code: {}'.format(rspcode))
        print('[send_anonymous_usage_data] Response Content: {}'.format(content))

        print("[send_anonymous_usage_data] End")
    except Exception, e:
        print(e)
        print("[send_anonymous_usage_data] Failed to Send Data")

#======================================================================================================================
# Lambda Entry Point
#======================================================================================================================
def lambda_handler(event, context):
    responseStatus = 'SUCCESS'
    responseData = {}
    try:
        cf = boto3.client('cloudformation')
        stack_name = context.invoked_function_arn.split(':')[6].rsplit('-', 2)[0]
        cf_desc = cf.describe_stacks(StackName=stack_name)

        request_type = event['RequestType'].upper()
        stack_status = cf_desc['Stacks'][0]['StackStatus'].upper()

        if ('CREATE' in request_type and "CREATE" in stack_status):
            create_stack(event['ResourceProperties'])
            send_anonymous_usage_data(event['RequestType'], event['ResourceProperties'])

        elif ('UPDATE' in request_type and "UPDATE" in stack_status):
            update_stack(stack_name, event['ResourceProperties'])
            send_anonymous_usage_data(event['RequestType'], event['ResourceProperties'])

        elif ('DELETE' in request_type and "DELETE" in stack_status):
            delete_stack(None, event['ResourceProperties'])
            send_anonymous_usage_data(event['RequestType'], event['ResourceProperties'])

    except Exception as e:
        print(e)
        responseStatus = 'FAILED'

    send_response(event, context, responseStatus, responseData)
