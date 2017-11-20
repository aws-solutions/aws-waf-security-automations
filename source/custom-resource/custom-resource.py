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
LIST_LIMIT  = 50
BATCH_DELETE_LIMIT = 1000
RULE_SUFIX_RATE_BASED = " - Http Flood Rule"

waf = None

#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================
def update_web_acl(web_acl_id, updates):
    if updates != []:
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
# new Access log file is created (and stored on this S3 bucket).
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

def get_or_create_rate_based_rule(stack_name, resource_properties):
    rule_id = ""

    #--------------------------------------------------------------------------
    # Get
    #--------------------------------------------------------------------------
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            keep_looking = True
            response = waf.list_rate_based_rules(Limit=LIST_LIMIT)
            while keep_looking:            
                for rule in response['Rules']:
                    if rule['Name'] == stack_name + RULE_SUFIX_RATE_BASED:
                        rule_id = rule['RuleId']
                        keep_looking = False
                        break
                
                keep_looking = False
                if len(response['Rules']) == LIST_LIMIT and 'NextMarker' in response:
                    response = waf.list_rate_based_rules(NextMarker=response['NextMarker'], Limit=LIST_LIMIT)
                    keep_looking = (len(response['Rules']) > 0)

        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print("[get_or_create_rate_based_rule] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print("[get_or_create_rate_based_rule] Failed ALL attempts to call API")

    #--------------------------------------------------------------------------
    # Create Update List
    #--------------------------------------------------------------------------
    if rule_id == "":
        for attempt in range(API_CALL_NUM_RETRIES):
            try:
                response = waf.create_rate_based_rule(
                    Name = stack_name + RULE_SUFIX_RATE_BASED,
                    MetricName='SecurityAutomationsHttpFloodRule',
                    RateKey='IP',
                    RateLimit=int(resource_properties['RequestThreshold'].replace(",","")),
                    ChangeToken=waf.get_change_token()['ChangeToken']
                )   

                rule_id = response['Rule']['RuleId'].encode('utf8').strip()

            except Exception, e:
                print(e)
                delay = math.pow(2, attempt)
                print("[get_or_create_rate_based_rule] Retrying in %d seconds..." % (delay))
                time.sleep(delay)
            else:
                break
        else:
            print("[get_or_create_rate_based_rule] Failed ALL attempts to call API")

    return rule_id

def delete_rate_based_rules(stack_name):
    #--------------------------------------------------------------------------
    # Create Update List
    #--------------------------------------------------------------------------
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            keep_looking = True
            response = waf.list_rate_based_rules(Limit=LIST_LIMIT)
            while keep_looking:            
                for rule in response['Rules']:
                    if rule['Name'] == stack_name + RULE_SUFIX_RATE_BASED:
                        try:
                            waf.delete_rate_based_rule(
                                RuleId=rule['RuleId'],
                                ChangeToken=waf.get_change_token()['ChangeToken']
                            )
                        except Exception as e:
                            print("[delete_rate_based_rules] Failed to Delete '%s':'%s'." % (rule['Name'], rule['RuleId']))
                
                keep_looking = False
                if len(response['Rules']) == LIST_LIMIT and 'NextMarker' in response:
                    response = waf.list_rate_based_rules(NextMarker=response['NextMarker'], Limit=LIST_LIMIT)
                    keep_looking = (len(response['Rules']) > 0)

        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print("[delete_rate_based_rules] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print("[delete_rate_based_rules] Failed ALL attempts to call API")

def clean_ip_set(ip_set_id):
    print("[clean_ip_set] Clean IP Set %s"%ip_set_id)

    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.get_ip_set(IPSetId=ip_set_id)        
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

                print "[clean_ip_set] Deleting %d IPs..."%len(updates)
                waf.update_ip_set(
                    IPSetId=ip_set_id,
                    ChangeToken=waf.get_change_token()['ChangeToken'],
                    Updates=updates
                )
                response = waf.get_ip_set(IPSetId=ip_set_id)

        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print("[clean_ip_set] Error to clean IP Set %s. Retrying in %d seconds..."%ip_set_id, delay)
            time.sleep(delay)
        else:
            break
    else:
        print("[clean_ip_set] Failed ALL attempts to call API")  

def create_stack(stack_name, resource_properties):
    print("[create_stack] Start")

    #--------------------------------------------------------------------------
    # Configure S3 Bucket
    #--------------------------------------------------------------------------
    if "AccessLogBucket" in resource_properties:
        configure_s3_bucket(resource_properties['Region'],
            resource_properties['AccessLogBucket'],
            resource_properties['LambdaWAFLogParserFunction'])

    #--------------------------------------------------------------------------
    # Get Current Rule List
    #--------------------------------------------------------------------------
    current_rules = []
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.get_web_acl(WebACLId=resource_properties['WAFWebACL'])
            current_rules = [r['RuleId'].encode('utf8') for r in response['WebACL']['Rules']]

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
    # Update List
    #--------------------------------------------------------------------------
    updates = []
    if 'WAFWhitelistRule' in resource_properties and resource_properties['WAFWhitelistRule'] not in current_rules:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 10,
                'RuleId': resource_properties['WAFWhitelistRule'],
                'Action': {'Type': 'ALLOW'}, 
                'Type': 'REGULAR'
            }
        })

    if 'WAFBlacklistRule' in resource_properties and resource_properties['WAFBlacklistRule'] not in current_rules:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 20,
                'RuleId': resource_properties['WAFBlacklistRule'],
                'Action': {'Type': 'BLOCK'},
                'Type': 'REGULAR'
            }
        })

    if resource_properties['ActivateHttpFloodProtection'] == "yes":
        rbr_id = get_or_create_rate_based_rule(stack_name, resource_properties)
        if rbr_id != "" and rbr_id not in current_rules:
            updates.append({
                'Action': 'INSERT',
                'ActivatedRule': {
                    'Priority': 30,
                    'RuleId': rbr_id,
                    'Action': {'Type': 'BLOCK'},
                    'Type': 'RATE_BASED'
                }
            })

    if 'WAFScansProbesRule' in resource_properties and resource_properties['WAFScansProbesRule'] not in current_rules:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 40,
                'RuleId': resource_properties['WAFScansProbesRule'],
                'Action': {'Type': 'BLOCK'},
                'Type': 'REGULAR'
            }
        })

    if 'WAFIPReputationListsRule1' in resource_properties and resource_properties['WAFIPReputationListsRule1'] not in current_rules:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 50,
                'RuleId': resource_properties['WAFIPReputationListsRule1'],
                'Action': {'Type': 'BLOCK'},
                'Type': 'REGULAR'
            }
        })

    if 'WAFIPReputationListsRule2' in resource_properties and resource_properties['WAFIPReputationListsRule2'] not in current_rules:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 60,
                'RuleId': resource_properties['WAFIPReputationListsRule2'],
                'Action': {'Type': 'BLOCK'},
                'Type': 'REGULAR'
            }
        })

    if 'WAFBadBotRule' in resource_properties and resource_properties['WAFBadBotRule'] not in current_rules:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 70,
                'RuleId': resource_properties['WAFBadBotRule'],
                'Action': {'Type': 'BLOCK'},
                'Type': 'REGULAR'
            }
        })

    if 'WAFSqlInjectionRule' in resource_properties and resource_properties['WAFSqlInjectionRule'] not in current_rules:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 80,
                'RuleId': resource_properties['WAFSqlInjectionRule'],
                'Action': {'Type': 'BLOCK'},
                'Type': 'REGULAR'
            }
        })

    if 'WAFXssRule' in resource_properties and resource_properties['WAFXssRule'] not in current_rules:
        updates.append({
            'Action': 'INSERT',
            'ActivatedRule': {
                'Priority': 90,
                'RuleId': resource_properties['WAFXssRule'],
                'Action': {'Type': 'BLOCK'},
                'Type': 'REGULAR'
            }
        })

    #--------------------------------------------------------------------------
    # Update WebACL
    #--------------------------------------------------------------------------
    update_web_acl(resource_properties['WAFWebACL'], updates)

    #--------------------------------------------------------------------------
    # Call IP Reputation List
    #--------------------------------------------------------------------------
    if 'LambdaWAFReputationListsParserFunction' in resource_properties and 'WAFIPReputationListsRule1' in resource_properties and 'WAFIPReputationListsRule2' in resource_properties:
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
                      "logType":"%s",
                      "region":"%s",
                      "ipSetIds": [
                            "%s",
                            "%s"
                      ]
                    }"""%(resource_properties['LOG_TYPE'], resource_properties['Region'], resource_properties['WAFReputationListsSet1'], resource_properties['WAFReputationListsSet2'])
            )
        except Exception, e:
            print(e)
            print("[ERROR] Failed to call IP Reputation List function")

    print("[create_stack] End")

def update_stack(stack_name, resource_properties):
    print("[update_stack] Start")
    delete_stack(stack_name, resource_properties, False)
    create_stack(stack_name, resource_properties)
    print("[update_stack] End")

def delete_stack(stack_name, resource_properties, force_delete):
    print("[delete_stack] Start")
    webacl_updates = []

    #--------------------------------------------------------------------------
    # Update S3 Event configuration
    #--------------------------------------------------------------------------
    if "AccessLogBucket" in resource_properties and resource_properties['LambdaWAFLogParserFunction']:
        remove_s3_bucket_lambda_event(resource_properties["AccessLogBucket"],
            resource_properties['LambdaWAFLogParserFunction'])

    #--------------------------------------------------------------------------
    # Create Update List
    #--------------------------------------------------------------------------
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.get_web_acl(WebACLId=resource_properties['WAFWebACL'])

            for rule in response['WebACL']['Rules']:
                rule_id = rule['RuleId'].encode('utf8')
                rule_type = rule['Type']
                can_delete, ipsets_to_clean = can_delete_rule(stack_name, resource_properties, rule_id, rule_type, force_delete)
                if can_delete:
                    webacl_updates.append({
                        'Action': 'DELETE',
                        'ActivatedRule': {
                            'Priority': rule['Priority'],
                            'RuleId': rule_id,
                            'Action': rule['Action'],
                            'Type': rule_type
                        }
                    })

                    #----------------------------------------------------------
                    # Clean IP Sets
                    #----------------------------------------------------------
                    for ip_set_id in ipsets_to_clean:
                        clean_ip_set(ip_set_id)

        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print("[delete_stack] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print("[delete_stack] Failed ALL attempts to call API")

    #--------------------------------------------------------------------------
    # Update WebACL
    #--------------------------------------------------------------------------
    update_web_acl(resource_properties['WAFWebACL'], webacl_updates)

    #--------------------------------------------------------------------------
    # Delete Rate Based Rule
    #--------------------------------------------------------------------------
    if force_delete or resource_properties['ActivateHttpFloodProtection'] == 'no':
        delete_rate_based_rules(stack_name)    

    print("[delete_stack] End")

def can_delete_rule(stack_name, resource_properties, rule_id, rule_type, force_delete):
    can_delete = False
    ipsets_to_clean = []

    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            rule_detail = None
            protection_activated = False
            if rule_type == 'RATE_BASED':
                rule_detail = waf.get_rate_based_rule(RuleId=rule_id)
                protection_activated = resource_properties['ActivateHttpFloodProtection'] == 'yes'
            else:
                rule_detail = waf.get_rule(RuleId=rule_id)
                protection_activated = rule_id in resource_properties.values()

            can_delete = force_delete or (not force_delete and 
                    rule_detail['Rule']['Name'].startswith(stack_name + " - ") and 
                    not protection_activated)

            if can_delete and rule_type != 'RATE_BASED':
                for p in rule_detail['Rule']['Predicates']:
                    if p['Type'] == 'IPMatch':
                        ipsets_to_clean.append(p['DataId'].encode('utf8'))

        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print("[can_delete_rule] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print("[can_delete_rule] Failed ALL attempts to call API")

    return can_delete, ipsets_to_clean

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
        stack_name = event['ResourceProperties']['StackName']
        cf_desc = cf.describe_stacks(StackName=stack_name)

        global waf
        if event['ResourceProperties']['LOG_TYPE'] == 'alb':
            session = boto3.session.Session(region_name=event['ResourceProperties']['Region'])
            waf = session.client('waf-regional')
        else:
            waf = boto3.client('waf')

        request_type = event['RequestType'].upper()

        #----------------------------------------------------------
        # Extra check for DELETE events
        #----------------------------------------------------------
        stack_status = cf_desc['Stacks'][0]['StackStatus'].upper()
        if 'DELETE' in request_type and "UPDATE" in stack_status:

            # Get new input parameters state
            parameters = cf_desc['Stacks'][0]['Parameters']
            for p in parameters:
                if p["ParameterKey"] == "SqlInjectionProtectionParam":
                    event['ResourceProperties']['SqlInjectionProtection'] = p["ParameterValue"]

                if p["ParameterKey"] == "CrossSiteScriptingProtectionParam":
                    event['ResourceProperties']['CrossSiteScriptingProtection'] = p["ParameterValue"]

                if p["ParameterKey"] == "ActivateHttpFloodProtectionParam":
                    event['ResourceProperties']['ActivateHttpFloodProtection'] = p["ParameterValue"]

                if p["ParameterKey"] == "ActivateScansProbesProtectionParam":
                    event['ResourceProperties']['ActivateScansProbesProtection'] = p["ParameterValue"]

                if p["ParameterKey"] == "ActivateReputationListsProtectionParam":
                    event['ResourceProperties']['ActivateReputationListsProtection'] = p["ParameterValue"]

                if p["ParameterKey"] == "ActivateBadBotProtectionParam":
                    event['ResourceProperties']['ActivateBadBotProtection'] = p["ParameterValue"]

            # If the is at least one protection activated during UPDATE stack state,
            # this should be handled as UPDATE event
            if (event['ResourceProperties']['SqlInjectionProtection'] == "yes" or
                event['ResourceProperties']['CrossSiteScriptingProtection'] == "yes" or
                event['ResourceProperties']['ActivateHttpFloodProtection'] == "yes" or
                event['ResourceProperties']['ActivateScansProbesProtection'] == "yes" or
                event['ResourceProperties']['ActivateReputationListsProtection'] == "yes" or
                event['ResourceProperties']['ActivateBadBotProtection'] == "yes"):
                request_type = 'UPDATE'
        #----------------------------------------------------------

        if 'CREATE' in request_type:
            create_stack(stack_name, event['ResourceProperties'])
            send_anonymous_usage_data(event['RequestType'], event['ResourceProperties'])

        elif 'UPDATE' in request_type:
            update_stack(stack_name, event['ResourceProperties'])
            send_anonymous_usage_data(event['RequestType'], event['ResourceProperties'])

        elif 'DELETE' in request_type:
            delete_stack(stack_name, event['ResourceProperties'], True)
            send_anonymous_usage_data(event['RequestType'], event['ResourceProperties'])

    except Exception as e:
        print(e)
        responseStatus = 'FAILED'

    send_response(event, context, responseStatus, responseData)
