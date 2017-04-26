'''
Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

import boto3
import math
import time
import json
import datetime
import os
from urllib2 import Request
from urllib2 import urlopen

print('Loading function')

#======================================================================================================================
# Constants
#======================================================================================================================
API_CALL_NUM_RETRIES = 3
IP_SET_ID_BAD_BOT = None
SEND_ANONYMOUS_USAGE_DATA = None
UUID = None

#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================
def waf_update_ip_set(ip_set_id, source_ip):
    waf = boto3.client('waf')
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.update_ip_set(IPSetId=ip_set_id,
                ChangeToken=waf.get_change_token()['ChangeToken'],
                Updates=[{
                    'Action': 'INSERT',
                    'IPSetDescriptor': {
                        'Type': 'IPV4',
                        'Value': "%s/32"%source_ip
                    }
                }]
            )
        except Exception, e:
            delay = math.pow(2, attempt)
            print "[waf_update_ip_set] Retrying in %d seconds..." % (delay)
            time.sleep(delay)
        else:
            break
    else:
        print "[waf_update_ip_set] Failed ALL attempts to call API"

def waf_get_ip_set(ip_set_id):
    response = None
    waf = boto3.client('waf')

    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.get_ip_set(IPSetId=ip_set_id)
        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print("[waf_get_ip_set] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print("[waf_get_ip_set] Failed ALL attempts to call API")

    return response

def send_anonymous_usage_data():
    if SEND_ANONYMOUS_USAGE_DATA != 'yes':
        return

    try:
        print("[send_anonymous_usage_data] Start")
        bad_bot_ip_set_size = 0
        allowed_requests = 0
        blocked_requests_all = 0
        blocked_requests_bad_bot = 0

        #--------------------------------------------------------------------------------------------------------------
        print("[send_anonymous_usage_data] Get Bad Bot IP Set Size")
        #--------------------------------------------------------------------------------------------------------------
        response = waf_get_ip_set(IP_SET_ID_BAD_BOT)
        if response != None:
            bad_bot_ip_set_size = len(response['IPSet']['IPSetDescriptors'])

        #--------------------------------------------------------------------------------------------------------------
        print("[send_anonymous_usage_data] Get Num Allowed Requests")
        #--------------------------------------------------------------------------------------------------------------
        try:
            cw = boto3.client('cloudwatch')
            response = cw.get_metric_statistics(
                MetricName='AllowedRequests',
                Namespace='WAF',
                Statistics=['Sum'],
                Period=12*3600,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=12*3600),
                EndTime=datetime.datetime.utcnow(),
                Dimensions=[
                    {
                        "Name": "Rule",
                        "Value": "ALL"
                    },
                    {
                        "Name": "WebACL",
                        "Value": "SecurityAutomationsMaliciousRequesters"
                    }
                ]
            )
            allowed_requests = response['Datapoints'][0]['Sum']
        except Exception, e:
            print("[send_anonymous_usage_data] Error to get Num Allowed Requests")

        #--------------------------------------------------------------------------------------------------------------
        print("[send_anonymous_usage_data] Get Num Blocked Requests - All Rules")
        #--------------------------------------------------------------------------------------------------------------
        try:
            cw = boto3.client('cloudwatch')
            response = cw.get_metric_statistics(
                MetricName='BlockedRequests',
                Namespace='WAF',
                Statistics=['Sum'],
                Period=12*3600,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=12*3600),
                EndTime=datetime.datetime.utcnow(),
                Dimensions=[
                    {
                        "Name": "Rule",
                        "Value": "ALL"
                    },
                    {
                        "Name": "WebACL",
                        "Value": "SecurityAutomationsMaliciousRequesters"
                    }
                ]
            )
            blocked_requests_all = response['Datapoints'][0]['Sum']
        except Exception, e:
            print("[send_anonymous_usage_data] Error to get Num Blocked Requests")

        #--------------------------------------------------------------------------------------------------------------
        print("[send_anonymous_usage_data] Get Num Blocked Requests - Bad Bot Rule")
        #--------------------------------------------------------------------------------------------------------------
        try:
            cw = boto3.client('cloudwatch')
            response = cw.get_metric_statistics(
                MetricName='BlockedRequests',
                Namespace='WAF',
                Statistics=['Sum'],
                Period=12*3600,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=12*3600),
                EndTime=datetime.datetime.utcnow(),
                Dimensions=[
                    {
                        "Name": "Rule",
                        "Value": "SecurityAutomationsBadBotRule"
                    },
                    {
                        "Name": "WebACL",
                        "Value": "SecurityAutomationsMaliciousRequesters"
                    }
                ]
            )
            blocked_requests_bad_bot = response['Datapoints'][0]['Sum']
        except Exception, e:
            print("[send_anonymous_usage_data] Error to get Num Blocked Requests")

        #--------------------------------------------------------------------------------------------------------------
        print("[send_anonymous_usage_data] Send Data")
        #--------------------------------------------------------------------------------------------------------------
        time_now = datetime.datetime.utcnow().isoformat()
        time_stamp = str(time_now)
        usage_data = {
          "Solution": "SO0006",
          "UUID": UUID,
          "TimeStamp": time_stamp,
          "Data":
          {
              "data_type" : "bad_bot",
              "bad_bot_ip_set_size" : bad_bot_ip_set_size,
              "allowed_requests" : allowed_requests,
              "blocked_requests_all" : blocked_requests_all,
              "blocked_requests_bad_bot" : blocked_requests_bad_bot
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
        print("[send_anonymous_usage_data] Failed to Send Data")

#======================================================================================================================
# Lambda Entry Point
#======================================================================================================================
def lambda_handler(event, context):
    response = {}

    print '[lambda_handler] Start'
    try:
        source_ip = event['source_ip'].encode('utf8').split(',')[0].strip()
        bad_bot_ip_set = event['bad_bot_ip_set'].encode('utf8')
        waf_update_ip_set(bad_bot_ip_set, source_ip)
        response['message'] = "[%s] Thanks for the visit."%source_ip

        global IP_SET_ID_BAD_BOT
        global SEND_ANONYMOUS_USAGE_DATA
        global UUID

        if (IP_SET_ID_BAD_BOT == None or SEND_ANONYMOUS_USAGE_DATA == None or UUID == None):
            outputs = {}
            cf = boto3.client('cloudformation')
            stack_name = os.environ['StackName']
            cf_desc = cf.describe_stacks(StackName=stack_name)
            for e in cf_desc['Stacks'][0]['Outputs']:
                outputs[e['OutputKey']] = e['OutputValue']

            if IP_SET_ID_BAD_BOT == None:
                IP_SET_ID_BAD_BOT = outputs['BadBotSetID']
            if SEND_ANONYMOUS_USAGE_DATA == None:
                SEND_ANONYMOUS_USAGE_DATA = outputs['SendAnonymousUsageData']
            if UUID == None:
                UUID = outputs['UUID']

        print("[lambda_handler] \t\tIP_SET_ID_BAD_BOT = %s"%IP_SET_ID_BAD_BOT)
        print("[lambda_handler] \t\tSEND_ANONYMOUS_USAGE_DATA = %s"%SEND_ANONYMOUS_USAGE_DATA)
        print("[lambda_handler] \t\tUUID = %s"%UUID)

        send_anonymous_usage_data()

    except Exception as e:
        print e
    print '[lambda_handler] End'

    return response
