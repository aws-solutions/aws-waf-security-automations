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
from os import environ

from urllib2 import Request
from urllib2 import urlopen

print('Loading function')

#======================================================================================================================
# Constants
#======================================================================================================================
API_CALL_NUM_RETRIES = 3

waf = None

#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================
def waf_update_ip_set(ip_set_id, source_ip):
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
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.get_ip_set(IPSetId=ip_set_id)
        except Exception, e:
            delay = math.pow(2, attempt)
            print("[waf_get_ip_set] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print("[waf_get_ip_set] Failed ALL attempts to call API")

    return response

def send_anonymous_usage_data():
    if environ['SEND_ANONYMOUS_USAGE_DATA'] != 'yes':
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
        response = waf_get_ip_set(environ['IP_SET_ID_BAD_BOT'])
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
                        "Value": environ['ACL_METRIC_NAME']
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
                        "Value": environ['ACL_METRIC_NAME']
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
                        "Value": environ['ACL_METRIC_NAME']
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
          "UUID": environ['UUID'],
          "TimeStamp": time_stamp,
          "Data":
          {
              "data_type" : "bad_bot",
              "bad_bot_ip_set_size" : bad_bot_ip_set_size,
              "allowed_requests" : allowed_requests,
              "blocked_requests_all" : blocked_requests_all,
              "blocked_requests_bad_bot" : blocked_requests_bad_bot,
              "waf_type" : environ['LOG_TYPE']
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
    response = {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': ''
    }

    print '[lambda_handler] Start'
    try:
        global waf
        if environ['LOG_TYPE'] == 'alb':
            session = boto3.session.Session(region_name=environ['REGION'])
            waf = session.client('waf-regional')
        else:
            waf = boto3.client('waf')

        source_ip = event['headers']['X-Forwarded-For'].encode('utf8').split(',')[0].strip()
        waf_update_ip_set(environ['IP_SET_ID_BAD_BOT'], source_ip)

        message = {}
        message['message'] = "[%s] Thanks for the visit."%source_ip
        response['body'] = json.dumps(message)

        send_anonymous_usage_data()

    except Exception as e:
        print e
    print '[lambda_handler] End'

    return response
