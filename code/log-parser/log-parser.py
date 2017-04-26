'''
Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

import json
import urllib
import boto3
import gzip
import datetime
import time
import math
import os
from urllib2 import Request
from urllib2 import urlopen

print("Loading function")

#======================================================================================================================
# Constants
#======================================================================================================================
# Configurables
OUTPUT_BUCKET = None
IP_SET_ID_BLACKLIST = None
IP_SET_ID_AUTO_BLOCK = None

BLACKLIST_BLOCK_PERIOD = None # in minutes
REQUEST_PER_MINUTE_LIMIT = None
ERROR_PER_MINUTE_LIMIT = None
SEND_ANONYMOUS_USAGE_DATA = None
UUID = None
BLOCK_ERROR_CODES = ['400','403','404','405'] # error codes to parse logs for

LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION = 1000
API_CALL_NUM_RETRIES = 3

OUTPUT_FILE_NAME = 'aws-waf-security-automations-current-blocked-ips.json'

# Fixed
LINE_FORMAT = {
    'date': 0,
    'time' : 1,
    'source_ip' : 4,
    'code' : 8
}

REQUEST_COUNTER_INDEX = 0
ERROR_COUNTER_INDEX = 1


#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================
def get_outstanding_requesters(bucket_name, key_name):
    print("[get_outstanding_requesters] Start")

    outstanding_requesters = {}
    outstanding_requesters['block'] = {}
    result = {}
    num_requests = 0
    try:
        if REQUEST_PER_MINUTE_LIMIT < 0 and ERROR_PER_MINUTE_LIMIT < 0:
            return outstanding_requesters, num_requests

        #--------------------------------------------------------------------------------------------------------------
        print("[get_outstanding_requesters] \tDownload file from S3")
        #--------------------------------------------------------------------------------------------------------------
        local_file_path = '/tmp/' + key_name.split('/')[-1]
        s3 = boto3.client('s3')
        s3.download_file(bucket_name, key_name, local_file_path)

        #--------------------------------------------------------------------------------------------------------------
        print("[get_outstanding_requesters] \tRead file content")
        #--------------------------------------------------------------------------------------------------------------
        with gzip.open(local_file_path,'r') as content:
            for line in content:
                try:
                    if line.startswith('#'):
                        continue

                    line_data = line.split('\t')
                    request_key = line_data[LINE_FORMAT['date']]
                    request_key += '-' + line_data[LINE_FORMAT['time']][:-3]
                    request_key += '-' + line_data[LINE_FORMAT['source_ip']]
                    if request_key in result.keys():
                        result[request_key][REQUEST_COUNTER_INDEX] += 1
                    else:
                        result[request_key] = [1,0]

                    if line_data[LINE_FORMAT['code']] in BLOCK_ERROR_CODES:
                        result[request_key][ERROR_COUNTER_INDEX] += 1

                    num_requests += 1

                except Exception, e:
                    print ("[get_outstanding_requesters] \t\tError to process line: %s"%line)

        #--------------------------------------------------------------------------------------------------------------
        print("[get_outstanding_requesters] \tKeep only outstanding requesters")
        #--------------------------------------------------------------------------------------------------------------
        now_timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for k, v in result.iteritems():
            k = k.split('-')[-1]
            if (
                    (REQUEST_PER_MINUTE_LIMIT >= 0 and v[REQUEST_COUNTER_INDEX] > REQUEST_PER_MINUTE_LIMIT) or
                    (ERROR_PER_MINUTE_LIMIT >= 0 and v[ERROR_COUNTER_INDEX] > ERROR_PER_MINUTE_LIMIT)
                ):
                if k not in outstanding_requesters['block'].keys() or (
                        outstanding_requesters['block'][k]['max_req_per_min'] < v[REQUEST_COUNTER_INDEX] or
                        outstanding_requesters['block'][k]['max_err_per_min'] < v[ERROR_COUNTER_INDEX]
                    ):
                    outstanding_requesters['block'][k] = {
                        'max_req_per_min': v[REQUEST_COUNTER_INDEX],
                        'max_err_per_min': v[ERROR_COUNTER_INDEX],
                        'updated_at': now_timestamp_str
                    }

    except Exception, e:
        print("[get_outstanding_requesters] \tError to read input file")

    print("[get_outstanding_requesters] End")
    return outstanding_requesters, num_requests

def merge_current_blocked_requesters(key_name, outstanding_requesters):
    print("[merge_current_blocked_requesters] Start")

    try:
        now_timestamp = datetime.datetime.now()
        now_timestamp_str = now_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        remote_outstanding_requesters = {}

        #--------------------------------------------------------------------------------------------------------------
        print("[merge_current_blocked_requesters] \tDownload current blocked IPs")
        #--------------------------------------------------------------------------------------------------------------
        local_file_path = '/tmp/' + key_name.split('/')[-1] + '_REMOTE.json'
        s3 = boto3.client('s3')
        s3.download_file(OUTPUT_BUCKET, OUTPUT_FILE_NAME, local_file_path)

        with open(local_file_path, 'r') as file_content:
            remote_outstanding_requesters = json.loads(file_content.read())

        #----------------------------------------------------------------------------------------------------------
        print("[merge_current_blocked_requesters] \tExpire Block IP rules")
        #----------------------------------------------------------------------------------------------------------
        for k, v in remote_outstanding_requesters['block'].iteritems():
            try:
                if (
                        (REQUEST_PER_MINUTE_LIMIT >= 0 and v['max_req_per_min'] > REQUEST_PER_MINUTE_LIMIT) or
                        (ERROR_PER_MINUTE_LIMIT >= 0 and v['max_err_per_min'] > ERROR_PER_MINUTE_LIMIT)
                    ):
                    if k in outstanding_requesters['block'].keys():
                        print("[merge_current_blocked_requesters] \t\tUpdating data of BLOCK %s rule"%k)
                        outstanding_requesters['block'][k]['updated_at'] = now_timestamp_str
                        if v['max_req_per_min'] > outstanding_requesters['block'][k]['max_req_per_min']:
                            outstanding_requesters['block'][k]['max_req_per_min'] = v['max_req_per_min']
                        if v['max_err_per_min'] > outstanding_requesters['block'][k]['max_err_per_min']:
                            outstanding_requesters['block'][k]['max_err_per_min'] = v['max_err_per_min']

                    else:
                        prev_updated_at = datetime.datetime.strptime(v['updated_at'], "%Y-%m-%d %H:%M:%S")
                        total_diff_min = ((now_timestamp - prev_updated_at).total_seconds())/60
                        if total_diff_min < BLACKLIST_BLOCK_PERIOD:
                            print("[merge_current_blocked_requesters] \t\tKeeping %s rule"%k)
                            outstanding_requesters['block'][k] = v
                        else:
                            print("[merge_current_blocked_requesters] \t\tExpired %s rule"%k)

            except Exception, e:
                print("[merge_current_blocked_requesters] \tError merging %s rule"%k)
                print(e)

    except Exception, e:
        print("[merge_current_blocked_requesters] \tError merging data")
        print(e)

    print("[merge_current_blocked_requesters] End")
    return outstanding_requesters

def write_output(key_name, outstanding_requesters):
    print("[write_output] Start")

    try:
        current_data = '/tmp/' + key_name.split('/')[-1] + '_LOCAL.json'
        with open(current_data, 'w') as outfile:
            json.dump(outstanding_requesters, outfile)

        s3 = boto3.client('s3')
        s3.upload_file(current_data, OUTPUT_BUCKET, OUTPUT_FILE_NAME, ExtraArgs={'ContentType': "application/json"})

    except Exception, e:
        print("[write_output] \tError to write output file")

    print("[write_output] End")

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

def waf_update_ip_set(ip_set_id, updates_list):
    response = None

    if updates_list != []:
        waf = boto3.client('waf')
        for attempt in range(API_CALL_NUM_RETRIES):
            try:
                response = waf.update_ip_set(IPSetId=ip_set_id,
                    ChangeToken=waf.get_change_token()['ChangeToken'],
                    Updates=updates_list)
            except Exception, e:
                delay = math.pow(2, attempt)
                print("[waf_update_ip_set] Retrying in %d seconds..." % (delay))
                time.sleep(delay)
            else:
                break
        else:
            print("[waf_update_ip_set] Failed ALL attempts to call API")

    return response

def get_ip_set_already_blocked():
    print("[get_ip_set_already_blocked] Start")
    ip_set_already_blocked = []
    try:
        if IP_SET_ID_BLACKLIST != None:
            response = waf_get_ip_set(IP_SET_ID_BLACKLIST)
            if response != None:
                for k in response['IPSet']['IPSetDescriptors']:
                    ip_set_already_blocked.append(k['Value'])
    except Exception, e:
        print("[get_ip_set_already_blocked] Error getting WAF IP set")
        print(e)

    print("[get_ip_set_already_blocked] End")
    return ip_set_already_blocked

def is_already_blocked(ip, ip_set):
    result = False

    try:
        for net in ip_set:
            ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
            netstr, bits = net.split('/')
            netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
            mask = (0xffffffff << (32 - int(bits))) & 0xffffffff

            if (ipaddr & mask) == (netaddr & mask):
                result = True
                break
    except Exception, e:
        pass

    return result

def update_waf_ip_set(outstanding_requesters, ip_set_id, ip_set_already_blocked):
    print("[update_waf_ip_set] Start")

    counter = 0
    try:
        if ip_set_id == None:
            print("[update_waf_ip_set] Ignore process when ip_set_id is None")
            return

        updates_list = []
        waf = boto3.client('waf')

        #--------------------------------------------------------------------------------------------------------------
        print("[update_waf_ip_set] \tTruncate [if necessary] list to respect WAF limit")
        #--------------------------------------------------------------------------------------------------------------
        top_outstanding_requesters = {}
        for key, value in sorted(outstanding_requesters.items(), key=lambda kv: kv[1]['max_req_per_min'], reverse=True):
            if counter < LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION:
                if not is_already_blocked(key, ip_set_already_blocked):
                    top_outstanding_requesters[key] = value
                    counter += 1
            else:
                break

        #--------------------------------------------------------------------------------------------------------------
        print("[update_waf_ip_set] \tRemove IPs that are not in current outstanding requesters list")
        #--------------------------------------------------------------------------------------------------------------
        response = waf_get_ip_set(ip_set_id)
        if response != None:
            for k in response['IPSet']['IPSetDescriptors']:
                ip_value = k['Value'].split('/')[0]
                if ip_value not in top_outstanding_requesters.keys():
                    updates_list.append({
                        'Action': 'DELETE',
                        'IPSetDescriptor': {
                            'Type': 'IPV4',
                            'Value': k['Value']
                        }
                    })
                else:
                    # Dont block an already blocked IP
                    top_outstanding_requesters.pop(ip_value, None)

        #--------------------------------------------------------------------------------------------------------------
        print("[update_waf_ip_set] \tBlock remaining outstanding requesters")
        #--------------------------------------------------------------------------------------------------------------
        for k in top_outstanding_requesters.keys():
            updates_list.append({
                'Action': 'INSERT',
                'IPSetDescriptor': {
                    'Type': 'IPV4',
                    'Value': "%s/32"%k
                }
            })

        #--------------------------------------------------------------------------------------------------------------
        print("[update_waf_ip_set] \tCommit changes in WAF IP set")
        #--------------------------------------------------------------------------------------------------------------
        response = waf_update_ip_set(ip_set_id, updates_list)

    except Exception, e:
        print("[update_waf_ip_set] Error to update waf ip set")
        print(e)

    print("[update_waf_ip_set] End")
    return counter

def send_anonymous_usage_data():
    if SEND_ANONYMOUS_USAGE_DATA != 'yes':
        return

    try:
        print("[send_anonymous_usage_data] Start")
        auto_block_ip_set_size = 0
        blacklist_set_size = 0
        allowed_requests = 0
        blocked_requests_all = 0
        blocked_requests_auto_block = 0
        blocked_requests_blacklist = 0

        #--------------------------------------------------------------------------------------------------------------
        print("[send_anonymous_usage_data] Get Auto Block IP Set Size")
        #--------------------------------------------------------------------------------------------------------------
        response = waf_get_ip_set(IP_SET_ID_AUTO_BLOCK)
        if response != None:
            auto_block_ip_set_size = len(response['IPSet']['IPSetDescriptors'])

        #--------------------------------------------------------------------------------------------------------------
        print("[send_anonymous_usage_data] Get Blacklist IP Set Size")
        #--------------------------------------------------------------------------------------------------------------
        response = waf_get_ip_set(IP_SET_ID_BLACKLIST)
        if response != None:
            blacklist_set_size = len(response['IPSet']['IPSetDescriptors'])

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
        print("[send_anonymous_usage_data] Get Num Blocked Requests - Auto Block Rule")
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
                        "Value": "SecurityAutomationsAutoBlockRule"
                    },
                    {
                        "Name": "WebACL",
                        "Value": "SecurityAutomationsMaliciousRequesters"
                    }
                ]
            )
            blocked_requests_auto_block = response['Datapoints'][0]['Sum']
        except Exception, e:
            print("[send_anonymous_usage_data] Error to get Num Blocked Requests")

        #--------------------------------------------------------------------------------------------------------------
        print("[send_anonymous_usage_data] Get Num Blocked Requests - Blacklist Rule")
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
                        "Value": "SecurityAutomationsBlacklistRule"
                    },
                    {
                        "Name": "WebACL",
                        "Value": "SecurityAutomationsMaliciousRequesters"
                    }
                ]
            )
            blocked_requests_blacklist = response['Datapoints'][0]['Sum']
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
              "data_type" : "http_flood_scanner_probe",
              "blacklist_set_size" : blacklist_set_size,
              "auto_block_ip_set_size" : auto_block_ip_set_size,
              "allowed_requests" : allowed_requests,
              "blocked_requests_all" : blocked_requests_all,
              "blocked_requests_auto_block" : blocked_requests_auto_block,
              "blocked_requests_blacklist" : blocked_requests_blacklist
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
    print("[lambda_handler] Start")
    print(event)
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    key_name = urllib.unquote_plus(event['Records'][0]['s3']['object']['key']).decode('utf8')

    try:
        if key_name == OUTPUT_FILE_NAME:
            print("[lambda_handler] \tIgnore processinf output file")
            return

        #--------------------------------------------------------------------------------------------------------------
        print("[lambda_handler] \tReading (if necessary) CloudFormation output values")
        #--------------------------------------------------------------------------------------------------------------
        global OUTPUT_BUCKET
        global IP_SET_ID_BLACKLIST
        global IP_SET_ID_AUTO_BLOCK
        global BLACKLIST_BLOCK_PERIOD
        global REQUEST_PER_MINUTE_LIMIT
        global ERROR_PER_MINUTE_LIMIT
        global SEND_ANONYMOUS_USAGE_DATA
        global UUID

        if (OUTPUT_BUCKET == None or IP_SET_ID_BLACKLIST == None or
            IP_SET_ID_AUTO_BLOCK == None or BLACKLIST_BLOCK_PERIOD == None or
            REQUEST_PER_MINUTE_LIMIT == None or ERROR_PER_MINUTE_LIMIT == None or
            SEND_ANONYMOUS_USAGE_DATA == None or UUID == None):

            outputs = {}
            cf = boto3.client('cloudformation')
            stack_name = os.environ['StackName']
            cf_desc = cf.describe_stacks(StackName=stack_name)
            for e in cf_desc['Stacks'][0]['Outputs']:
                outputs[e['OutputKey']] = e['OutputValue']

            if OUTPUT_BUCKET == None:
                if 'CloudFrontAccessLogBucket' in outputs.keys():
                    OUTPUT_BUCKET = outputs['CloudFrontAccessLogBucket']
                else:
                    OUTPUT_BUCKET = bucket_name
            if IP_SET_ID_BLACKLIST == None:
                IP_SET_ID_BLACKLIST = outputs['BlacklistIPSetID']
            if IP_SET_ID_AUTO_BLOCK == None:
                IP_SET_ID_AUTO_BLOCK = outputs['AutoBlockIPSetID']
            if BLACKLIST_BLOCK_PERIOD == None:
                BLACKLIST_BLOCK_PERIOD = int(outputs['WAFBlockPeriod']) # in minutes
            if REQUEST_PER_MINUTE_LIMIT == None:
                try:
                    REQUEST_PER_MINUTE_LIMIT = int(outputs['RequestThreshold'])
                except Exception, e:
                    REQUEST_PER_MINUTE_LIMIT = -1
            if ERROR_PER_MINUTE_LIMIT == None:
                try:
                    ERROR_PER_MINUTE_LIMIT = int(outputs['ErrorThreshold'])
                except Exception, e:
                    ERROR_PER_MINUTE_LIMIT = -1
            if SEND_ANONYMOUS_USAGE_DATA == None:
                SEND_ANONYMOUS_USAGE_DATA = outputs['SendAnonymousUsageData']
            if UUID == None:
                UUID = outputs['UUID']



        print("[lambda_handler] \t\tOUTPUT_BUCKET = %s"%OUTPUT_BUCKET)
        print("[lambda_handler] \t\tIP_SET_ID_BLACKLIST = %s"%IP_SET_ID_BLACKLIST)
        print("[lambda_handler] \t\tIP_SET_ID_AUTO_BLOCK = %s"%IP_SET_ID_AUTO_BLOCK)
        print("[lambda_handler] \t\tBLACKLIST_BLOCK_PERIOD = %d"%BLACKLIST_BLOCK_PERIOD)
        print("[lambda_handler] \t\tREQUEST_PER_MINUTE_LIMIT = %d"%REQUEST_PER_MINUTE_LIMIT)
        print("[lambda_handler] \t\tERROR_PER_MINUTE_LIMIT = %d"%ERROR_PER_MINUTE_LIMIT)
        print("[lambda_handler] \t\tSEND_ANONYMOUS_USAGE_DATA = %s"%SEND_ANONYMOUS_USAGE_DATA)
        print("[lambda_handler] \t\tUUID = %s"%UUID)

        #--------------------------------------------------------------------------------------------------------------
        print("[lambda_handler] \tReading input data and get outstanding requesters")
        #--------------------------------------------------------------------------------------------------------------
        outstanding_requesters, num_requests = get_outstanding_requesters(bucket_name, key_name)

        #--------------------------------------------------------------------------------------------------------------
        print("[lambda_handler] \tMerge with current blocked requesters")
        #--------------------------------------------------------------------------------------------------------------
        outstanding_requesters = merge_current_blocked_requesters(key_name, outstanding_requesters)

        #--------------------------------------------------------------------------------------------------------------
        print("[lambda_handler] \tUpdate new blocked requesters list to S3")
        #--------------------------------------------------------------------------------------------------------------
        write_output(key_name, outstanding_requesters)

        #--------------------------------------------------------------------------------------------------------------
        print("[lambda_handler] \tUpdate WAF IP Set")
        #--------------------------------------------------------------------------------------------------------------
        ip_set_already_blocked = get_ip_set_already_blocked()
        num_blocked = update_waf_ip_set(outstanding_requesters['block'], IP_SET_ID_AUTO_BLOCK, ip_set_already_blocked)

        send_anonymous_usage_data()

        return outstanding_requesters
    except Exception as e:
        raise e
    print("[lambda_handler] End")
