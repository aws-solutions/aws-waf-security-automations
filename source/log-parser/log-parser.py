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
from os import environ

from urllib2 import Request
from urllib2 import urlopen

print("Loading function")

#======================================================================================================================
# Constants
#======================================================================================================================
API_CALL_NUM_RETRIES = 3
BLOCK_ERROR_CODES = ['400','403','404','405'] # error codes to parse logs for
OUTPUT_FILE_NAME = 'aws-waf-security-automations-current-blocked-ips.json'

# CloudFront Access Logs
# http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html#BasicDistributionFileFormat
LINE_FORMAT_CLOUD_FRONT = {
    'delimiter': '\t',
    'date': 0,
    'time' : 1,
    'source_ip' : 4,
    'code' : 8
}
# ALB Access Logs
# http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
LINE_FORMAT_ALB = {
    'delimiter': ' ',
    'timestamp': 1,
    'source_ip' : 3,
    'code' : 8
}


REQUEST_COUNTER_INDEX = 0
ERROR_COUNTER_INDEX = 1

waf = None

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
        if int(environ['ERROR_PER_MINUTE_LIMIT']) < 0:
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

                    return_code_index = None
                    if environ['LOG_TYPE'] == 'cloudfront':
                        line_data = line.split(LINE_FORMAT_CLOUD_FRONT['delimiter'])
                        request_key = line_data[LINE_FORMAT_CLOUD_FRONT['date']]
                        request_key += '-' + line_data[LINE_FORMAT_CLOUD_FRONT['time']][:-3]
                        request_key += '-' + line_data[LINE_FORMAT_CLOUD_FRONT['source_ip']]
                        return_code_index = LINE_FORMAT_CLOUD_FRONT['code']
                    elif environ['LOG_TYPE'] == 'alb':
                        line_data = line.split(LINE_FORMAT_ALB['delimiter'])
                        request_key = line_data[LINE_FORMAT_ALB['timestamp']].rsplit(':', 1)[0]
                        request_key += '-' + line_data[LINE_FORMAT_ALB['source_ip']].split(':')[0]
                        return_code_index = LINE_FORMAT_ALB['code']
                    else:
                        return outstanding_requesters, num_requests

                    if request_key in result.keys():
                        result[request_key][REQUEST_COUNTER_INDEX] += 1
                    else:
                        result[request_key] = [1,0]

                    if line_data[return_code_index] in BLOCK_ERROR_CODES:
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
            if int(environ['ERROR_PER_MINUTE_LIMIT']) >= 0 and v[ERROR_COUNTER_INDEX] > int(environ['ERROR_PER_MINUTE_LIMIT']):
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

    expired = False
    last_update_age = 0
    try:
        remote_outstanding_requesters = {}

        #--------------------------------------------------------------------------------------------------------------
        print("[merge_current_blocked_requesters] \tCalculate Last Update Age")
        #--------------------------------------------------------------------------------------------------------------
        s3 = boto3.client('s3')
        local_file_path = '/tmp/' + key_name.split('/')[-1] + '_REMOTE.json'
        response = s3.head_object(Bucket=environ['OUTPUT_BUCKET'], Key=OUTPUT_FILE_NAME)
        now_timestamp = datetime.datetime.now(response['LastModified'].tzinfo)
        now_timestamp_str = now_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        last_update_age = int(((now_timestamp - response['LastModified']).total_seconds())/60)

        #--------------------------------------------------------------------------------------------------------------
        print("[merge_current_blocked_requesters] \tDownload current blocked IPs")
        #--------------------------------------------------------------------------------------------------------------
        s3.download_file(environ['OUTPUT_BUCKET'], OUTPUT_FILE_NAME, local_file_path)

        with open(local_file_path, 'r') as file_content:
            remote_outstanding_requesters = json.loads(file_content.read())

        #----------------------------------------------------------------------------------------------------------
        print("[merge_current_blocked_requesters] \tExpire Block IP rules")
        #----------------------------------------------------------------------------------------------------------
        for k, v in remote_outstanding_requesters['block'].iteritems():
            try:
                if int(environ['ERROR_PER_MINUTE_LIMIT']) >= 0 and v['max_err_per_min'] > int(environ['ERROR_PER_MINUTE_LIMIT']):
                    if k in outstanding_requesters['block'].keys():
                        print("[merge_current_blocked_requesters] \t\tUpdating data of BLOCK %s rule"%k)
                        outstanding_requesters['block'][k]['updated_at'] = now_timestamp_str
                        if v['max_req_per_min'] > outstanding_requesters['block'][k]['max_req_per_min']:
                            outstanding_requesters['block'][k]['max_req_per_min'] = v['max_req_per_min']
                        if v['max_err_per_min'] > outstanding_requesters['block'][k]['max_err_per_min']:
                            outstanding_requesters['block'][k]['max_err_per_min'] = v['max_err_per_min']

                    else:
                        prev_updated_at = datetime.datetime.strptime(v['updated_at'], "%Y-%m-%d %H:%M:%S")
                        prev_updated_at = prev_updated_at.replace(tzinfo=response['LastModified'].tzinfo)
                        total_diff_min = ((now_timestamp - prev_updated_at).total_seconds())/60
                        if total_diff_min < int(environ['BLACKLIST_BLOCK_PERIOD']):
                            print("[merge_current_blocked_requesters] \t\tKeeping %s rule"%k)
                            outstanding_requesters['block'][k] = v
                        else:
                            expired = True
                            print("[merge_current_blocked_requesters] \t\tExpired %s rule"%k)

            except Exception, e:
                print("[merge_current_blocked_requesters] \tError merging %s rule"%k)
                print(e)

    except Exception, e:
        print("[merge_current_blocked_requesters] \tError merging data")
        print(e)

    need_update = (expired or last_update_age > int(environ['MAX_AGE_TO_UPDATE']) or len(outstanding_requesters['block']) > 0)

    print("[merge_current_blocked_requesters] End")
    return outstanding_requesters, need_update

def write_output(key_name, outstanding_requesters):
    print("[write_output] Start")

    try:
        current_data = '/tmp/' + key_name.split('/')[-1] + '_LOCAL.json'
        with open(current_data, 'w') as outfile:
            json.dump(outstanding_requesters, outfile)

        s3 = boto3.client('s3')
        s3.upload_file(current_data, environ['OUTPUT_BUCKET'], OUTPUT_FILE_NAME, ExtraArgs={'ContentType': "application/json"})

    except Exception, e:
        print("[write_output] \tError to write output file")

    print("[write_output] End")

def waf_get_ip_set(ip_set_id):
    response = None

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
        if environ['IP_SET_ID_BLACKLIST'] != None:
            response = waf_get_ip_set(environ['IP_SET_ID_BLACKLIST'])
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

        #--------------------------------------------------------------------------------------------------------------
        print("[update_waf_ip_set] \tTruncate [if necessary] list to respect WAF limit")
        #--------------------------------------------------------------------------------------------------------------
        top_outstanding_requesters = {}
        for key, value in sorted(outstanding_requesters.items(), key=lambda kv: kv[1]['max_req_per_min'], reverse=True):
            if counter < int(environ['LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION']):
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
    if environ['SEND_ANONYMOUS_USAGE_DATA'] != 'yes':
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
        response = waf_get_ip_set(environ['IP_SET_ID_AUTO_BLOCK'])
        if response != None:
            auto_block_ip_set_size = len(response['IPSet']['IPSetDescriptors'])

        #--------------------------------------------------------------------------------------------------------------
        print("[send_anonymous_usage_data] Get Blacklist IP Set Size")
        #--------------------------------------------------------------------------------------------------------------
        response = waf_get_ip_set(environ['IP_SET_ID_BLACKLIST'])
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
                        "Value": environ['ACL_METRIC_NAME']
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
                        "Value": environ['ACL_METRIC_NAME']
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
          "UUID": environ['UUID'],
          "TimeStamp": time_stamp,
          "Data":
          {
              "data_type" : "http_flood_scanner_probe",
              "blacklist_set_size" : blacklist_set_size,
              "auto_block_ip_set_size" : auto_block_ip_set_size,
              "allowed_requests" : allowed_requests,
              "blocked_requests_all" : blocked_requests_all,
              "blocked_requests_auto_block" : blocked_requests_auto_block,
              "blocked_requests_blacklist" : blocked_requests_blacklist,
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
    print("[lambda_handler] Start")

    outstanding_requesters = {}

    try:
        bucket_name = event['Records'][0]['s3']['bucket']['name']
        key_name = urllib.unquote_plus(event['Records'][0]['s3']['object']['key']).decode('utf8')

        if key_name == OUTPUT_FILE_NAME:
            print("[lambda_handler] \tIgnore processing output file")
            return

        global waf
        if environ['LOG_TYPE'] == 'alb':
            session = boto3.session.Session(region_name=environ['REGION'])
            waf = session.client('waf-regional')
        else:
            waf = boto3.client('waf')

        #--------------------------------------------------------------------------------------------------------------
        print("[lambda_handler] \tReading input data and get outstanding requesters")
        #--------------------------------------------------------------------------------------------------------------
        outstanding_requesters, num_requests = get_outstanding_requesters(bucket_name, key_name)

        #--------------------------------------------------------------------------------------------------------------
        print("[lambda_handler] \tMerge with current blocked requesters")
        #--------------------------------------------------------------------------------------------------------------
        outstanding_requesters, need_update = merge_current_blocked_requesters(key_name, outstanding_requesters)

        if need_update:
            #----------------------------------------------------------------------------------------------------------
            print("[lambda_handler] \tUpdate new blocked requesters list to S3")
            #----------------------------------------------------------------------------------------------------------
            write_output(key_name, outstanding_requesters)

            #----------------------------------------------------------------------------------------------------------
            print("[lambda_handler] \tUpdate WAF IP Set")
            #----------------------------------------------------------------------------------------------------------
            ip_set_already_blocked = get_ip_set_already_blocked()
            num_blocked = update_waf_ip_set(outstanding_requesters['block'], environ['IP_SET_ID_AUTO_BLOCK'], ip_set_already_blocked)

            send_anonymous_usage_data()

        else:
            #----------------------------------------------------------------------------------------------------------
            print("[lambda_handler] \tNo changes identified")
            #----------------------------------------------------------------------------------------------------------

    except Exception as e:
        raise e

    print("[lambda_handler] End")
    return outstanding_requesters
