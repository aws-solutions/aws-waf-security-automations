#####################################################################################################################
# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
#                                                                                                                   #
# Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance        #
# with the License. A copy of the License is located at                                                             #
#                                                                                                                   #
#     http://aws.amazon.com/asl/                                                                                    #
#                                                                                                                   #
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
# OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
# and limitations under the License.                                                                                #
#####################################################################################################################

import boto3
import csv
import gzip
import json
import logging
import datetime
import time
from os import environ
from ipaddress import ip_address
from botocore.config import Config
from urllib.parse import unquote_plus
from urllib.request import Request, urlopen
from urllib.parse import urlparse

logging.getLogger().debug('Loading function')

#======================================================================================================================
# Constants/Globals
#======================================================================================================================
API_CALL_NUM_RETRIES = 5
MAX_DESCRIPTORS_PER_IP_SET_UPDATE = 500
DELAY_BETWEEN_UPDATES = 2

# CloudFront Access Logs
# http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html#BasicDistributionFileFormat
LINE_FORMAT_CLOUD_FRONT = {
    'delimiter': '\t',
    'date': 0,
    'time' : 1,
    'source_ip' : 4,
    'uri': 7,
    'code' : 8
}
# ALB Access Logs
# http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
LINE_FORMAT_ALB = {
    'delimiter': ' ',
    'timestamp': 1,
    'source_ip' : 3,
    'code' : 9, # GitHub issue #44. Changed from elb_status_code to target_status_code.
    'uri': 13
}

waf = None
config = {}

#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================
def waf_get_ip_set(ip_set_id):
    logging.getLogger().debug('[waf_get_ip_set] Start')
    response = waf.get_ip_set(IPSetId=ip_set_id)
    logging.getLogger().debug('[waf_get_ip_set] End')
    return response

def waf_commit_updates(ip_set_id, updates_list):
    logging.getLogger().debug('[waf_commit_updates] Start')
    response = None

    if len(updates_list) > 0:
        index = 0
        while index < len(updates_list):
            logging.getLogger().debug('[waf_commit_updates] Processing from index %d.'%index)

            response = waf.update_ip_set(IPSetId=ip_set_id,
                ChangeToken=waf.get_change_token()['ChangeToken'],
                Updates=updates_list[index: index + MAX_DESCRIPTORS_PER_IP_SET_UPDATE])

            index += MAX_DESCRIPTORS_PER_IP_SET_UPDATE
            if index < len(updates_list):
                logging.getLogger().debug('[waf_commit_updates] Sleep %d sec befone next slot to avoid AWS WAF API throttling ...'%DELAY_BETWEEN_UPDATES)
                time.sleep(DELAY_BETWEEN_UPDATES)

    logging.getLogger().debug('[waf_commit_updates] End')
    return response

def update_waf_ip_set(ip_set_id, outstanding_requesters):
    logging.getLogger().debug('[update_waf_ip_set] Start')

    counter = 0
    try:
        if ip_set_id == None:
            logging.getLogger().info("[update_waf_ip_set] Ignore process when ip_set_id is None")
            return

        updates_list = []

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[update_waf_ip_set] \tMerge general and uriList into a single list")
        #--------------------------------------------------------------------------------------------------------------
        unified_outstanding_requesters = outstanding_requesters['general']
        for uri in outstanding_requesters['uriList'].keys():
            for k in outstanding_requesters['uriList'][uri].keys():
                if (k not in unified_outstanding_requesters.keys() or
                    outstanding_requesters['uriList'][uri][k]['max_counter_per_min'] > unified_outstanding_requesters[k]['max_counter_per_min']):
                    unified_outstanding_requesters[k] = outstanding_requesters['uriList'][uri][k]

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[update_waf_ip_set] \tTruncate [if necessary] list to respect WAF limit")
        #--------------------------------------------------------------------------------------------------------------
        if len(unified_outstanding_requesters) > int(environ['LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION']):
            ordered_unified_outstanding_requesters = sorted(unified_outstanding_requesters.items(), key=lambda kv: kv[1]['max_counter_per_min'], reverse=True)
            unified_outstanding_requesters = {}
            for key, value in ordered_unified_outstanding_requesters:
                if counter < int(environ['LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION']):
                    unified_outstanding_requesters[key] = value
                    counter += 1
                else:
                    break

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[update_waf_ip_set] \tRemove IPs that are not in current outstanding requesters list")
        #--------------------------------------------------------------------------------------------------------------
        response = waf_get_ip_set(ip_set_id)
        if response != None:
            for k in response['IPSet']['IPSetDescriptors']:
                ip_value = k['Value'].split('/')[0]
                if ip_value not in unified_outstanding_requesters.keys():
                    ip_type = "IPV%s"%ip_address(ip_value).version
                    updates_list.append({
                        'Action': 'DELETE',
                        'IPSetDescriptor': {
                            'Type': ip_type,
                            'Value': k['Value']
                        }
                    })
                else:
                    # Dont block an already blocked IP
                    unified_outstanding_requesters.pop(ip_value, None)

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[update_waf_ip_set] \tBlock remaining outstanding requesters")
        #--------------------------------------------------------------------------------------------------------------
        for k in unified_outstanding_requesters.keys():
            ip_type = "IPV%s"%ip_address(k).version
            ip_class = "32" if ip_type == "IPV4" else "128"
            updates_list.append({
                'Action': 'INSERT',
                'IPSetDescriptor': {
                    'Type': ip_type,
                    'Value': "%s/%s"%(k, ip_class)
                }
            })

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[update_waf_ip_set] \tCommit changes in WAF IP set")
        #--------------------------------------------------------------------------------------------------------------
        response = waf_commit_updates(ip_set_id, updates_list)

    except Exception as error:
        logging.getLogger().error(str(error))
        logging.getLogger().error("[update_waf_ip_set] Error to update waf ip set")

    logging.getLogger().debug('[update_waf_ip_set] End')
    return counter

def send_anonymous_usage_data():
    try:
        if 'SEND_ANONYMOUS_USAGE_DATA' not in environ or environ['SEND_ANONYMOUS_USAGE_DATA'].lower() != 'yes':
            return

        logging.getLogger().debug("[send_anonymous_usage_data] Start")

        cw = boto3.client('cloudwatch')
        usage_data = {
            "Solution": "SO0006",
            "UUID": environ['UUID'],
            "TimeStamp": str(datetime.datetime.utcnow().isoformat()),
            "Data":
            {
                "data_type" : "lop_parser",
                "scanners_probes_set_size": 0,
                "http_flood_set_size": 0,
                "allowed_requests" : 0,
                "blocked_requests_all" : 0,
                "blocked_requests_scanners_probes": 0,
                "blocked_requests_http_flood": 0,
                "waf_type" : environ['LOG_TYPE']
            }
        }

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().debug("[send_anonymous_usage_data] Get num allowed requests")
        #--------------------------------------------------------------------------------------------------------------
        try:
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
                        "Value": environ['METRIC_NAME_PREFIX'] + 'MaliciousRequesters'
                    }
                ]
            )
            usage_data['Data']['allowed_requests'] = response['Datapoints'][0]['Sum']

        except Exception as error:
            logging.getLogger().debug("[send_anonymous_usage_data] Failed to get Num Allowed Requests")
            logging.getLogger().debug(str(error))

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[send_anonymous_usage_data] Get num blocked requests - all rules")
        #--------------------------------------------------------------------------------------------------------------
        try:
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
                        "Value": environ['METRIC_NAME_PREFIX'] + 'MaliciousRequesters'
                    }
                ]
            )
            usage_data['Data']['blocked_requests_all'] = response['Datapoints'][0]['Sum']

        except Exception as error:
            logging.getLogger().debug("[send_anonymous_usage_data] Failed to get num blocked requests - all rules")
            logging.getLogger().debug(str(error))

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().debug("[send_anonymous_usage_data] Get scanners probes data")
        #--------------------------------------------------------------------------------------------------------------
        if 'IP_SET_ID_SCANNERS_PROBES' in environ:
            try:
                response = waf_get_ip_set(environ['IP_SET_ID_SCANNERS_PROBES'])
                if response != None:
                    usage_data['Data']['scanners_probes_set_size'] = len(response['IPSet']['IPSetDescriptors'])

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
                            "Value": environ['METRIC_NAME_PREFIX'] + 'ScannersProbesRule'
                        },
                        {
                            "Name": "WebACL",
                            "Value": environ['METRIC_NAME_PREFIX'] + 'MaliciousRequesters'
                        }
                    ]
                )
                usage_data['Data']['blocked_requests_scanners_probes'] = response['Datapoints'][0]['Sum']

            except Exception as error:
                logging.getLogger().debug("[send_anonymous_usage_data] Failed to get scanners probes data")
                logging.getLogger().debug(str(error))

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().debug("[send_anonymous_usage_data] Get HTTP flood data")
        #--------------------------------------------------------------------------------------------------------------
        if 'IP_SET_ID_HTTP_FLOOD' in environ:
            try:
                response = waf_get_ip_set(environ['IP_SET_ID_HTTP_FLOOD'])
                if response != None:
                    usage_data['Data']['http_flood_set_size'] = len(response['IPSet']['IPSetDescriptors'])

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
                            "Value": environ['METRIC_NAME_PREFIX'] + 'HttpFloodRule'
                        },
                        {
                            "Name": "WebACL",
                            "Value": environ['METRIC_NAME_PREFIX'] + 'MaliciousRequesters'
                        }
                    ]
                )
                usage_data['Data']['blocked_requests_http_flood'] = response['Datapoints'][0]['Sum']

            except Exception as error:
                logging.getLogger().debug("[send_anonymous_usage_data] Failed to get HTTP flood data")
                logging.getLogger().debug(str(error))

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[send_anonymous_usage_data] Send Data")
        #--------------------------------------------------------------------------------------------------------------
        url = 'https://metrics.awssolutionsbuilder.com/generic'
        req = Request(url, method='POST', data=bytes(json.dumps(usage_data), encoding='utf8'), headers={'Content-Type': 'application/json'})
        rsp = urlopen(req)
        rspcode = rsp.getcode()
        logging.getLogger().debug('[send_anonymous_usage_data] Response Code: {}'.format(rspcode))
        logging.getLogger().debug("[send_anonymous_usage_data] End")

    except Exception as error:
        logging.getLogger().debug("[send_anonymous_usage_data] Failed to send data")
        logging.getLogger().debug(str(error))

#======================================================================================================================
# Athena Log Parser
#======================================================================================================================
def process_athena_scheduler_event(event):
    logging.getLogger().debug('[process_athena_scheduler_event] Start')

    athena_client = boto3.client('athena')
    response = athena_client.get_named_query(NamedQueryId=event['logParserQuery'])

    s3_ouput = "s3://%s/athena_results/"%event['accessLogBucket']
    response = athena_client.start_query_execution(
        QueryString = response['NamedQuery']['QueryString'],
        QueryExecutionContext = {'Database': event['glueAccessLogsDatabase']},
        ResultConfiguration = {'OutputLocation': s3_ouput}
    )

    logging.getLogger().debug('[process_athena_scheduler_event] End')

def process_athena_result(bucket_name, key_name, ip_set_id):
    logging.getLogger().debug('[process_athena_result] Start')

    try:
        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[process_athena_result] \tDownload file from S3")
        #--------------------------------------------------------------------------------------------------------------
        local_file_path = '/tmp/' + key_name.split('/')[-1]
        s3 = boto3.client('s3')
        s3.download_file(bucket_name, key_name, local_file_path)

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[process_athena_result] \tRead file content")
        #--------------------------------------------------------------------------------------------------------------
        outstanding_requesters = {
            'general': {},
            'uriList': {}
        }
        utc_now_timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z%z")
        with open(local_file_path,'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # max_counter_per_min is set as 1 just to reuse lambda log parser data structure
                # and reuse update_waf_ip_set.
                outstanding_requesters['general'][row['client_ip']] = {
                    "max_counter_per_min": row['max_counter_per_min'],
                    "updated_at": utc_now_timestamp_str
                }

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[process_athena_result] \tUpdate WAF IP Set")
        #--------------------------------------------------------------------------------------------------------------
        update_waf_ip_set(ip_set_id, outstanding_requesters)

    except Exception:
        logging.getLogger().error("[process_athena_result] \tError to read input file")

    logging.getLogger().debug('[process_athena_result] End')

#======================================================================================================================
# Lambda Log Parser
#======================================================================================================================
def load_configurations(bucket_name, key_name):
    logging.getLogger().debug('[load_configurations] Start')

    try:
        s3 = boto3.resource('s3')
        file_obj = s3.Object(bucket_name, key_name)
        file_content = file_obj.get()['Body'].read()

        global config
        config = json.loads(file_content)

    except Exception as e:
        logging.getLogger().error("[load_configurations] \tError to read config file")
        raise e

    logging.getLogger().debug('[load_configurations] End')

def get_outstanding_requesters(bucket_name, key_name, log_type):
    logging.getLogger().debug('[get_outstanding_requesters] Start')

    counter = {
        'general': {},
        'uriList': {}
    }
    outstanding_requesters = {
        'general': {},
        'uriList': {}
    }

    try:
        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[get_outstanding_requesters] \tDownload file from S3")
        #--------------------------------------------------------------------------------------------------------------
        local_file_path = '/tmp/' + key_name.split('/')[-1]
        s3 = boto3.client('s3')
        s3.download_file(bucket_name, key_name, local_file_path)

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[get_outstanding_requesters] \tRead file content")
        #--------------------------------------------------------------------------------------------------------------
        with gzip.open(local_file_path,'r') as content:
            for line in content:
                try:
                    request_key = ""
                    uri = ""
                    return_code_index = None

                    if log_type == 'waf':
                        line = line.decode() # Remove the b in front of each field
                        line_data = json.loads(str(line))

                        request_key = datetime.datetime.fromtimestamp(int(line_data['timestamp'])/1000.0).isoformat(sep='T', timespec='minutes')
                        request_key += ' ' + line_data['httpRequest']['clientIp']
                        uri = urlparse(line_data['httpRequest']['uri']).path

                    elif log_type == 'alb':
                        line = line.decode('utf8')
                        if line.startswith('#'):
                            continue

                        line_data = line.split(LINE_FORMAT_ALB['delimiter'])
                        request_key = line_data[LINE_FORMAT_ALB['timestamp']].rsplit(':', 1)[0]
                        request_key += ' ' + line_data[LINE_FORMAT_ALB['source_ip']].rsplit(':', 1)[0]
                        return_code_index = LINE_FORMAT_ALB['code']
                        uri = urlparse(line_data[LINE_FORMAT_ALB['uri']]).path

                    elif log_type == 'cloudfront':
                        line = line.decode('utf8')
                        if line.startswith('#'):
                            continue

                        line_data = line.split(LINE_FORMAT_CLOUD_FRONT['delimiter'])
                        request_key = line_data[LINE_FORMAT_CLOUD_FRONT['date']]
                        request_key += ' ' + line_data[LINE_FORMAT_CLOUD_FRONT['time']][:-3]
                        request_key += ' ' + line_data[LINE_FORMAT_CLOUD_FRONT['source_ip']]
                        return_code_index = LINE_FORMAT_CLOUD_FRONT['code']
                        uri = urlparse(line_data[LINE_FORMAT_ALB['uri']]).path

                    else:
                        return outstanding_requesters

                    if 'ignoredSufixes' in config['general'] and uri.endswith(tuple(config['general']['ignoredSufixes'])):
                        logging.getLogger().debug("[get_outstanding_requesters] \t\tSkipping line %s. Included in ignoredSufixes."%line)
                        continue

                    if return_code_index == None or line_data[return_code_index] in config['general']['errorCodes']:
                        if request_key in counter['general'].keys():
                            counter['general'][request_key] += 1
                        else:
                            counter['general'][request_key] = 1

                        if 'uriList' in config and uri in config['uriList'].keys():
                            if uri not in counter['uriList'].keys():
                                counter['uriList'][uri] = {}

                            if request_key in counter['uriList'][uri].keys():
                                counter['uriList'][uri][request_key] += 1
                            else:
                                counter['uriList'][uri][request_key] = 1

                except Exception as e:
                    logging.getLogger().error("[get_outstanding_requesters] \t\tError to process line: %s"%line)

        #--------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[get_outstanding_requesters] \tKeep only outstanding requesters")
        #--------------------------------------------------------------------------------------------------------------
        threshold = 'requestThreshold' if log_type == 'waf' else "errorThreshold"
        utc_now_timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z%z")
        for k, num_reqs in counter['general'].items():
            try:
                k = k.split(' ')[-1]
                if num_reqs >= config['general'][threshold]:
                    if k not in outstanding_requesters['general'].keys() or num_reqs > outstanding_requesters['general'][k]['max_counter_per_min']:
                        outstanding_requesters['general'][k] = {
                            'max_counter_per_min': num_reqs,
                            'updated_at': utc_now_timestamp_str
                        }
            except Exception as e:
                logging.getLogger().error("[get_outstanding_requesters] \t\tError to process outstanding requester: %s"%k)

        for uri in counter['uriList'].keys():
            for k, num_reqs in counter['uriList'][uri].items():
                try:
                    k = k.split(' ')[-1]
                    if num_reqs >= config['uriList'][uri][threshold]:
                        if uri not in outstanding_requesters['uriList'].keys():
                            outstanding_requesters['uriList'][uri] = {}

                        if k not in outstanding_requesters['uriList'][uri].keys() or num_reqs > outstanding_requesters['uriList'][uri][k]['max_counter_per_min']:
                            outstanding_requesters['uriList'][uri][k] = {
                                'max_counter_per_min': num_reqs,
                                'updated_at': utc_now_timestamp_str
                            }
                except Exception as e:
                    logging.getLogger().error("[get_outstanding_requesters] \t\tError to process outstanding requester: (%s) %s"%(uri, k))

    except Exception as e:
        logging.getLogger().error("[get_outstanding_requesters] \tError to read input file")
        logging.getLogger().error(e)

    logging.getLogger().debug('[get_outstanding_requesters] End')
    return outstanding_requesters

def merge_outstanding_requesters(bucket_name, key_name, log_type, output_key_name, outstanding_requesters):
    logging.getLogger().debug('[merge_outstanding_requesters] Start')

    force_update = False
    need_update = False
    s3 = boto3.client('s3')

    #--------------------------------------------------------------------------------------------------------------
    logging.getLogger().info("[merge_outstanding_requesters] \tCalculate Last Update Age")
    #--------------------------------------------------------------------------------------------------------------
    response = None
    try:
        response = s3.head_object(Bucket=bucket_name, Key=output_key_name)
    except Exception:
        logging.getLogger().info('[merge_outstanding_requesters] No file to be merged.')
        need_update = True
        return outstanding_requesters, need_update

    utc_last_modified = response['LastModified'].astimezone(datetime.timezone.utc)
    utc_now_timestamp = datetime.datetime.now(datetime.timezone.utc)

    utc_now_timestamp_str = utc_now_timestamp.strftime("%Y-%m-%d %H:%M:%S %Z%z")
    last_update_age = int(((utc_now_timestamp - utc_last_modified).total_seconds())/60)

    #--------------------------------------------------------------------------------------------------------------
    logging.getLogger().info("[merge_outstanding_requesters] \tDownload current blocked IPs")
    #--------------------------------------------------------------------------------------------------------------
    local_file_path = '/tmp/' + key_name.split('/')[-1] + '_REMOTE.json'
    s3.download_file(bucket_name, output_key_name, local_file_path)

    #----------------------------------------------------------------------------------------------------------
    logging.getLogger().info("[merge_outstanding_requesters] \tProcess outstanding requesters files")
    #----------------------------------------------------------------------------------------------------------
    remote_outstanding_requesters = {
        'general': {},
        'uriList': {}
    }
    with open(local_file_path, 'r') as file_content:
        remote_outstanding_requesters = json.loads(file_content.read())

    threshold = 'requestThreshold' if log_type == 'waf' else "errorThreshold"
    try:
        if 'general' in remote_outstanding_requesters:
            for k, v in remote_outstanding_requesters['general'].items():
                try:
                    if k in outstanding_requesters['general'].keys():
                        logging.getLogger().info("[merge_outstanding_requesters] \t\tUpdating general data of BLOCK %s rule"%k)
                        outstanding_requesters['general'][k]['updated_at'] = utc_now_timestamp_str
                        if v['max_counter_per_min'] > outstanding_requesters['general'][k]['max_counter_per_min']:
                            outstanding_requesters['general'][k]['max_counter_per_min'] = v['max_counter_per_min']

                    else:
                        utc_prev_updated_at = datetime.datetime.strptime(v['updated_at'], "%Y-%m-%d %H:%M:%S %Z%z").astimezone(datetime.timezone.utc)
                        total_diff_min = ((utc_now_timestamp - utc_prev_updated_at).total_seconds())/60

                        if v['max_counter_per_min'] < config['general'][threshold]:
                            force_update = True
                            logging.getLogger().info("[merge_outstanding_requesters] \t\t%s is bellow the current general threshold"%k)

                        elif total_diff_min < config['general']['blockPeriod']:
                            logging.getLogger().debug("[merge_outstanding_requesters] \t\tKeeping %s in general"%k)
                            outstanding_requesters['general'][k] = v

                        else:
                            force_update = True
                            logging.getLogger().info("[merge_outstanding_requesters] \t\t%s expired in general"%k)

                except Exception:
                    logging.getLogger().error("[merge_outstanding_requesters] \tError merging general %s rule"%k)
    except Exception:
        logging.getLogger().error('[merge_outstanding_requesters] Failed to process general group.')

    try:
        if 'uriList' in remote_outstanding_requesters:
            if 'uriList' not in config or len(config['uriList']) == 0:
                force_update = True
                logging.getLogger().info("[merge_outstanding_requesters] \t\tCurrent config file does not contain uriList anymore")
            else:
                for uri in remote_outstanding_requesters['uriList'].keys():
                    if 'ignoredSufixes' in config['general'] and uri.endswith(tuple(config['general']['ignoredSufixes'])):
                        force_update = True
                        logging.getLogger().info("[merge_outstanding_requesters] \t\t%s is in current ignored sufixes list."%uri)
                        continue

                    for k, v in remote_outstanding_requesters['uriList'][uri].items():
                        try:
                            if uri in outstanding_requesters['uriList'].keys() and k in outstanding_requesters['uriList'][uri].keys():
                                logging.getLogger().info("[merge_outstanding_requesters] \t\tUpdating uriList (%s) data of BLOCK %s rule"%(uri, k))
                                outstanding_requesters['uriList'][uri][k]['updated_at'] = utc_now_timestamp_str
                                if v['max_counter_per_min'] > outstanding_requesters['uriList'][uri][k]['max_counter_per_min']:
                                    outstanding_requesters['uriList'][uri][k]['max_counter_per_min'] = v['max_counter_per_min']

                            else:
                                utc_prev_updated_at = datetime.datetime.strptime(v['updated_at'], "%Y-%m-%d %H:%M:%S %Z%z").astimezone(datetime.timezone.utc)
                                total_diff_min = ((utc_now_timestamp - utc_prev_updated_at).total_seconds())/60

                                if v['max_counter_per_min'] < config['uriList'][uri][threshold]:
                                    force_update = True
                                    logging.getLogger().info("[merge_outstanding_requesters] \t\t%s is bellow the current uriList (%s) threshold"%(k, uri))

                                elif total_diff_min < config['general']['blockPeriod']:
                                    logging.getLogger().debug("[merge_outstanding_requesters] \t\tKeeping %s in uriList (%s)"%(k, uri))

                                    if uri not in outstanding_requesters['uriList'].keys():
                                        outstanding_requesters['uriList'][uri] = {}

                                    outstanding_requesters['uriList'][uri][k] = v
                                else:
                                    force_update = True
                                    logging.getLogger().info("[merge_outstanding_requesters] \t\t%s expired in uriList (%s)"%(k, uri))

                        except Exception:
                            logging.getLogger().error("[merge_outstanding_requesters] \tError merging uriList (%s) %s rule"%(uri, k))
    except Exception:
        logging.getLogger().error('[merge_outstanding_requesters] Failed to process uriList group.')

    need_update = (force_update or
        last_update_age > int(environ['MAX_AGE_TO_UPDATE']) or
        len(outstanding_requesters['general']) > 0 or
        len(outstanding_requesters['uriList']) > 0)

    logging.getLogger().debug('[merge_outstanding_requesters] End')
    return outstanding_requesters, need_update

def write_output(bucket_name, key_name, output_key_name, outstanding_requesters):
    logging.getLogger().debug('[write_output] Start')

    try:
        current_data = '/tmp/' + key_name.split('/')[-1] + '_LOCAL.json'
        with open(current_data, 'w') as outfile:
            json.dump(outstanding_requesters, outfile)

        s3 = boto3.client('s3')
        s3.upload_file(current_data, bucket_name, output_key_name, ExtraArgs={'ContentType': "application/json"})

    except Exception as e:
        logging.getLogger().error("[write_output] \tError to write output file")
        logging.getLogger().error(e)

    logging.getLogger().debug('[write_output] End')

def process_log_file(bucket_name, key_name, conf_filename, output_filename, log_type, ip_set_id):
    logging.getLogger().debug('[process_log_file] Start')

    #--------------------------------------------------------------------------------------------------------------
    logging.getLogger().info("[process_log_file] \tReading input data and get outstanding requesters")
    #--------------------------------------------------------------------------------------------------------------
    load_configurations(bucket_name, conf_filename)
    outstanding_requesters = get_outstanding_requesters(bucket_name, key_name, log_type)
    outstanding_requesters, need_update = merge_outstanding_requesters(bucket_name, key_name, log_type, output_filename, outstanding_requesters)

    if need_update:
        #----------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[process_log_file] \tUpdate new blocked requesters list to S3")
        #----------------------------------------------------------------------------------------------------------
        write_output(bucket_name, key_name, output_filename, outstanding_requesters)

        #----------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[process_log_file] \tUpdate WAF IP Set")
        #----------------------------------------------------------------------------------------------------------
        update_waf_ip_set(ip_set_id, outstanding_requesters)

    else:
        #----------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[process_log_file] \tNo changes identified")
        #----------------------------------------------------------------------------------------------------------

    logging.getLogger().debug('[process_log_file] End')

#======================================================================================================================
# Lambda Entry Point
#======================================================================================================================
def lambda_handler(event, context):
    logging.getLogger().debug('[lambda_handler] Start')

    result = {}
    try:
        #------------------------------------------------------------------
        # Set Log Level
        #------------------------------------------------------------------
        global log_level
        log_level = str(environ['LOG_LEVEL'].upper())
        if log_level not in ['DEBUG', 'INFO','WARNING', 'ERROR','CRITICAL']:
            log_level = 'ERROR'
        logging.getLogger().setLevel(log_level)

        #------------------------------------------------------------------
        # Set WAF API Level
        #------------------------------------------------------------------
        global waf
        if environ['LOG_TYPE'] == 'alb':
            session = boto3.session.Session(region_name=environ['REGION'])
            waf = session.client('waf-regional', config=Config(retries={'max_attempts': API_CALL_NUM_RETRIES}))
        else:
            waf = boto3.client('waf', config=Config(retries={'max_attempts': API_CALL_NUM_RETRIES}))

        #----------------------------------------------------------
        # Process event
        #----------------------------------------------------------
        logging.getLogger().info(event)

        if "resourceType" in event:
            process_athena_scheduler_event(event)
            result['message'] = "[lambda_handler] Athena scheduler event processed."
            logging.getLogger().debug(result['message'])

        elif 'Records' in event:
            for r in event['Records']:
                bucket_name = r['s3']['bucket']['name']
                key_name = unquote_plus(r['s3']['object']['key'])

                if 'APP_ACCESS_LOG_BUCKET' in environ and bucket_name == environ['APP_ACCESS_LOG_BUCKET']:
                    if key_name.startswith('athena_results/'):
                        process_athena_result(bucket_name, key_name, environ['IP_SET_ID_SCANNERS_PROBES'])
                        result['message'] = "[lambda_handler] Athena app log query result processed."
                        logging.getLogger().debug(result['message'])

                    else:
                        conf_filename = environ['STACK_NAME'] + '-app_log_conf.json'
                        output_filename = environ['STACK_NAME'] + '-app_log_out.json'
                        log_type = environ['LOG_TYPE']
                        ip_set_id = environ['IP_SET_ID_SCANNERS_PROBES']
                        process_log_file(bucket_name, key_name, conf_filename, output_filename, log_type, ip_set_id)
                        result['message'] = "[lambda_handler] App access log file processed."
                        logging.getLogger().debug(result['message'])

                elif 'WAF_ACCESS_LOG_BUCKET' in environ and bucket_name == environ['WAF_ACCESS_LOG_BUCKET']:
                    if key_name.startswith('athena_results/'):
                        process_athena_result(bucket_name, key_name, environ['IP_SET_ID_HTTP_FLOOD'])
                        result['message'] = "[lambda_handler] Athena AWS WAF log query result processed."
                        logging.getLogger().debug(result['message'])

                    else:
                        conf_filename = environ['STACK_NAME'] + '-waf_log_conf.json'
                        output_filename = environ['STACK_NAME'] + '-waf_log_out.json'
                        log_type = 'waf'
                        ip_set_id = environ['IP_SET_ID_HTTP_FLOOD']
                        process_log_file(bucket_name, key_name, conf_filename, output_filename, log_type, ip_set_id)
                        result['message'] = "[lambda_handler] AWS WAF access log file processed."
                        logging.getLogger().debug(result['message'])

                else:
                    result['message'] = "[lambda_handler] undefined handler for bucket %s"%bucket_name
                    logging.getLogger().info(result['message'])

                send_anonymous_usage_data()

        else:
            result['message'] = "[lambda_handler] undefined handler for this type of event"
            logging.getLogger().info(result['message'])

    except Exception as error:
        logging.getLogger().error(str(error))

    logging.getLogger().debug('[lambda_handler] End')
    return result

