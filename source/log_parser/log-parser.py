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
import csv
import gzip
import json
import logging
import datetime
import os
from os import environ, remove
from urllib.parse import unquote_plus
from urllib.parse import urlparse
import requests

from lib.waflibv2 import WAFLIBv2
from lib.solution_metrics import send_metrics
from build_athena_queries import build_athena_query_for_app_access_logs, \
    build_athena_query_for_waf_logs

logging.getLogger().debug('Loading function')

api_call_num_retries = 5
max_descriptors_per_ip_set_update = 500
delay_between_updates = 2
scope = os.getenv('SCOPE')
scanners = 1
flood = 2

# CloudFront Access Logs
# http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html#BasicDistributionFileFormat
LINE_FORMAT_CLOUD_FRONT = {
    'delimiter': '\t',
    'date': 0,
    'time': 1,
    'source_ip': 4,
    'uri': 7,
    'code': 8
}
# ALB Access Logs
# http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
LINE_FORMAT_ALB = {
    'delimiter': ' ',
    'timestamp': 1,
    'source_ip': 3,
    'code': 9,  # GitHub issue #44. Changed from elb_status_code to target_status_code.
    'uri': 13
}

waflib = WAFLIBv2()
config = {}


# ======================================================================================================================
# Auxiliary Functions
# ======================================================================================================================
def update_ip_set(log, ip_set_type, outstanding_requesters):
    log.info('[update_ip_set] Start')

    # With wafv2 api we need to pass the scope, name and arn of an IPSet to manipulate the Address list
    # We also can only put source_ips in the appropriate IPSets based on IP version
    # Depending on the ip_set_type, we choose the appropriate set of IPSets and Names

    # initialize as SCANNER_PROBES IPSets
    ipset_name_v4 = None
    ipset_name_v6 = None
    ipset_arn_v4 = None
    ipset_arn_v6 = None

    # switch if type of IPSets are HTTP_FLOOD
    if ip_set_type == flood:
        ipset_name_v4 = os.getenv('IP_SET_NAME_HTTP_FLOODV4')
        ipset_name_v6 = os.getenv('IP_SET_NAME_HTTP_FLOODV6')
        ipset_arn_v4 = os.getenv('IP_SET_ID_HTTP_FLOODV4')
        ipset_arn_v6 = os.getenv('IP_SET_ID_HTTP_FLOODV6')

    if ip_set_type == scanners:
        ipset_name_v4 = os.getenv('IP_SET_NAME_SCANNERS_PROBESV4')
        ipset_name_v6 = os.getenv('IP_SET_NAME_SCANNERS_PROBESV6')
        ipset_arn_v4 = os.getenv('IP_SET_ID_SCANNERS_PROBESV4')
        ipset_arn_v6 = os.getenv('IP_SET_ID_SCANNERS_PROBESV6')

    counter = 0
    try:
        if ipset_arn_v4 == None or ipset_arn_v6 == None:
            log.info("[update_ip_set] Ignore process when ip_set_id is None")
            return

        # --------------------------------------------------------------------------------------------------------------
        log.info("[update_ip_set] \tMerge general and uriList into a single list")
        # --------------------------------------------------------------------------------------------------------------
        unified_outstanding_requesters = outstanding_requesters['general']
        for uri in outstanding_requesters['uriList'].keys():
            for k in outstanding_requesters['uriList'][uri].keys():
                if (k not in unified_outstanding_requesters.keys() or
                        outstanding_requesters['uriList'][uri][k]['max_counter_per_min'] >
                        unified_outstanding_requesters[k]['max_counter_per_min']):
                    unified_outstanding_requesters[k] = outstanding_requesters['uriList'][uri][k]

        # --------------------------------------------------------------------------------------------------------------
        log.info("[update_ip_set] \tTruncate [if necessary] list to respect WAF limit")
        # --------------------------------------------------------------------------------------------------------------
        if len(unified_outstanding_requesters) > int(os.getenv('LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION')):
            ordered_unified_outstanding_requesters = sorted(unified_outstanding_requesters.items(),
                                                            key=lambda kv: kv[1]['max_counter_per_min'], reverse=True)
            unified_outstanding_requesters = {}
            for key, value in ordered_unified_outstanding_requesters:
                if counter < int(os.getenv('LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION')):
                    unified_outstanding_requesters[key] = value
                    counter += 1
                else:
                    break

        # --------------------------------------------------------------------------------------------------------------
        log.info("[update_ip_set] \tBlock remaining outstanding requesters")
        # --------------------------------------------------------------------------------------------------------------
        addresses_v4 = []
        addresses_v6 = []

        for k in unified_outstanding_requesters.keys():
            ip_type = waflib.which_ip_version(log, k)
            source_ip = waflib.set_ip_cidr(log, k)

            if ip_type == "IPV4":
                addresses_v4.append(source_ip)
            elif ip_type == "IPV6":
                addresses_v6.append(source_ip)

        # --------------------------------------------------------------------------------------------------------------
        log.info("[update_ip_set] \tCommit changes in WAF IP set")
        # --------------------------------------------------------------------------------------------------------------
        response = waflib.update_ip_set(log, scope, ipset_name_v4, ipset_arn_v4, addresses_v4)
        response = waflib.update_ip_set(log, scope, ipset_name_v6, ipset_arn_v6, addresses_v6)

    except Exception as error:
        log.error(str(error))
        log.error("[update_ip_set] Error to update waf ip set")

    log.info('[update_ip_set] End')
    return counter


def send_anonymous_usage_data(log):
    try:
        if 'SEND_ANONYMOUS_USAGE_DATA' not in environ or os.getenv('SEND_ANONYMOUS_USAGE_DATA').lower() != 'yes':
            return

        log.info("[send_anonymous_usage_data] Start")

        cw = boto3.client('cloudwatch')
        usage_data = {
                    "data_type": "log_parser",
                    "scanners_probes_set_size": 0,
                    "http_flood_set_size": 0,
                    "allowed_requests": 0,
                    "blocked_requests_all": 0,
                    "blocked_requests_scanners_probes": 0,
                    "blocked_requests_http_flood": 0,
                    "allowed_requests_WAFWebACL": 0,
                    "blocked_requests_WAFWebACL": 0,
                    "waf_type": os.getenv('LOG_TYPE')
                }

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Get num allowed requests")
        # --------------------------------------------------------------------------------------------------------------
        try:
            response = cw.get_metric_statistics(
                MetricName='AllowedRequests',
                Namespace='AWS/WAFV2',
                Statistics=['Sum'],
                Period=300,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=300),
                EndTime=datetime.datetime.utcnow(),
                Dimensions=[
                    {
                        "Name": "Rule",
                        "Value": "ALL"
                    },
                    {
                        "Name": "WebACL",
                        "Value": os.getenv('STACK_NAME')
                    },
                    {
                        "Name": "Region",
                        "Value": os.getenv('AWS_REGION')
                    }
                ]
            )
            if len(response['Datapoints']):
                usage_data['allowed_requests'] = response['Datapoints'][0]['Sum']

        except Exception as error:
            log.debug("[send_anonymous_usage_data] Failed to get Num Allowed Requests")
            log.debug(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Get num blocked requests - all rules")
        # --------------------------------------------------------------------------------------------------------------
        try:
            response = cw.get_metric_statistics(
                MetricName='BlockedRequests',
                Namespace='AWS/WAFV2',
                Statistics=['Sum'],
                Period=300,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=300),
                EndTime=datetime.datetime.utcnow(),
                Dimensions=[
                    {
                        "Name": "Rule",
                        "Value": "ALL"
                    },
                    {
                        "Name": "WebACL",
                        "Value": os.getenv('STACK_NAME')
                    },
                    {
                        "Name": "Region",
                        "Value": os.getenv('AWS_REGION')
                    }
                ]
            )

            if len(response['Datapoints']):
                usage_data['blocked_requests_all'] = response['Datapoints'][0]['Sum']

        except Exception as error:
            log.info("[send_anonymous_usage_data] Failed to get num blocked requests - all rules")
            log.error(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Get scanners probes data")
        # --------------------------------------------------------------------------------------------------------------
        if 'IP_SET_ID_SCANNERS_PROBESV4' in environ or 'IP_SET_ID_SCANNERS_PROBESV6' in environ:
            try:
                countv4 = 0
                response = waflib.get_ip_set(log, scope,
                    os.getenv('IP_SET_NAME_SCANNERS_PROBESV4'),
                    os.getenv('IP_SET_ID_SCANNERS_PROBESV4')
                    )
                log.info(response)
                if response is not None:
                    countv4 = len(response['IPSet']['Addresses'])
                    log.info("Scanner Probes IPV4 address Count: %s", countv4)

                countv6 = 0
                response = waflib.get_ip_set(log, scope,
                    os.getenv('IP_SET_NAME_SCANNERS_PROBESV6'),
                    os.getenv('IP_SET_ID_SCANNERS_PROBESV6')
                    )
                log.info(response)
                if response is not None:
                    countv6 = len(response['IPSet']['Addresses'])
                    log.info("Scanner Probes IPV6 address Count: %s", countv6)

                usage_data['scanners_probes_set_size'] = str(countv4 + countv6)

                response = cw.get_metric_statistics(
                    MetricName='BlockedRequests',
                    Namespace='AWS/WAFV2',
                    Statistics=['Sum'],
                    Period=300,
                    StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=300),
                    EndTime=datetime.datetime.utcnow(),
                    Dimensions=[
                        {
                            "Name": "Rule",
                            "Value": os.getenv('METRIC_NAME_PREFIX') + 'ScannersProbesRule'
                        },
                        {
                            "Name": "WebACL",
                            "Value": os.getenv('STACK_NAME')
                        },
                        {
                            "Name": "Region",
                            "Value": os.getenv('AWS_REGION')
                        }
                    ]
                )

                if len(response['Datapoints']):
                    usage_data['blocked_requests_scanners_probes'] = response['Datapoints'][0]['Sum']

            except Exception as error:
                log.debug("[send_anonymous_usage_data] Failed to get scanners probes data")
                log.debug(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Get HTTP flood data")
        # --------------------------------------------------------------------------------------------------------------
        if 'IP_SET_ID_HTTP_FLOODV4' in environ or 'IP_SET_ID_HTTP_FLOODV6' in environ:
            try:
                countv4 = 0
                response = waflib.get_ip_set(log, scope,
                    os.getenv('IP_SET_NAME_HTTP_FLOODV4'),
                    os.getenv('IP_SET_ID_HTTP_FLOODV4')
                    )
                log.info(response)
                if response is not None:
                    countv4 = len(response['IPSet']['Addresses'])
                    log.info("HTTP Flood IPV4 address Count: %s", countv4)

                countv6 = 0
                response = waflib.get_ip_set(log, scope,
                    os.getenv('IP_SET_NAME_HTTP_FLOODV6'),
                    os.getenv('IP_SET_ID_HTTP_FLOODV6')
                    )
                log.info(response)
                if response is not None:
                    countv6 = len(response['IPSet']['Addresses'])
                    log.info("HTTP Flood IPV6 address Count: %s", countv6)

                usage_data['http_flood_set_size'] = str(countv4 + countv6)

                response = cw.get_metric_statistics(
                    MetricName='BlockedRequests',
                    Namespace='AWS/WAFV2',
                    Statistics=['Sum'],
                    Period=300,
                    StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=300),
                    EndTime=datetime.datetime.utcnow(),
                    Dimensions=[
                        {
                            "Name": "Rule",
                            "Value": os.getenv('METRIC_NAME_PREFIX') + 'HttpFloodRegularRule'
                        },
                        {
                            "Name": "WebACL",
                            "Value": os.getenv('STACK_NAME')
                        },
                        {
                            "Name": "Region",
                            "Value": os.getenv('AWS_REGION')
                        }
                    ]
                )

                if len(response['Datapoints']):
                    usage_data['blocked_requests_http_flood'] = response['Datapoints'][0]['Sum']

            except Exception as error:
                log.info("[send_anonymous_usage_data] Failed to get HTTP flood data")
                log.error(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Get num allowed requests - WAF Web ACL")
        # --------------------------------------------------------------------------------------------------------------
        try:
            response = cw.get_metric_statistics(
                MetricName='AllowedRequests',
                Namespace='AWS/WAFV2',
                Statistics=['Sum'],
                Period=300,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=300),
                EndTime=datetime.datetime.utcnow(),
                Dimensions=[
                    {
                        "Name": "Rule",
                        "Value": os.getenv('METRIC_NAME_PREFIX') + 'WAFWebACL'
                    },
                    {
                        "Name": "WebACL",
                        "Value": os.getenv('STACK_NAME')
                    },
                    {
                        "Name": "Region",
                        "Value": os.getenv('AWS_REGION')
                    }
                ]
            )

            if len(response['Datapoints']):
                usage_data['allowed_requests_WAFWebACL'] = response['Datapoints'][0]['Sum']

        except Exception as error:
            log.info("[send_anonymous_usage_data] Failed to get num blocked requests - all rules")
            log.error(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Get num blocked requests - WAF Web ACL")
        # --------------------------------------------------------------------------------------------------------------
        try:
            response = cw.get_metric_statistics(
                MetricName='BlockedRequests',
                Namespace='AWS/WAFV2',
                Statistics=['Sum'],
                Period=300,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=300),
                EndTime=datetime.datetime.utcnow(),
                Dimensions=[
                    {
                        "Name": "Rule",
                        "Value": os.getenv('METRIC_NAME_PREFIX') + 'WAFWebACL'
                    },
                    {
                        "Name": "WebACL",
                        "Value": os.getenv('STACK_NAME')
                    },
                    {
                        "Name": "Region",
                        "Value": os.getenv('AWS_REGION')
                    }
                ]
            )

            if len(response['Datapoints']):
                usage_data['blocked_requests_WAFWebACL'] = response['Datapoints'][0]['Sum']

        except Exception as error:
            log.info("[send_anonymous_usage_data] Failed to get num blocked requests - all rules")
            log.error(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Send Data")
        # --------------------------------------------------------------------------------------------------------------
        response = send_metrics(data=usage_data)
        response_code = response.status_code
        log.info('[send_anonymous_usage_data] Response Code: {}'.format(response_code))
        log.info("[send_anonymous_usage_data] End")

    except Exception as error:
        log.info("[send_anonymous_usage_data] Failed to send data")
        log.error(str(error))


# ======================================================================================================================
# Athena Log Parser
# ======================================================================================================================
def process_athena_scheduler_event(log, event):
    log.debug('[process_athena_scheduler_event] Start')

    log_type = str(environ['LOG_TYPE'].upper())

    # Execute athena query for CloudFront or ALB logs
    if event['resourceType'] == 'LambdaAthenaAppLogParser' \
            and (log_type == 'CLOUDFRONT' or log_type == 'ALB'):
        execute_athena_query(log, log_type, event)

    # Execute athena query for WAF logs
    if event['resourceType'] == 'LambdaAthenaWAFLogParser':
        execute_athena_query(log, 'WAF', event)

    log.debug('[process_athena_scheduler_event] End')


def execute_athena_query(log, log_type, event):
    log.debug('[execute_athena_query] Start')

    athena_client = boto3.client('athena')
    s3_output = "s3://%s/athena_results/" % event['accessLogBucket']
    database_name = event['glueAccessLogsDatabase']

    # Dynamically build query string using partition
    # for CloudFront or ALB logs
    if log_type == 'CLOUDFRONT' or log_type == 'ALB':
        query_string = build_athena_query_for_app_access_logs(
            log,
            log_type,
            event['glueAccessLogsDatabase'],
            event['glueAppAccessLogsTable'],
            datetime.datetime.utcnow(),
            int(environ['WAF_BLOCK_PERIOD']),
            int(environ['ERROR_THRESHOLD'])
        )
    else:  # Dynamically build query string using partition for WAF logs
        query_string = build_athena_query_for_waf_logs(
            log,
            event['glueAccessLogsDatabase'],
            event['glueWafAccessLogsTable'],
            datetime.datetime.utcnow(),
            int(environ['WAF_BLOCK_PERIOD']),
            int(environ['REQUEST_THRESHOLD'])
        )

    response = athena_client.start_query_execution(
        QueryString=query_string,
        QueryExecutionContext={'Database': database_name},
        ResultConfiguration={
            'OutputLocation': s3_output,
            'EncryptionConfiguration': {
                'EncryptionOption': 'SSE_S3'
            }
        },
        WorkGroup=event['athenaWorkGroup']
    )

    log.info("[execute_athena_query] Query Execution Response: {}".format(response))
    log.info('[execute_athena_query] End')


def process_athena_result(log, bucket_name, key_name, ip_set_type):
    log.debug('[process_athena_result] Start')

    try:
        # --------------------------------------------------------------------------------------------------------------
        log.info("[process_athena_result] \tDownload file from S3")
        # --------------------------------------------------------------------------------------------------------------
        local_file_path = '/tmp/' + key_name.split('/')[-1]
        s3 = boto3.client('s3')
        s3.download_file(bucket_name, key_name, local_file_path)

        # --------------------------------------------------------------------------------------------------------------
        log.info("[process_athena_result] \tRead file content")
        # --------------------------------------------------------------------------------------------------------------
        outstanding_requesters = {
            'general': {},
            'uriList': {}
        }
        utc_now_timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z%z")
        with open(local_file_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # max_counter_per_min is set as 1 just to reuse lambda log parser data structure
                # and reuse update_ip_set.
                outstanding_requesters['general'][row['client_ip']] = {
                    "max_counter_per_min": row['max_counter_per_min'],
                    "updated_at": utc_now_timestamp_str
                }
        remove(local_file_path)

        # --------------------------------------------------------------------------------------------------------------
        log.info("[process_athena_result] \tUpdate WAF IP Sets")
        # --------------------------------------------------------------------------------------------------------------
        update_ip_set(log,ip_set_type, outstanding_requesters)

    except Exception:
        log.error("[process_athena_result] \tError to read input file")

    log.debug('[process_athena_result] End')


# ======================================================================================================================
# Lambda Log Parser
# ======================================================================================================================
def load_configurations(log, bucket_name, key_name):
    log.debug('[load_configurations] Start')

    try:
        s3 = boto3.resource('s3')
        file_obj = s3.Object(bucket_name, key_name)
        file_content = file_obj.get()['Body'].read()

        global config
        config = json.loads(file_content)

    except Exception as e:
        log.error("[load_configurations] \tError to read config file")
        raise e

    log.debug('[load_configurations] End')


def get_outstanding_requesters(log, bucket_name, key_name, log_type):
    log.debug('[get_outstanding_requesters] Start')

    counter = {
        'general': {},
        'uriList': {}
    }
    outstanding_requesters = {
        'general': {},
        'uriList': {}
    }

    try:
        # --------------------------------------------------------------------------------------------------------------
        log.info("[get_outstanding_requesters] \tDownload file from S3")
        # --------------------------------------------------------------------------------------------------------------
        local_file_path = '/tmp/' + key_name.split('/')[-1]
        s3 = boto3.client('s3')
        s3.download_file(bucket_name, key_name, local_file_path)

        # --------------------------------------------------------------------------------------------------------------
        log.info("[get_outstanding_requesters] \tRead file content")
        # --------------------------------------------------------------------------------------------------------------
        with gzip.open(local_file_path, 'r') as content:
            for line in content:
                try:
                    request_key = ""
                    uri = ""
                    return_code_index = None

                    if log_type == 'waf':
                        line = line.decode()  # Remove the b in front of each field
                        line_data = json.loads(str(line))

                        request_key = datetime.datetime.fromtimestamp(int(line_data['timestamp']) / 1000.0).isoformat(
                            sep='T', timespec='minutes')
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

                    if 'ignoredSufixes' in config['general'] and uri.endswith(
                            tuple(config['general']['ignoredSufixes'])):
                        log.debug(
                            "[get_outstanding_requesters] \t\tSkipping line %s. Included in ignoredSufixes." % line)
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
                    log.error("[get_outstanding_requesters] \t\tError to process line: %s" % line)
        remove(local_file_path)

        # --------------------------------------------------------------------------------------------------------------
        log.info("[get_outstanding_requesters] \tKeep only outstanding requesters")
        # --------------------------------------------------------------------------------------------------------------
        threshold = 'requestThreshold' if log_type == 'waf' else "errorThreshold"
        utc_now_timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z%z")
        for k, num_reqs in counter['general'].items():
            try:
                k = k.split(' ')[-1]
                if num_reqs >= config['general'][threshold]:
                    if k not in outstanding_requesters['general'].keys() or num_reqs > \
                            outstanding_requesters['general'][k]['max_counter_per_min']:
                        outstanding_requesters['general'][k] = {
                            'max_counter_per_min': num_reqs,
                            'updated_at': utc_now_timestamp_str
                        }
            except Exception as e:
                log.error(
                    "[get_outstanding_requesters] \t\tError to process outstanding requester: %s" % k)

        for uri in counter['uriList'].keys():
            for k, num_reqs in counter['uriList'][uri].items():
                try:
                    k = k.split(' ')[-1]
                    if num_reqs >= config['uriList'][uri][threshold]:
                        if uri not in outstanding_requesters['uriList'].keys():
                            outstanding_requesters['uriList'][uri] = {}

                        if k not in outstanding_requesters['uriList'][uri].keys() or num_reqs > \
                                outstanding_requesters['uriList'][uri][k]['max_counter_per_min']:
                            outstanding_requesters['uriList'][uri][k] = {
                                'max_counter_per_min': num_reqs,
                                'updated_at': utc_now_timestamp_str
                            }
                except Exception as e:
                    log.error(
                        "[get_outstanding_requesters] \t\tError to process outstanding requester: (%s) %s" % (uri, k))

    except Exception as e:
        log.error("[get_outstanding_requesters] \tError to read input file")
        log.error(e)

    log.debug('[get_outstanding_requesters] End')
    return outstanding_requesters


def merge_outstanding_requesters(log, bucket_name, key_name, log_type, output_key_name, outstanding_requesters):
    log.debug('[merge_outstanding_requesters] Start')

    force_update = False
    need_update = False
    s3 = boto3.client('s3')

    # --------------------------------------------------------------------------------------------------------------
    log.info("[merge_outstanding_requesters] \tCalculate Last Update Age")
    # --------------------------------------------------------------------------------------------------------------
    response = None
    try:
        response = s3.head_object(Bucket=bucket_name, Key=output_key_name)
    except Exception:
        log.info('[merge_outstanding_requesters] No file to be merged.')
        need_update = True
        return outstanding_requesters, need_update

    utc_last_modified = response['LastModified'].astimezone(datetime.timezone.utc)
    utc_now_timestamp = datetime.datetime.now(datetime.timezone.utc)

    utc_now_timestamp_str = utc_now_timestamp.strftime("%Y-%m-%d %H:%M:%S %Z%z")
    last_update_age = int(((utc_now_timestamp - utc_last_modified).total_seconds()) / 60)

    # --------------------------------------------------------------------------------------------------------------
    log.info("[merge_outstanding_requesters] \tDownload current blocked IPs")
    # --------------------------------------------------------------------------------------------------------------
    local_file_path = '/tmp/' + key_name.split('/')[-1] + '_REMOTE.json'
    s3.download_file(bucket_name, output_key_name, local_file_path)

    # ----------------------------------------------------------------------------------------------------------
    log.info("[merge_outstanding_requesters] \tProcess outstanding requesters files")
    # ----------------------------------------------------------------------------------------------------------
    remote_outstanding_requesters = {
        'general': {},
        'uriList': {}
    }
    with open(local_file_path, 'r') as file_content:
        remote_outstanding_requesters = json.loads(file_content.read())
    remove(local_file_path)

    threshold = 'requestThreshold' if log_type == 'waf' else "errorThreshold"
    try:
        if 'general' in remote_outstanding_requesters:
            for k, v in remote_outstanding_requesters['general'].items():
                try:
                    if k in outstanding_requesters['general'].keys():
                        log.info(
                            "[merge_outstanding_requesters] \t\tUpdating general data of BLOCK %s rule" % k)
                        outstanding_requesters['general'][k]['updated_at'] = utc_now_timestamp_str
                        if v['max_counter_per_min'] > outstanding_requesters['general'][k]['max_counter_per_min']:
                            outstanding_requesters['general'][k]['max_counter_per_min'] = v['max_counter_per_min']

                    else:
                        utc_prev_updated_at = datetime.datetime.strptime(v['updated_at'],
                                                                         "%Y-%m-%d %H:%M:%S %Z%z").astimezone(
                            datetime.timezone.utc)
                        total_diff_min = ((utc_now_timestamp - utc_prev_updated_at).total_seconds()) / 60

                        if v['max_counter_per_min'] < config['general'][threshold]:
                            force_update = True
                            log.info(
                                "[merge_outstanding_requesters] \t\t%s is bellow the current general threshold" % k)

                        elif total_diff_min < config['general']['blockPeriod']:
                            log.debug("[merge_outstanding_requesters] \t\tKeeping %s in general" % k)
                            outstanding_requesters['general'][k] = v

                        else:
                            force_update = True
                            log.info("[merge_outstanding_requesters] \t\t%s expired in general" % k)

                except Exception:
                    log.error("[merge_outstanding_requesters] \tError merging general %s rule" % k)
    except Exception:
        log.error('[merge_outstanding_requesters] Failed to process general group.')

    try:
        if 'uriList' in remote_outstanding_requesters:
            if 'uriList' not in config or len(config['uriList']) == 0:
                force_update = True
                log.info(
                    "[merge_outstanding_requesters] \t\tCurrent config file does not contain uriList anymore")
            else:
                for uri in remote_outstanding_requesters['uriList'].keys():
                    if 'ignoredSufixes' in config['general'] and uri.endswith(
                            tuple(config['general']['ignoredSufixes'])):
                        force_update = True
                        log.info(
                            "[merge_outstanding_requesters] \t\t%s is in current ignored sufixes list." % uri)
                        continue

                    for k, v in remote_outstanding_requesters['uriList'][uri].items():
                        try:
                            if uri in outstanding_requesters['uriList'].keys() and k in \
                                    outstanding_requesters['uriList'][uri].keys():
                                log.info(
                                    "[merge_outstanding_requesters] \t\tUpdating uriList (%s) data of BLOCK %s rule" % (
                                    uri, k))
                                outstanding_requesters['uriList'][uri][k]['updated_at'] = utc_now_timestamp_str
                                if v['max_counter_per_min'] > outstanding_requesters['uriList'][uri][k][
                                    'max_counter_per_min']:
                                    outstanding_requesters['uriList'][uri][k]['max_counter_per_min'] = v[
                                        'max_counter_per_min']

                            else:
                                utc_prev_updated_at = datetime.datetime.strptime(v['updated_at'],
                                                                                 "%Y-%m-%d %H:%M:%S %Z%z").astimezone(
                                    datetime.timezone.utc)
                                total_diff_min = ((utc_now_timestamp - utc_prev_updated_at).total_seconds()) / 60

                                if v['max_counter_per_min'] < config['uriList'][uri][threshold]:
                                    force_update = True
                                    log.info(
                                        "[merge_outstanding_requesters] \t\t%s is bellow the current uriList (%s) threshold" % (
                                        k, uri))

                                elif total_diff_min < config['general']['blockPeriod']:
                                    log.debug(
                                        "[merge_outstanding_requesters] \t\tKeeping %s in uriList (%s)" % (k, uri))

                                    if uri not in outstanding_requesters['uriList'].keys():
                                        outstanding_requesters['uriList'][uri] = {}

                                    outstanding_requesters['uriList'][uri][k] = v
                                else:
                                    force_update = True
                                    log.info(
                                        "[merge_outstanding_requesters] \t\t%s expired in uriList (%s)" % (k, uri))

                        except Exception:
                            log.error(
                                "[merge_outstanding_requesters] \tError merging uriList (%s) %s rule" % (uri, k))
    except Exception:
        log.error('[merge_outstanding_requesters] Failed to process uriList group.')

    need_update = (force_update or
                   last_update_age > int(os.getenv('MAX_AGE_TO_UPDATE')) or
                   len(outstanding_requesters['general']) > 0 or
                   len(outstanding_requesters['uriList']) > 0)

    log.debug('[merge_outstanding_requesters] End')
    return outstanding_requesters, need_update


def write_output(log, bucket_name, key_name, output_key_name, outstanding_requesters):
    log.debug('[write_output] Start')

    try:
        current_data = '/tmp/' + key_name.split('/')[-1] + '_LOCAL.json'
        with open(current_data, 'w') as outfile:
            json.dump(outstanding_requesters, outfile)

        s3 = boto3.client('s3')
        s3.upload_file(current_data, bucket_name, output_key_name, ExtraArgs={'ContentType': "application/json"})
        remove(current_data)

    except Exception as e:
        log.error("[write_output] \tError to write output file")
        log.error(e)

    log.debug('[write_output] End')


def process_log_file(log, bucket_name, key_name, conf_filename, output_filename, log_type, ip_set_type):
    log.debug('[process_log_file] Start')

    # --------------------------------------------------------------------------------------------------------------
    log.info("[process_log_file] \tReading input data and get outstanding requesters")
    # --------------------------------------------------------------------------------------------------------------
    load_configurations(log, bucket_name, conf_filename)
    outstanding_requesters = get_outstanding_requesters(log, bucket_name, key_name, log_type)
    outstanding_requesters, need_update = merge_outstanding_requesters(log, bucket_name, key_name, log_type, output_filename,
                                                                       outstanding_requesters)

    if need_update:
        # ----------------------------------------------------------------------------------------------------------
        log.info("[process_log_file] \tUpdate new blocked requesters list to S3")
        # ----------------------------------------------------------------------------------------------------------
        write_output(log, bucket_name, key_name, output_filename, outstanding_requesters)

        # ----------------------------------------------------------------------------------------------------------
        log.info("[process_log_file] \tUpdate WAF IP Set")
        # ----------------------------------------------------------------------------------------------------------
        update_ip_set(log, ip_set_type, outstanding_requesters)

    else:
        # ----------------------------------------------------------------------------------------------------------
        log.info("[process_log_file] \tNo changes identified")
        # ----------------------------------------------------------------------------------------------------------

    log.debug('[process_log_file] End')


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
def lambda_handler(event, context):
    log = logging.getLogger()
    log.info('[lambda_handler] Start')

    result = {}
    try:
        # ------------------------------------------------------------------
        # Set Log Level
        # ------------------------------------------------------------------
        log_level = str(os.getenv('LOG_LEVEL').upper())
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            log_level = 'ERROR'
        log.setLevel(log_level)

        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        log.info(event)

        if "resourceType" in event:
            process_athena_scheduler_event(log, event)
            result['message'] = "[lambda_handler] Athena scheduler event processed."
            log.info(result['message'])

        elif 'Records' in event:
            for r in event['Records']:
                bucket_name = r['s3']['bucket']['name']
                key_name = unquote_plus(r['s3']['object']['key'])

                if 'APP_ACCESS_LOG_BUCKET' in environ and bucket_name == os.getenv('APP_ACCESS_LOG_BUCKET'):
                    if key_name.startswith('athena_results/'):
                        process_athena_result(log, bucket_name, key_name, scanners)
                        result['message'] = "[lambda_handler] Athena app log query result processed."
                        log.info(result['message'])

                    else:
                        conf_filename = os.getenv('STACK_NAME') + '-app_log_conf.json'
                        output_filename = os.getenv('STACK_NAME') + '-app_log_out.json'
                        log_type = os.getenv('LOG_TYPE')
                        process_log_file(log, bucket_name, key_name, conf_filename, output_filename, log_type, scanners)
                        result['message'] = "[lambda_handler] App access log file processed."
                        log.info(result['message'])

                elif 'WAF_ACCESS_LOG_BUCKET' in environ and bucket_name == os.getenv('WAF_ACCESS_LOG_BUCKET'):
                    if key_name.startswith('athena_results/'):
                        process_athena_result(log, bucket_name, key_name, flood)
                        result['message'] = "[lambda_handler] Athena AWS WAF log query result processed."
                        log.info(result['message'])

                    else:
                        conf_filename = os.getenv('STACK_NAME') + '-waf_log_conf.json'
                        output_filename = os.getenv('STACK_NAME') + '-waf_log_out.json'
                        log_type = 'waf'
                        process_log_file(log, bucket_name, key_name, conf_filename, output_filename, log_type, flood)
                        result['message'] = "[lambda_handler] AWS WAF access log file processed."
                        log.info(result['message'])

                else:
                    result['message'] = "[lambda_handler] undefined handler for bucket %s" % bucket_name
                    log.info(result['message'])

                send_anonymous_usage_data(log)

        else:
            result['message'] = "[lambda_handler] undefined handler for this type of event"
            log.info(result['message'])

    except Exception as error:
        log.error(str(error))

    log.info('[lambda_handler] End')
    return result
