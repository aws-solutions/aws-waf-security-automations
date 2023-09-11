######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
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

import os
from os import environ
from urllib.parse import unquote_plus
from lib.waflibv2 import WAFLIBv2
from lib.solution_metrics import send_metrics
from lib.cw_metrics_util import WAFCloudWatchMetrics
from lib.logging_util import set_log_level
from lambda_log_parser import LambdaLogParser
from athena_log_parser import AthenaLogParser

scope = os.getenv('SCOPE')
scanners = 1
flood = 2
CW_METRIC_PERIOD_SECONDS = 300    # 5 minutes in seconds


def initialize_usage_data():
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
        "waf_type": os.getenv('LOG_TYPE'),
        "provisioner": os.getenv('provisioner') if "provisioner" in environ else "cfn"
    }
    return usage_data


def get_log_parser_usage_data(log, waf_rule, cw, ipv4_set_id, ipv6_set_id,
                              ipset_name_v4, ipset_arn_v4, ipset_name_v6,
                              ipset_arn_v6, usage_data, usage_data_ip_set_field,
                              usage_data_blocked_request_field):
    log.info("[get_log_parser_usage_data] Get %s data", waf_rule)

    if ipv4_set_id in environ or ipv6_set_id in environ:
        # Get the count of ipv4 and ipv6
        waflib = WAFLIBv2()
        ipv4_count = waflib.get_ip_address_count(log, scope, ipset_name_v4, ipset_arn_v4)
        ipv6_count = waflib.get_ip_address_count(log, scope, ipset_name_v6, ipset_arn_v6)
        usage_data[usage_data_ip_set_field] = str(ipv4_count + ipv6_count)

        # Get the count of blocked requests for the bad bot rule from cloudwatch metrics
        usage_data = cw.add_waf_cw_metric_to_usage_data(
            'BlockedRequests',
            CW_METRIC_PERIOD_SECONDS,
            os.getenv('METRIC_NAME_PREFIX') + waf_rule,
            usage_data,
            usage_data_blocked_request_field,
            0
        )
    return usage_data


def send_anonymized_usage_data(log):
    try:
        if 'SEND_ANONYMIZED_USAGE_DATA' not in environ or os.getenv('SEND_ANONYMIZED_USAGE_DATA').lower() != 'yes':
            return

        log.info("[send_anonymized_usage_data] Start")

        cw = WAFCloudWatchMetrics(log)
        usage_data = initialize_usage_data()

        # Get the count of allowed requests for all the waf rules from cloudwatch metrics
        usage_data = cw.add_waf_cw_metric_to_usage_data(
            'AllowedRequests',
            CW_METRIC_PERIOD_SECONDS,
            'ALL',
            usage_data,
            'allowed_requests',
            0
        )

        # Get the count of blocked requests for all the waf rules from cloudwatch metrics
        usage_data = cw.add_waf_cw_metric_to_usage_data(
            'BlockedRequests',
            CW_METRIC_PERIOD_SECONDS,
            'ALL',
            usage_data,
            'blocked_requests_all',
            0
        )

        # Get scanners probes rule specific usage data
        get_log_parser_usage_data(
            log, 'ScannersProbesRule', cw,
            'IP_SET_ID_SCANNERS_PROBESV4', 
            'IP_SET_ID_SCANNERS_PROBESV6',
            os.getenv('IP_SET_NAME_SCANNERS_PROBESV4'), 
            os.getenv('IP_SET_ID_SCANNERS_PROBESV4'),
            os.getenv('IP_SET_NAME_SCANNERS_PROBESV6'),
            os.getenv('IP_SET_ID_SCANNERS_PROBESV6'),
            usage_data, 'scanners_probes_set_size',
            'blocked_requests_scanners_probes'
        )

        # Get HTTP flood rule specific usage data
        get_log_parser_usage_data(
            log, 'HttpFloodRegularRule', cw,
            'IP_SET_ID_HTTP_FLOODV4', 
            'IP_SET_ID_HTTP_FLOODV6',
            os.getenv('IP_SET_NAME_HTTP_FLOODV4'), 
            os.getenv('IP_SET_ID_HTTP_FLOODV4'),
            os.getenv('IP_SET_NAME_HTTP_FLOODV6'),
            os.getenv('IP_SET_ID_HTTP_FLOODV6'),
            usage_data, 'http_flood_set_size',
            'blocked_requests_http_flood'
        )

        # Get the count of allowed requests for the web acl from cloudwatch metrics
        usage_data = cw.add_waf_cw_metric_to_usage_data(
            'AllowedRequests',
            CW_METRIC_PERIOD_SECONDS,
            os.getenv('METRIC_NAME_PREFIX') + 'WAFWebACL',
            usage_data,
            'allowed_requests_WAFWebACL',
            0
        )

        # Get the count of allowed requests for the web acl from cloudwatch metrics
        usage_data = cw.add_waf_cw_metric_to_usage_data(
            'BlockedRequests',
            CW_METRIC_PERIOD_SECONDS,
            os.getenv('METRIC_NAME_PREFIX') + 'WAFWebACL',
            usage_data,
            'blocked_requests_WAFWebACL',
            0
        )

        # Send usage data
        log.info('[send_anonymized_usage_data] Send usage data: \n{}'.format(usage_data))
        response = send_metrics(data=usage_data)
        response_code = response.status_code
        log.info('[send_anonymized_usage_data] Response Code: {}'.format(response_code))
        log.info("[send_anonymized_usage_data] End")

    except Exception as error:
        log.info("[send_anonymized_usage_data] Failed to send data")
        log.error(str(error))


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
def lambda_handler(event, _):
    log = set_log_level()
    log.info('[lambda_handler] Start')

    result = {}
    try:
        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        log.info(event)

        athena_log_parser = AthenaLogParser(log)

        if "resourceType" in event:
            athena_log_parser.process_athena_scheduler_event(event)
            result['message'] = "[lambda_handler] Athena scheduler event processed."
            log.info(result['message'])

        elif 'Records' in event:
            lambda_log_parser = LambdaLogParser(log)
            for record in event['Records']:
                process_record(record, log, result, athena_log_parser, lambda_log_parser)
                send_anonymized_usage_data(log)

        else:
            result['message'] = "[lambda_handler] undefined handler for this type of event"
            log.info(result['message'])

    except Exception as error:
        log.error(str(error))
        raise

    log.info('[lambda_handler] End')
    return result


def process_record(r, log, result, athena_log_parser, lambda_log_parser):
    bucket_name = r['s3']['bucket']['name']
    key_name = unquote_plus(r['s3']['object']['key'])

    if 'APP_ACCESS_LOG_BUCKET' in environ and bucket_name == os.getenv('APP_ACCESS_LOG_BUCKET'):
        if key_name.startswith('athena_results/'):
            athena_log_parser.process_athena_result(bucket_name, key_name, scanners)
            result['message'] = "[lambda_handler] Athena app log query result processed."
            log.info(result['message'])

        else:
            conf_filename = os.getenv('STACK_NAME') + '-app_log_conf.json'
            output_filename = os.getenv('STACK_NAME') + '-app_log_out.json'
            log_type = os.getenv('LOG_TYPE')
            lambda_log_parser.process_log_file(bucket_name, key_name, conf_filename, output_filename, log_type, scanners)
            result['message'] = "[lambda_handler] App access log file processed."
            log.info(result['message'])

    elif 'WAF_ACCESS_LOG_BUCKET' in environ and bucket_name == os.getenv('WAF_ACCESS_LOG_BUCKET'):
        if key_name.startswith('athena_results/'):
            athena_log_parser.process_athena_result(bucket_name, key_name, flood)
            result['message'] = "[lambda_handler] Athena AWS WAF log query result processed."
            log.info(result['message'])

        else:
            conf_filename = os.getenv('STACK_NAME') + '-waf_log_conf.json'
            output_filename = os.getenv('STACK_NAME') + '-waf_log_out.json'
            log_type = 'waf'
            lambda_log_parser.process_log_file(bucket_name, key_name, conf_filename, output_filename, log_type, flood)
            result['message'] = "[lambda_handler] AWS WAF access log file processed."
            log.info(result['message'])

    else:
        result['message'] = "[lambda_handler] undefined handler for bucket %s" % bucket_name
        log.info(result['message'])
