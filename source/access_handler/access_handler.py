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
from ipaddress import ip_address
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from os import environ
from lib.waflibv2 import WAFLIBv2
from lib.solution_metrics import send_metrics
from lib.cw_metrics_util import WAFCloudWatchMetrics
from lib.logging_util import set_log_level

waflib = WAFLIBv2()
CW_METRIC_PERIOD_SECONDS = 12 * 3600    # Twelve hours in seconds

def initialize_usage_data():
    usage_data = {
        "data_type": "bad_bot",
        "bad_bot_ip_set_size": 0,
        "allowed_requests": 0,
        "blocked_requests_all": 0,
        "blocked_requests_bad_bot": 0,
        "waf_type": os.getenv('LOG_TYPE'),
        "provisioner": os.getenv('provisioner') if "provisioner" in environ else "cfn"

    }
    return usage_data


def get_bad_bot_usage_data(log, scope, cw, ipset_name_v4, ipset_arn_v4, ipset_name_v6, ipset_arn_v6, usage_data):
    log.info("[get_bad_bot_usage_data] Get bad bot data")

    if 'IP_SET_ID_BAD_BOTV4' in environ or 'IP_SET_ID_BAD_BOTV6' in environ:
        # Get the count of ipv4 and ipv6 in bad bot ip sets
        ipv4_count = waflib.get_ip_address_count(log, scope, ipset_name_v4, ipset_arn_v4)
        ipv6_count = waflib.get_ip_address_count(log, scope, ipset_name_v6, ipset_arn_v6)
        usage_data['bad_bot_ip_set_size'] = str(ipv4_count + ipv6_count)

        # Get the count of blocked requests for the bad bot rule from cloudwatch metrics
        usage_data = cw.add_waf_cw_metric_to_usage_data(
            'BlockedRequests',
            CW_METRIC_PERIOD_SECONDS,
            os.getenv('METRIC_NAME_PREFIX') + 'BadBotRule',
            usage_data,
            'blocked_requests_bad_bot',
            0
        )
    return usage_data


def send_anonymous_usage_data(log, scope, ipset_name_v4, ipset_arn_v4, ipset_name_v6, ipset_arn_v6):
    try:
        if 'SEND_ANONYMOUS_USAGE_DATA' not in environ or os.getenv('SEND_ANONYMOUS_USAGE_DATA').lower() != 'yes':
            return

        log.info("[send_anonymous_usage_data] Start")

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

        # Get bad bot specific usage data
        usage_data = get_bad_bot_usage_data(log, scope, cw, ipset_name_v4, ipset_arn_v4,
            ipset_name_v6, ipset_arn_v6, usage_data)

        # Send usage data
        log.info('[send_anonymous_usage_data] Send usage data: \n{}'.format(usage_data))
        response = send_metrics(data=usage_data)
        response_code = response.status_code
        log.info('[send_anonymous_usage_data] Response Code: {}'.format(response_code))
        log.info("[send_anonymous_usage_data] End")

    except Exception as error:
        log.info("[send_anonymous_usage_data] Failed to Send Data")
        log.error(str(error))


def add_ip_to_ip_set(log, scope, ip_type, source_ip, ipset_name, ipset_arn):
    new_address = []
    output = None
    
    if ip_type == "IPV4":
        new_address.append(IPv4Network(source_ip).with_prefixlen)
    elif ip_type == "IPV6":
        new_address.append(IPv6Network(source_ip).with_prefixlen)
    
    ipset = waflib.get_ip_set(log, scope, ipset_name, ipset_arn)
    # merge old addresses with this one
    log.info(ipset)
    current_list = ipset["IPSet"]["Addresses"]
    log.info(current_list)
    new_list = list(set(current_list) | set(new_address))
    log.info(new_list)
    output = waflib.update_ip_set(log, scope, ipset_name, ipset_arn, new_list)

    return output


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
def lambda_handler(event, _):
    log = set_log_level()
    log.info('[lambda_handler] Start')

    # ----------------------------------------------------------
    # Read inputs parameters
    # ----------------------------------------------------------
    try:
        scope = os.getenv('SCOPE')
        ipset_name_v4 = os.getenv('IP_SET_NAME_BAD_BOTV4')
        ipset_name_v6 = os.getenv('IP_SET_NAME_BAD_BOTV6')
        ipset_arn_v4 = os.getenv('IP_SET_ID_BAD_BOTV4')
        ipset_arn_v6 = os.getenv('IP_SET_ID_BAD_BOTV6')

        # Fixed as old line had security exposure based on user supplied IP address
        log.info("Event->%s<-", str(event))
        if event['requestContext']['identity']['userAgent'] == 'Amazon CloudFront':
            source_ip = str(event['headers']['X-Forwarded-For'].split(',')[0].strip())
        else:
            source_ip = str(event['requestContext']['identity']['sourceIp'])

        log.info("scope = %s", scope)
        log.info("ipset_name_v4 = %s", ipset_name_v4)
        log.info("ipset_name_v6 = %s", ipset_name_v6)
        log.info("IPARNV4 = %s", ipset_arn_v4)
        log.info("IPARNV6 = %s", ipset_arn_v6)
        log.info("source_ip = %s", source_ip)

        ip_type = "IPV%s" % ip_address(source_ip).version
        output = None
        if ip_type == "IPV4":
            output = add_ip_to_ip_set(log, scope, ip_type, source_ip, ipset_name_v4, ipset_arn_v4)
        elif ip_type == "IPV6":
            output = add_ip_to_ip_set(log, scope, ip_type, source_ip, ipset_name_v6, ipset_arn_v6)
    except Exception as e:
        log.error(e)
        raise
    finally:
        log.info("Output->%s<-", output)
        message = "message: [%s] Thanks for the visit." % source_ip
        response = {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': message
        }

    if output is not None:
        send_anonymous_usage_data(log, scope, ipset_name_v4, ipset_arn_v4, ipset_name_v6, ipset_arn_v6)
    log.info('[lambda_handler] End')

    return response
