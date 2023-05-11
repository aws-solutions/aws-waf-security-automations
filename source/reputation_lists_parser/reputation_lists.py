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
import requests
import json
import re
from time import sleep
from ipaddress import ip_address
from ipaddress import ip_network
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from os import environ
from lib.solution_metrics import send_metrics
from lib.waflibv2 import WAFLIBv2
from lib.cfn_response import send_response
from lib.cw_metrics_util import WAFCloudWatchMetrics
from lib.logging_util import set_log_level

waflib = WAFLIBv2()

delay_between_updates = 5
CW_METRIC_PERIOD_SECONDS = 3600    # One hour in seconds

# Find matching ip address ranges from a line
def find_ips(line, prefix=""):
    reg = re.compile('^' + prefix + '\\s*((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])(?:/(?:3[0-2]|[1-2][0-9]|[0-9]))?)')
    ips = re.findall(reg, line)

    return ips
    
# Read each address from source URL
def read_url_list(log, current_list, url, prefix=""):
    try:
        log.info("[read_url_list]reading url " + url)
        response = requests.get(url, timeout=30)
        new_ip_count = 0
        line_count = 0
        current_ip_count = len(current_list)

        # Proceed if request returns success code 200
        if response.status_code == 200:
            for line in response.iter_lines():
                decoded_line = line.decode("utf-8").strip()  # remove spaces on either end of string
                line_count = line_count + 1
                new_ips = find_ips(decoded_line, prefix)
                current_list = list(set(current_list) | set(new_ips))
                new_ip_count = new_ip_count + len(new_ips)
        
        log.info("[read_url_list]"+ str(new_ip_count) + " ip address ranges read from " + url + "; " + str(line_count) + " lines")
        log.info("[read_url_list]number of new ip address ranges added to current list: " + str(len(current_list) - current_ip_count)
                + "; total number of ip address ranges on curent list: " + str(len(current_list)))
    except Exception as e:
        log.error(e)

    return current_list


# Fully qualify each address with network cidr
def process_url_list(log, current_list):
    process_list = []
    for source_ip in current_list:
        try:
            ip_type = "IPV%s" % ip_address(source_ip).version
            if (ip_type == "IPV4"):
                process_list.append(IPv4Network(source_ip).with_prefixlen)
            elif (ip_type == "IPV6"):
                process_list.append(IPv6Network(source_ip).with_prefixlen)
        except:
            try:
                if (ip_network(source_ip)):
                    process_list.append(source_ip)
            except Exception:
                log.debug(source_ip + " not an IP address.")
    return process_list


# push each source_ip into the appropriate IPSet
def populate_ipsets(log, scope, ipset_name_v4, ipset_name_v6, ipset_arn_v4, ipset_arn_v6, current_list):
    addresses_v4 = []
    addresses_v6 = []

    for address in current_list:
        try:
            source_ip = address.split("/")[0]
            ip_type = "IPV%s" % ip_address(source_ip).version
            if ip_type == "IPV4":
                addresses_v4.append(address)
            elif ip_type == "IPV6":
                addresses_v6.append(address)
        except Exception as e:
            log.error(e)

    waflib.update_ip_set(log, scope, ipset_name_v4, ipset_arn_v4, addresses_v4)
    ipset = waflib.get_ip_set(log, scope, ipset_name_v4, ipset_arn_v4)

    log.info(ipset)
    log.info("There are %d IP addresses in IPSet %s", len(ipset["IPSet"]["Addresses"]), ipset_name_v4)

    # Sleep for a few seconds to mitigate AWS WAF Update API call throttling issue
    sleep(delay_between_updates)

    waflib.update_ip_set(log, scope, ipset_name_v6, ipset_arn_v6, addresses_v6)
    ipset = waflib.get_ip_set(log, scope, ipset_name_v6, ipset_arn_v6)

    log.info(ipset)
    log.info("There are %d IP addresses in IPSet %s", len(ipset["IPSet"]["Addresses"]), ipset_name_v6)


def initialize_usage_data():
    usage_data = {
        "data_type": "reputation_lists",
        "ipv4_reputation_lists_size": 0,
        "ipv4_reputation_lists": 0,
        "ipv6_reputation_lists_size": 0,
        "ipv6_reputation_lists": 0,
        "allowed_requests": 0,
        "blocked_requests": 0,
        "blocked_requests_ip_reputation_lists": 0,
        "waf_type": os.getenv('LOG_TYPE'),
        "provisioner": os.getenv('provisioner') if "provisioner" in environ else "cfn"
    }
    return usage_data


def get_ip_reputation_usage_data(log, scope, ipset_name,
                                ipset_arn, usage_data,
                                usage_data_ip_list_size_field,
                                usage_data_ip_list_field):
    log.info("[get_ip_reputation_usage_data] Get size of %s", ipset_name)

    # Get ip reputation ipv4 and ipv6 lists
    if 'IP_SET_ID_REPUTATIONV4' in environ or 'IP_SET_ID_REPUTATIONV6' in environ:
        response = waflib.get_ip_set(log, scope, ipset_name, ipset_arn)

        if response is not None:
            usage_data[usage_data_ip_list_size_field] = len(response['IPSet']['Addresses'])
            usage_data[usage_data_ip_list_field] = response['IPSet']['Addresses']
    return usage_data


def send_anonymous_usage_data(log, scope):
    try:
        if 'SEND_ANONYMOUS_USAGE_DATA' not in os.environ or os.getenv('SEND_ANONYMOUS_USAGE_DATA').lower() != 'yes':
            return

        log.debug("[send_anonymous_usage_data] Start")
        cw = WAFCloudWatchMetrics(log)
        usage_data = initialize_usage_data()

        usage_data = get_ip_reputation_usage_data(
            log, scope,
            os.getenv('IP_SET_NAME_REPUTATIONV4'),
            os.getenv('IP_SET_ID_REPUTATIONV4'),
            usage_data,
            'ipv4_reputation_lists_size',
            'ipv4_reputation_lists'
        )
        
        usage_data = get_ip_reputation_usage_data(
            log, scope,
            os.getenv('IP_SET_NAME_REPUTATIONV6'),
            os.getenv('IP_SET_ID_REPUTATIONV6'),
            usage_data,
            'ipv6_reputation_lists_size',
            'ipv6_reputation_lists'
        )

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
            'blocked_requests',
            0
        )

        # Get the count of blocked requests for the Reputation Lists Rule from cloudwatch metrics
        usage_data = cw.add_waf_cw_metric_to_usage_data(
            'BlockedRequests',
            CW_METRIC_PERIOD_SECONDS,
            os.getenv('IPREPUTATIONLIST_METRICNAME'),
            usage_data,
            'blocked_requests_ip_reputation_lists',
            0
        )

        # Send usage data
        log.info('[send_anonymous_usage_data] Send usage data: \n{}'.format(usage_data))
        response = send_metrics(data=usage_data)
        response_code = response.status_code
        log.debug('[send_anonymous_usage_data] Response Code: {}'.format(response_code))
        log.debug("[send_anonymous_usage_data] End")
    except Exception:
        log.debug("[send_anonymous_usage_data] Failed to send data")


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================

def lambda_handler(event, context):
    log = set_log_level()
    log.info('[lambda_handler] Start')

    response_status = 'SUCCESS'
    reason = None
    response_data = {}
    result = {
        'StatusCode': '200',
        'Body': {'message': 'success'}
    }

    current_list = []
    try:
        scope = os.getenv('SCOPE')
        ipset_name_v4 = os.getenv('IP_SET_NAME_REPUTATIONV4')
        ipset_name_v6 = os.getenv('IP_SET_NAME_REPUTATIONV6')
        ipset_arn_v4 = os.getenv('IP_SET_ID_REPUTATIONV4')
        ipset_arn_v6 = os.getenv('IP_SET_ID_REPUTATIONV6')
        URL_LIST = os.getenv('URL_LIST')
        url_list = json.loads(URL_LIST)

        log.info("SCOPE = %s", scope)
        log.info("ipset_name_v4 = %s", ipset_name_v4)
        log.info("ipset_name_v6 = %s", ipset_name_v6)
        log.info("ipset_arn_v4 = %s", ipset_arn_v4)
        log.info("ipset_arn_v6 = %s", ipset_arn_v6)
        log.info("URLLIST = %s", url_list)
    except Exception as e:
        log.error(e)
        raise

    try:
        for info in url_list:
            try:
                if("prefix" in info):
                    current_list = read_url_list(log, current_list, info["url"], info["prefix"])
                else:
                    current_list = read_url_list(log, current_list, info["url"])
            except:
                log.error("URL info not valid %s", info)

        current_list = sorted(current_list, key=str)
        current_list = process_url_list(log, current_list)

        populate_ipsets(log, scope, ipset_name_v4, ipset_name_v6, ipset_arn_v4, ipset_arn_v6, current_list)
        send_anonymous_usage_data(log, scope)

    except Exception as error:
        log.error(str(error))
        response_status = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '400',
            'body': {'message': reason}
        }
    finally:
        log.info('[lambda_handler] End')
        if 'ResponseURL' in event:
            resource_id = event['PhysicalResourceId'] if 'PhysicalResourceId' in event else event['LogicalResourceId']
            log.info("ResourceId %s", resource_id)
            send_response(log, event, context, response_status, response_data, resource_id, reason)

        return json.dumps(result)
