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
import datetime
import logging
import sys
import os
import requests
import json
import re
from ipaddress import ip_address
from ipaddress import ip_network
from ipaddress import IPv4Network
from ipaddress import IPv6Network
import boto3
from lib.solution_metrics import send_metrics
from lib.waflibv2 import WAFLIBv2

waflib = WAFLIBv2()


# Find matching ip address ranges from a line
def find_ips(line, prefix=""):
    reg = re.compile('^' + prefix + '\\s*((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])(?:/(?:3[0-2]|[1-2][0-9]|[0-9]))?)')
    ips = re.findall(reg, line)

    return ips
    
# Read each address from source URL
def read_url_list(log, current_list, url, prefix=""):
    try:
        log.info("[read_url_list]reading url " + url)
        file = requests.get(url)
        new_ip_count = 0
        line_count = 0
        current_ip_count = len(current_list)

        # Proceed if request returns success code 200
        if file.status_code == 200:
            for line in file.iter_lines():
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
            except Exception as e:
                log.debug(source_ip + " not an IP address.")
    return process_list


# push each source_ip into the appropriate IPSet
def populate_ipsets(log, scope, ipset_name_v4, ipset_name_v6, ipset_arn_v4, ipset_arn_v6, current_list):
    addressesV4 = []
    addressesV6 = []

    for address in current_list:
        try:
            source_ip = address.split("/")[0]
            ip_type = "IPV%s" % ip_address(source_ip).version
            if ip_type == "IPV4":
                addressesV4.append(address)
            elif ip_type == "IPV6":
                addressesV6.append(address)
        except Exception as e:
            log.error(e)

    waflib.update_ip_set(log, scope, ipset_name_v4, ipset_arn_v4, addressesV4)
    ipset = waflib.get_ip_set(log, scope, ipset_name_v4, ipset_arn_v4)

    log.info(ipset)
    log.info("There are %d IP addresses in IPSet %s", len(ipset["IPSet"]["Addresses"]), ipset_name_v4)

    waflib.update_ip_set(log, scope, ipset_name_v6, ipset_arn_v6, addressesV6)
    ipset = waflib.get_ip_set(log, scope, ipset_name_v6, ipset_arn_v6)

    log.info(ipset)
    log.info("There are %d IP addresses in IPSet %s", len(ipset["IPSet"]["Addresses"]), ipset_name_v6)

    return


def send_response(log, event, context, responseStatus, responseData, resourceId, reason=None):
    log.debug("[send_response] Start")

    responseUrl = event['ResponseURL']
    cw_logs_url = "https://console.aws.amazon.com/cloudwatch/home?region=%s#logEventViewer:group=%s;stream=%s" % (
        context.invoked_function_arn.split(':')[3], context.log_group_name, context.log_stream_name)

    log.info(responseUrl)
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = reason or ('See the details in CloudWatch Logs: ' + cw_logs_url)
    responseBody['PhysicalResourceId'] = resourceId
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = False
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)
    log.debug("Response body:\n" + json_responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        log.debug("Status code: " + response.reason)

    except Exception as error:
        log.error("[send_response] Failed executing requests.put(..)")
        log.error(str(error))

    log.debug("[send_response] End")


def send_anonymous_usage_data(log, scope):
    try:
        if 'SEND_ANONYMOUS_USAGE_DATA' not in os.environ or os.getenv('SEND_ANONYMOUS_USAGE_DATA').lower() != 'yes':
            return

        log.debug("[send_anonymous_usage_data] Start")
        cw = boto3.client('cloudwatch')
        usage_data = {
            "data_type": "reputation_lists",
            "ipv4_reputation_lists_size": 0,
            "ipv4_reputation_lists": 0,
            "ipv6_reputation_lists_size": 0,
            "ipv6_reputation_lists": 0,
            "allowed_requests": 0,
            "blocked_requests": 0,
            "blocked_requests_ip_reputation_lists": 0,
            "waf_type": os.getenv('LOG_TYPE')
        }

        # --------------------------------------------------------------------------------------------------------------
        log.debug("[send_anonymous_usage_data] Get size of the Reputation List IP set")
        # --------------------------------------------------------------------------------------------------------------
        try:
            response = waflib.get_ip_set(log, scope, os.getenv('IP_SET_NAME_REPUTATIONV4'),
                                         os.getenv('IP_SET_ID_REPUTATIONV4'))

            if response is not None:
                usage_data['ipv4_reputation_lists_size'] = len(response['IPSet']['Addresses'])
                usage_data['ipv4_reputation_lists'] = response['IPSet']['Addresses']

        except Exception as error:
            log.debug("[send_anonymous_usage_data] Failed to get size of the Reputation List IPV4 set")
            log.debug(str(error))

        try:
            response = waflib.get_ip_set(log, scope, os.getenv('IP_SET_NAME_REPUTATIONV6'),
                                         os.getenv('IP_SET_ID_REPUTATIONV6'))
            if response is not None:
                usage_data['ipv6_reputation_lists_size'] = len(response['IPSet']['Addresses'])
                usage_data['ipv6_reputation_lists'] = response['IPSet']['Addresses']

        except Exception as error:
            log.debug("[send_anonymous_usage_data] Failed to get size of the Reputation List IPV6 set")
            log.debug(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.debug("[send_anonymous_usage_data] Get total number of allowed requests")
        # --------------------------------------------------------------------------------------------------------------
        try:
            response = cw.get_metric_statistics(
                MetricName='AllowedRequests',
                Namespace='AWS/WAFV2',
                Statistics=['Sum'],
                Period=3600,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=3600),
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
        log.debug("[send_anonymous_usage_data] Get total number of blocked requests")
        # --------------------------------------------------------------------------------------------------------------
        try:
            response = cw.get_metric_statistics(
                MetricName='BlockedRequests',
                Namespace='AWS/WAFV2',
                Statistics=['Sum'],
                Period=3600,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=3600),
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
                usage_data['blocked_requests'] = response['Datapoints'][0]['Sum']

        except Exception as error:
            log.debug("[send_anonymous_usage_data] Failed to get Num Allowed Requests")
            log.debug(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.debug("[send_anonymous_usage_data] Get total number of blocked requests for Reputation Lists Rule")
        # --------------------------------------------------------------------------------------------------------------
        try:
            response = cw.get_metric_statistics(
                MetricName='BlockedRequests',
                Namespace='AWS/WAFV2',
                Statistics=['Sum'],
                Period=3600,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=3600),
                EndTime=datetime.datetime.utcnow(),
                Dimensions=[
                    {
                        "Name": "Rule",
                        "Value": os.getenv('IPREPUTATIONLIST_METRICNAME')
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
                usage_data['blocked_requests_ip_reputation_lists'] = response['Datapoints'][0]['Sum']

        except Exception as error:
            log.debug("[send_anonymous_usage_data] Failed to get Num Allowed Requests")
            log.debug(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Send Data")
        # --------------------------------------------------------------------------------------------------------------

        response = send_metrics(data=usage_data)
        response_code = response.status_code
        log.debug('[send_anonymous_usage_data] Response Code: {}'.format(response_code))
        log.debug("[send_anonymous_usage_data] End")
    except Exception as error:
        log.debug("[send_anonymous_usage_data] Failed to send data")


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================

def lambda_handler(event, context):
    log = logging.getLogger()
    log.info('[lambda_handler] Start')

    responseStatus = 'SUCCESS'
    reason = None
    responseData = {}
    result = {
        'StatusCode': '200',
        'Body': {'message': 'success'}
    }
    log_level = str(os.getenv('LOG_LEVEL').upper())
    if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        log_level = 'ERROR'
    log.setLevel(log_level)

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
        responseStatus = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '400',
            'body': {'message': reason}
        }
    finally:
        log.info('[lambda_handler] End')
        if 'ResponseURL' in event:
            resourceId = event['PhysicalResourceId'] if 'PhysicalResourceId' in event else event['LogicalResourceId']
            log.info("ResourceId %s", resourceId)
            send_response(log, event, context, responseStatus, responseData, resourceId, reason)

        return json.dumps(result)
