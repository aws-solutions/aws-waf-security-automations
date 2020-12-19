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

import requests
import boto3
import json
import logging
import math
import time
import datetime
import os
from ipaddress import ip_address
from ipaddress import ip_network
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from os import environ
from botocore.config import Config

from lib.waflibv2 import WAFLIBv2
from lib.solution_metrics import send_metrics

waflib = WAFLIBv2()


def send_anonymous_usage_data(log, scope, ipset_name_v4, ipset_arn_v4, ipset_name_v6, ipset_arn_v6):
    try:
        if 'SEND_ANONYMOUS_USAGE_DATA' not in environ or os.getenv('SEND_ANONYMOUS_USAGE_DATA').lower() != 'yes':
            return

        log.info("[send_anonymous_usage_data] Start")
        metric_prefix = os.getenv('METRIC_NAME_PREFIX')

        cw = boto3.client('cloudwatch')
        usage_data = {
            "data_type": "bad_bot",
            "bad_bot_ip_set_size": 0,
            "allowed_requests": 0,
            "blocked_requests_all": 0,
            "blocked_requests_bad_bot": 0,
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
                Period=12 * 3600,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=12 * 3600),
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
            if len(response['Datapoints']) > 0:
                usage_data['allowed_requests'] = response['Datapoints'][0]['Sum']

        except Exception as error:
            log.info("[send_anonymous_usage_data] Failed to get Num Allowed Requests")
            log.error(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Get num blocked requests - all rules")
        # --------------------------------------------------------------------------------------------------------------
        try:
            response = cw.get_metric_statistics(
                MetricName='BlockedRequests',
                Namespace='AWS/WAFV2',
                Statistics=['Sum'],
                Period=12 * 3600,
                StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=12 * 3600),
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
            if len(response['Datapoints']) > 0:
                usage_data['blocked_requests_all'] = response['Datapoints'][0]['Sum']

        except Exception as error:
            log.info("[send_anonymous_usage_data] Failed to get num blocked requests - all rules")
            log.error(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Get bad bot data")
        # --------------------------------------------------------------------------------------------------------------
        if 'IP_SET_ID_BAD_BOTV4' in environ or 'IP_SET_ID_BAD_BOTV6' in environ:
            try:
                countv4 = 0
                response = waflib.get_ip_set(log, scope, ipset_name_v4, ipset_arn_v4)
                log.info(response)
                if response is not None:
                    countv4 = len(response['IPSet']['Addresses'])
                    log.info("Bad Bot CountV4 %s", countv4)

                countv6 = 0
                response = waflib.get_ip_set(log, scope, ipset_name_v6, ipset_arn_v6)
                log.info(response)
                if response is not None:
                    countv6 = len(response['IPSet']['Addresses'])
                    log.info("Bad Bot CountV6 %s", countv6)

                usage_data['bad_bot_ip_set_size'] = str(countv4 + countv6)

                response = cw.get_metric_statistics(
                    MetricName='BlockedRequests',
                    Namespace='AWS/WAFV2',
                    Statistics=['Sum'],
                    Period=12 * 3600,
                    StartTime=datetime.datetime.utcnow() - datetime.timedelta(seconds=12 * 3600),
                    EndTime=datetime.datetime.utcnow(),
                    Dimensions=[
                        {
                            "Name": "Rule",
                            "Value": metric_prefix + 'BadBotRule'
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
                if len(response['Datapoints']) > 0:
                    usage_data['blocked_requests_bad_bot'] = response['Datapoints'][0]['Sum']

            except Exception as error:
                log.info("[send_anonymous_usage_data] Failed to get bad bot data")
                log.error(str(error))

        # --------------------------------------------------------------------------------------------------------------
        log.info("[send_anonymous_usage_data] Send Data")
        # --------------------------------------------------------------------------------------------------------------
        response = send_metrics(data=usage_data)
        response_code = response.status_code
        log.info('[send_anonymous_usage_data] Response Code: {}'.format(response_code))
        log.info("[send_anonymous_usage_data] End")

    except Exception as error:
        log.info("[send_anonymous_usage_data] Failed to Send Data")
        log.error(str(error))


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
def lambda_handler(event, context):
    log = logging.getLogger()
    log.info('[lambda_handler] Start')
    log_level = str(os.getenv('LOG_LEVEL').upper())
    if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        log_level = 'ERROR'
    log.setLevel(log_level)

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
        source_ip = str(event['requestContext']['identity']['sourceIp'])

        log.info("scope = %s", scope)
        log.info("ipset_name_v4 = %s", ipset_name_v4)
        log.info("ipset_name_v6 = %s", ipset_name_v6)
        log.info("IPARNV4 = %s", ipset_arn_v4)
        log.info("IPARNV6 = %s", ipset_arn_v6)
        log.info("source_ip = %s", source_ip)
    except Exception as e:
        log.error(e)
        raise

    new_address = []
    output = None
    try:
        ip_type = "IPV%s" % ip_address(source_ip).version
        if ip_type == "IPV4":
            new_address.append(IPv4Network(source_ip).with_prefixlen)
            ipset = waflib.get_ip_set(log, scope, ipset_name_v4, ipset_arn_v4)
            # merge old addresses with this one
            log.info(ipset)
            current_list = ipset["IPSet"]["Addresses"]
            log.info(current_list)
            new_list = list(set(current_list) | set(new_address))
            log.info(new_list)
            output = waflib.update_ip_set(log, scope, ipset_name_v4, ipset_arn_v4, new_list)
        elif ip_type == "IPV6":
            new_address.append(IPv6Network(source_ip).with_prefixlen)
            ipset = waflib.get_ip_set(log, scope, ipset_name_v6, ipset_arn_v6)

            # merge old addresses with this one
            log.info(ipset)
            current_list = ipset["IPSet"]["Addresses"]
            log.info(current_list)
            new_list = list(set(current_list) | set(new_address))
            log.info(new_list)
            output = waflib.update_ip_set(log, scope, ipset_name_v6, ipset_arn_v6, new_list)
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
