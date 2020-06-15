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
import json
import logging
import math
import time
import datetime
from urllib.request import Request, urlopen
from os import environ
from ipaddress import ip_address
from botocore.config import Config
from backoff import on_exception, expo

logging.getLogger().debug('Loading function')

#======================================================================================================================
# Constants
#======================================================================================================================
API_CALL_NUM_RETRIES = 5

waf = None
if environ['LOG_TYPE'] == 'alb':
    session = boto3.session.Session(region_name=environ['REGION'])
    waf = session.client('waf-regional', config=Config(retries={'max_attempts': API_CALL_NUM_RETRIES}))
else:
    waf = boto3.client('waf', config=Config(retries={'max_attempts': API_CALL_NUM_RETRIES}))

#======================================================================================================================
# Auxiliary Functions
#======================================================================================================================
@on_exception(expo, waf.exceptions.WAFStaleDataException, max_time=10)
def waf_update_ip_set(ip_set_id, source_ip):
    logging.getLogger().debug('[waf_update_ip_set] Start')

    ip_type = "IPV%s"%ip_address(source_ip).version
    ip_class = "32" if ip_type == "IPV4" else "128"
    waf.update_ip_set(IPSetId=ip_set_id,
        ChangeToken=waf.get_change_token()['ChangeToken'],
        Updates=[{
            'Action': 'INSERT',
            'IPSetDescriptor': {
                'Type': ip_type,
                'Value': "%s/%s"%(source_ip, ip_class)
            }
        }]
    )

    logging.getLogger().debug('[waf_update_ip_set] End')

@on_exception(expo, waf.exceptions.WAFStaleDataException, max_time=10)
def waf_get_ip_set(ip_set_id):
    logging.getLogger().debug('[waf_get_ip_set] Start')
    response = waf.get_ip_set(IPSetId=ip_set_id)
    logging.getLogger().debug('[waf_get_ip_set] End')
    return response

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
              "data_type" : "bad_bot",
              "bad_bot_ip_set_size" : 0,
              "allowed_requests" : 0,
              "blocked_requests_all" : 0,
              "blocked_requests_bad_bot" : 0,
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
        logging.getLogger().debug("[send_anonymous_usage_data] Get bad bot data")
        #--------------------------------------------------------------------------------------------------------------
        if 'IP_SET_ID_BAD_BOT' in environ:
            try:
                response = waf_get_ip_set(environ['IP_SET_ID_BAD_BOT'])
                if response != None:
                    usage_data['Data']['bad_bot_ip_set_size'] = len(response['IPSet']['IPSetDescriptors'])

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
                            "Value": environ['METRIC_NAME_PREFIX'] + 'BadBotRule'
                        },
                        {
                            "Name": "WebACL",
                            "Value": environ['METRIC_NAME_PREFIX'] + 'MaliciousRequesters'
                        }
                    ]
                )
                usage_data['Data']['blocked_requests_bad_bot'] = response['Datapoints'][0]['Sum']

            except Exception as error:
                logging.getLogger().debug("[send_anonymous_usage_data] Failed to get bad bot data")
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
        logging.getLogger().debug("[send_anonymous_usage_data] Failed to Send Data")
        logging.getLogger().debug(str(error))

#======================================================================================================================
# Lambda Entry Point
#======================================================================================================================
def lambda_handler(event, context):
    logging.getLogger().debug('[lambda_handler] Start')

    response = {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': ''
    }

    try:
        #------------------------------------------------------------------
        # Set Log Level
        #------------------------------------------------------------------
        global log_level
        log_level = str(environ['LOG_LEVEL'].upper())
        if log_level not in ['DEBUG', 'INFO','WARNING', 'ERROR','CRITICAL']:
            log_level = 'ERROR'
        logging.getLogger().setLevel(log_level)

        #----------------------------------------------------------
        # Read inputs parameters
        #----------------------------------------------------------
        logging.getLogger().info(event)
        # fix security exposure based on user supplied IP addresses
        source_ip = event['requestContext']['identity']['sourceIp']

        waf_update_ip_set(environ['IP_SET_ID_BAD_BOT'], source_ip)

        message = {}
        message['message'] = "[%s] Thanks for the visit."%source_ip
        response['body'] = json.dumps(message)

        send_anonymous_usage_data()

    except Exception as error:
        logging.getLogger().error(str(error))

    logging.getLogger().debug('[lambda_handler] End')
    return response
