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

import logging
import time
import sys
import os
import requests
import json


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

    try:
        log_level = str(os.getenv('LOG_LEVEL').upper())
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            log_level = 'ERROR'
        log.setLevel(log_level)
        count = 3
        SECONDS = os.getenv('SECONDS')
        if (SECONDS != None):
            count = int(SECONDS)
        time.sleep(count)
        log.info(count)
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
