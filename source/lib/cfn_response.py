######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
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
# !/bin/python

import requests
import json

def send_response(log, event, context, response_status, response_data, resource_id, reason=None):
    """
    Send a response to an AWS CloudFormation custom resource.
        Parameters:
           event: The fields in a custom resource request
           context: An object, specific to Lambda functions, that you can use to specify 
                    when the function and any callbacks have completed execution, or to 
                    access information from within the Lambda execution environment
           response_status: Whether the function successfully completed - SUCCESS or FAILED
           response_data: The Data field of a custom resource response object
           resource_id: The id of the custom resource that invoked the function
           reason: The error message if the function fails

        Returns: None
    """
    log.debug("[send_response] Start")

    responseUrl = event['ResponseURL']
    cw_logs_url = "https://console.aws.amazon.com/cloudwatch/home?region=%s#logEventViewer:group=%s;stream=%s" % (
        context.invoked_function_arn.split(':')[3], context.log_group_name, context.log_stream_name)

    log.info("[send_response] Sending cfn response url: %s", responseUrl)
    responseBody = {}
    responseBody['Status'] = response_status
    responseBody['Reason'] = reason or ('See the details in CloudWatch Logs: ' + cw_logs_url)
    responseBody['PhysicalResourceId'] = resource_id
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = False
    responseBody['Data'] = response_data

    json_responseBody = json.dumps(responseBody)
    log.debug("Response body:\n" + json_responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers,
                                timeout=10)
        log.info("[send_response] Sending cfn response status code: %s", response.reason)

    except Exception as error:
        log.error("[send_response] Failed executing requests.put(..)")
        log.error(str(error))

    log.debug("[send_response] End")