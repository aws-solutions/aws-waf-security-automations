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

import json
from stack_requirements import StackRequirements
from lib.cfn_response import send_response
from lib.logging_util import set_log_level

# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
def lambda_handler(event, context):
    log = set_log_level()

    response_status = 'SUCCESS'
    reason = None
    response_data = {}
    resource_id = event['PhysicalResourceId'] if 'PhysicalResourceId' in event else event['LogicalResourceId']
    result = {
        'StatusCode': '200',
        'Body': {'message': 'success'}
    }

    stack_requirements = StackRequirements(log)

    log.info(f'context: {context}')
    try:
        # ----------------------------------------------------------
        # Read inputs parameters
        # ----------------------------------------------------------
        log.info(event)
        request_type = event['RequestType'].upper() if ('RequestType' in event) else ""
        log.info(request_type)

        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        if event['ResourceType'] == "Custom::CheckRequirements" and request_type in {'CREATE', 'UPDATE'}:
            stack_requirements.verify_requirements_and_dependencies(event)

        elif event['ResourceType'] == "Custom::CreateUUID" and request_type == 'CREATE':
            stack_requirements.create_uuid(response_data)

        elif event['ResourceType'] == "Custom::CreateDeliveryStreamName" and request_type == 'CREATE':
            stack_requirements.create_delivery_stream_name(event, response_data)

        elif event['ResourceType'] == "Custom::CreateGlueDatabaseName" and request_type == 'CREATE':
            stack_requirements.create_db_name(event, response_data)

    except Exception as error:
        log.error(error)
        response_status = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '400',
            'body': {'message': reason}
        }

    finally:
        # ------------------------------------------------------------------
        # Send Result
        # ------------------------------------------------------------------
        if 'ResponseURL' in event:
            send_response(log, event, context, response_status, response_data, resource_id, reason)

        return json.dumps(result)
