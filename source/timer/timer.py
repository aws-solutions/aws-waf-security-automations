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

import time
import os
import json
from lib.cfn_response import send_response
from lib.logging_util import set_log_level


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

    try:
        count = 3
        SECONDS = os.getenv('SECONDS')
        if (SECONDS != None):
            count = int(SECONDS)
        time.sleep(count)
        log.info(count)
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

        return json.dumps(result) #NOSONAR needed to send a response of the result
