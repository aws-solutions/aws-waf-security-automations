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

import json
from lib.cfn_response import send_response
from lib.logging_util import set_log_level
from operations import (
    operation_types,
    set_log_group_retention,
    config_app_access_log_bucket,
    config_waf_log_bucket,
    config_web_acl,
    config_aws_waf_logs,
    generate_app_log_parser_conf,
    generate_waf_log_parser_conf,
    add_athena_partitions
)
from operations.operation_types import RESOURCE_TYPE

operations_dictionary = {
    operation_types.SET_CLOUDWATCH_LOGGROUP_RETENTION: set_log_group_retention.execute,
    operation_types.CONFIG_AWS_WAF_LOGS: config_aws_waf_logs.execute,
    operation_types.CONFIG_APP_ACCESS_LOG_BUCKET: config_app_access_log_bucket.execute,
    operation_types.CONFIG_WAF_LOG_BUCKET: config_waf_log_bucket.execute,
    operation_types.CONFIG_WEB_ACL: config_web_acl.execute,
    operation_types.GENERATE_APP_LOG_PARSER_CONF_FILE: generate_app_log_parser_conf.execute,
    operation_types.GENERATE_WAF_LOG_PARSER_CONF_FILE: generate_waf_log_parser_conf.execute,
    operation_types.ADD_ATHENA_PARTITIONS: add_athena_partitions.execute
}

class UnSupportedOperationTypeException(Exception):
    pass

def get_function_for_resource(resource, log):
    try:
        return operations_dictionary[resource]
    except KeyError as key_error:
        log.error(key_error)
        raise UnSupportedOperationTypeException(f"The operation {resource} is not supported")


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
def lambda_handler(event, context):    
    log = set_log_level()
    response_status = 'SUCCESS'
    reason = None
    response_data = {}
    resource_id = event.get('PhysicalResourceId', event['LogicalResourceId'])
    result = {
        'StatusCode': '200',
        'Body': {'message': 'success'}
    }
    
    log.info(f'context: {context}')
    
    try:
        # ----------------------------------------------------------
        # Read inputs parameters
        # ----------------------------------------------------------
        log.info(event)
        request_type = event.get('RequestType', "").upper()
        log.info(request_type)

        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        operation = get_function_for_resource(event[RESOURCE_TYPE], log)
        if operation:
            operation(event, context, log)

    except Exception as error:
        log.error(error)
        response_status = 'FAILED'
        reason = str(error)
        result = {
            'statusCode': '500',
            'body': {'message': reason}
        }

    finally:
        # ------------------------------------------------------------------
        # Send Result
        # ------------------------------------------------------------------
        if 'ResponseURL' in event:
            send_response(log, event, context, response_status, response_data, resource_id, reason)

        return json.dumps(result) #NOSONAR needed to send a response of the result
