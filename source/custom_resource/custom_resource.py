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
from resource_manager import ResourceManager
from log_group_retention import LogGroupRetention
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
    resource_id = event.get('PhysicalResourceId', event['LogicalResourceId'])
    result = {
        'StatusCode': '200',
        'Body': {'message': 'success'}
    }
    resource_manager = ResourceManager(log=log)
    
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

        if event['ResourceType'] == "Custom::SetCloudWatchLogGroupRetention" and request_type in {'UPDATE', 'CREATE'}:
            log_group_retention = LogGroupRetention(log)
            log_group_retention.update_retention(
                event=event
            )

        if event['ResourceType'] == "Custom::ConfigureAppAccessLogBucket":
            if 'CREATE' in request_type:
                resource_manager.configure_s3_bucket(event)
                app_access_params = resource_manager.get_params_app_access_create_event(event)
                resource_manager.add_s3_bucket_lambda_event(**app_access_params)

            elif 'UPDATE' in request_type:
                resource_manager.configure_s3_bucket(event)
                if resource_manager.contains_old_app_access_resources(event):
                    resource_manager.update_app_access_log_bucket(event)

            elif 'DELETE' in request_type:
                bucket_lambda_params = resource_manager.get_params_app_access_delete_event(event)
                resource_manager.remove_s3_bucket_lambda_event(**bucket_lambda_params)
                

        elif event['ResourceType'] == "Custom::ConfigureWafLogBucket":
            if 'CREATE' in request_type:
                waf_params = resource_manager.get_params_waf_event(event)
                resource_manager.add_s3_bucket_lambda_event(**waf_params)

            elif 'UPDATE' in request_type:
                if resource_manager.waf_has_old_resources(event):
                    resource_manager.update_waf_log_bucket(event)

            elif 'DELETE' in request_type:
                bucket_lambda_params = resource_manager.get_params_bucket_lambda_delete_event(event)
                resource_manager.remove_s3_bucket_lambda_event(**bucket_lambda_params)


        elif event['ResourceType'] == "Custom::ConfigureWebAcl":
            # Manually delete ip sets to avoid throttling occurred during stack deletion due to API call limit 
            if 'DELETE' in request_type:
                resource_manager.delete_ip_sets(event)
            resource_manager.send_anonymous_usage_data(event['RequestType'], event.get('ResourceProperties', {}))


        elif event['ResourceType'] == "Custom::ConfigureAWSWAFLogs":
            if 'CREATE' in request_type:
                resource_manager.put_logging_configuration(event)

            elif 'UPDATE' in request_type:
                resource_manager.delete_logging_configuration(event)
                resource_manager.put_logging_configuration(event)

            elif 'DELETE' in request_type:
                resource_manager.delete_logging_configuration(event)


        elif event['ResourceType'] == "Custom::GenerateAppLogParserConfFile":
            if 'CREATE' in request_type:
                resource_manager.generate_app_log_parser_conf_file(event, overwrite=True)
                
            elif 'UPDATE' in request_type:
                resource_manager.generate_app_log_parser_conf_file(event, overwrite=False)

            # DELETE: do nothing


        elif event['ResourceType'] == "Custom::GenerateWafLogParserConfFile":
            if 'CREATE' in request_type:
                resource_manager.generate_waf_log_parser_conf_file(event, overwrite=True)
                
            elif 'UPDATE' in request_type:
                resource_manager.generate_waf_log_parser_conf_file(event, overwrite=False)

            # DELETE: do nothing


        elif event['ResourceType'] == "Custom::AddAthenaPartitions":
            if 'CREATE' in request_type or 'UPDATE' in request_type:
                resource_manager.add_athena_partitions(event)

            # DELETE: do nothing

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

        return json.dumps(result)
