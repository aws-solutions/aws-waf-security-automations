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

from resource_manager import ResourceManager
from operations.operation_types import (
    CREATE,
    UPDATE,
    DELETE,
    REQUEST_TYPE
)

def execute(event, _, log):
    resource_manager = ResourceManager(log=log)
    if event[REQUEST_TYPE] == CREATE:
        waf_params = resource_manager.get_params_waf_event(event)
        resource_manager.add_s3_bucket_lambda_event(**waf_params)

    elif event[REQUEST_TYPE] == UPDATE:
        if resource_manager.waf_has_old_resources(event):
            resource_manager.update_waf_log_bucket(event)

    elif event[REQUEST_TYPE] == DELETE:
        bucket_lambda_params = resource_manager.get_params_bucket_lambda_delete_event(event)
        resource_manager.remove_s3_bucket_lambda_event(**bucket_lambda_params)