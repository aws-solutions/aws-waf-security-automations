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
        resource_manager.configure_s3_bucket(event)
        app_access_params = resource_manager.get_params_app_access_create_event(event)
        resource_manager.add_s3_bucket_lambda_event(**app_access_params)

    elif event[REQUEST_TYPE] == UPDATE:
        resource_manager.configure_s3_bucket(event)
        if resource_manager.contains_old_app_access_resources(event):
            resource_manager.update_app_access_log_bucket(event)

    elif event[REQUEST_TYPE] == DELETE:
        bucket_lambda_params = resource_manager.get_params_app_access_delete_event(event)
        resource_manager.remove_s3_bucket_lambda_event(**bucket_lambda_params)