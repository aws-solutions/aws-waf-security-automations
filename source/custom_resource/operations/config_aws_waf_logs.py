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
    DELETE,
    REQUEST_TYPE,
    CREATE,
    UPDATE
)

def execute(event, _, log):
    resource_manager = ResourceManager(log=log)

    if event[REQUEST_TYPE] == CREATE:
        resource_manager.put_logging_configuration(event)

    elif event[REQUEST_TYPE] == UPDATE:
        resource_manager.delete_logging_configuration(event)
        resource_manager.put_logging_configuration(event)

    elif event[REQUEST_TYPE] == DELETE:
        resource_manager.delete_logging_configuration(event)