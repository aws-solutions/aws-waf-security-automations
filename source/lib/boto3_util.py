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
#!/bin/python

import boto3
import logging
from os import environ
from botocore.config import Config

log = logging.getLogger()

def create_client(service_name, max_attempt=5, mode='standard', user_agent_extra=environ.get('USER_AGENT_EXTRA'), my_config = {}):
    """
    This function creates a boto3 client given a service and its configurations
    """
    try:
          config = Config(
                user_agent_extra=user_agent_extra,
                retries={'max_attempts': max_attempt, 'mode': mode}
            )
          if my_config != {}:
                config = my_config

          return boto3.client(
                service_name,
                config = config
             )
    except Exception as e:
        log.error("[boto3_util: create_client] failed to create client")
        log.error(e)
        raise e


def create_resource(service_name, max_attempt=5, mode='standard', user_agent_extra=environ.get('USER_AGENT_EXTRA'), my_config = {}):
    """
    This function creates a boto3 resource given a service and its configurations
    """
    try:
          config = Config(
                user_agent_extra=user_agent_extra,
                retries={'max_attempts': max_attempt, 'mode': mode}
            )
          if my_config != {}:
                config = my_config

          return boto3.resource(
                service_name,
                config = config
             )
    except Exception as e:
        log.error("[boto3_util: create_resource] failed to create resource")
        log.error(e)
        raise e