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
import os
import boto3
import logging
from botocore.config import Config
from ipaddress import ip_address
import sys
from backoff import on_exception, expo

API_CALL_NUM_RETRIES = 5
MAX_TIME = 10
client = boto3.client('wafv2', config=Config(retries={'max_attempts': API_CALL_NUM_RETRIES}))

class WAFLIBv2(object):

    def __init__(self):
        return

    # Parse arn into ip_set_id
    def arn_to_id(self, arn):
        if arn == None:
            return None
        tmp = arn.split('/')
        return tmp.pop()
    
    # Determine network version for source_ip
    def which_ip_version(self, log, source_ip):
        if source_ip == None:
            return None
        try:
            source_ip = source_ip.strip()
            ip_type = "IPV%s"%ip_address(source_ip).version
            return ip_type
        except Exception as e:
            log.error("Source ip %s is not IPV4 or IPV6.", str(source_ip))
            log.error(str(e))
            return None
    
    # Append correct cidr to source_ip
    def set_ip_cidr(self, log, source_ip):
        if source_ip == None:
            return None
        try:
            source_ip = source_ip.strip()
            ip_type = "IPV%s"%ip_address(source_ip).version
        except Exception as e:
            log.error("Source ip %s is not IPV4 or IPV6.", str(source_ip))
            log.error(str(e))
            return None
        
        ip_class = "32" if ip_type == "IPV4" else "128"
        return str(source_ip)+"/"+str(ip_class)

    # Retrieve IPSet based on ip_set_id
    @on_exception(expo, client.exceptions.WAFInternalErrorException, max_time=MAX_TIME)
    def get_ip_set(self, log, scope, name, arn):
        try:
            log.info("[waflib:get_ip_set] Start")
            ip_set_id = self.arn_to_id(arn)
            response = client.get_ip_set(
                Scope=scope,
                Name=name,
                Id=ip_set_id
            )
            log.info("[waflib:get_ip_set] End")
            return response
        except Exception as e:
            log.error("Failed to get IPSet %s", str(ip_set_id))
            log.error(str(e))
            return None

    # Retrieve addresses based on ip_set_id
    @on_exception(expo, client.exceptions.WAFInternalErrorException, max_time=MAX_TIME)
    def get_addresses(self, log, scope, name, arn):
        try:
            response = self.get_ip_set(log, scope, name, arn)
            addresses = response["IPSet"]["Addresses"]
            return addresses
        except Exception as e:
            log.error("Failed to get addresses for ARN %s", str(arn))
            log.error(str(e))
            return None

    # Update addresses in an IPSet
    @on_exception(expo,
                  (client.exceptions.WAFInternalErrorException,
                   client.exceptions.WAFOptimisticLockException,
                   client.exceptions.WAFLimitsExceededException),
                  max_time=MAX_TIME)
    def update_ip_set(self, log, scope, name, ip_set_arn, addresses):
        log.info("[waflib:update_ip_set] Start")
        if (ip_set_arn is None or name is None):
            log.error("No IPSet found for: %s ", str(ip_set_arn))
            return None

        try:
            # convert from arn to ip_set_id
            ip_set_id = self.arn_to_id(ip_set_arn)

            # retrieve the ipset to get a locktoken
            ip_set = self.get_ip_set(log, scope, name, ip_set_arn)
            lock_token = ip_set['LockToken']
            description = ip_set['IPSet']['Description']
            log.info("Updating IPSet with description: %s", str(description))

            response = client.update_ip_set(
                Scope=scope,
                Name=name,
                Description=description,
                Id=ip_set_id,
                Addresses=addresses,
                LockToken=lock_token
            )

            new_ip_set = self.get_ip_set(log, scope, name, ip_set_id)
            log.info("[waflib:update_ip_set] End")
            return new_ip_set
        except Exception as e:
            log.error(e)
            log.error("Failed to update IPSet: %s", str(ip_set_id))
            return None
            
    
    # Put Log Configuration for webacl
    @on_exception(expo, client.exceptions.WAFInternalErrorException, max_time=MAX_TIME)
    def put_logging_configuration(self, log, web_acl_arn, delivery_stream_arn):
        try:
            response = client.put_logging_configuration(
                LoggingConfiguration={
                    'ResourceArn': web_acl_arn,
                    'LogDestinationConfigs': [delivery_stream_arn]
                }
            )
            return response
        except Exception as e:
            log.error("Failed to configure log for WebAcl: %s", str(web_acl_arn))
            log.error(str(e))
            return None

    # Delete Log Configuration for webacl
    @on_exception(expo, client.exceptions.WAFInternalErrorException, max_time=MAX_TIME)
    def delete_logging_configuration(self, log, web_acl_arn):
        try:
            response = client.delete_logging_configuration(
                ResourceArn=web_acl_arn
            )
            return response
        except Exception as e:
            log.error("Failed to delete log for WebAcl: %s", str(web_acl_arn))
            log.error(str(e))
            return None

    # List webacls
    @on_exception(expo, client.exceptions.WAFInternalErrorException, max_time=MAX_TIME)
    def list_web_acls(self, log, scope):
        try:
            response = client.list_web_acls(
                Scope=scope
            )
            return response
        except Exception as e:
            log.error("Failed to list WebAcld in scope: %s", str(scope))
            log.error(str(e))
            return None
            

    #################################################################
    # Following functions only used for testing, not in WAF Solution
    #################################################################

    @on_exception(expo,
                  (client.exceptions.WAFInternalErrorException,
                   client.exceptions.WAFOptimisticLockException,
                   client.exceptions.WAFLimitsExceededException),
                  max_time=MAX_TIME)
    def create_ip_set(self, log, scope, name, description, version, addresses):
        try:
            response = client.create_ip_set(
                Scope=scope,
                Name=name,
                Description=description,
                IPAddressVersion=version,
                Addresses=addresses
            )
            return response
        except Exception as e:
            log.error("Failed to create IPSet: %s", str(name))
            log.error(str(e))
            return None

    @on_exception(expo,
                  (client.exceptions.WAFInternalErrorException,
                   client.exceptions.WAFOptimisticLockException,
                   client.exceptions.WAFAssociatedItemException),
                  max_time=MAX_TIME)
    def delete_ip_set(self, log, scope, name, ip_set_id):
        try:
            response = self.get_ip_set(log, scope, name, ip_set_id)          
            if response is not None:
                lock_token = response['LockToken']
                response = client.delete_ip_set(
                    Scope=scope,
                    Name=name,
                    LockToken=lock_token,
                    Id=ip_set_id
                )
            return response
        except Exception as e:
            log.error("Failed to delete IPSet: %s", str(name))
            log.error(str(e))
            return None

    @on_exception(expo, client.exceptions.WAFInternalErrorException, max_time=MAX_TIME)
    def list_ip_sets(self, log, scope, marker=None):
        try:
            response = None
            if marker == None:
                response = client.list_ip_sets(
                    Scope=scope,
                    Limit=50
                )
            else:
                response = client.list_ip_sets(
                    Scope=scope,
                    NextMarker=marker,
                    Limit=50
                )
            return response
        except Exception as e:
            log.error("Failed to list IPSets in scope: %s", str(scope))
            log.error(str(e))
            return None
