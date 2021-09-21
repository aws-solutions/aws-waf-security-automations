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
import logging
from time import sleep
from os import environ
from datetime import datetime
from boto3.dynamodb.types import TypeDeserializer
from lib.waflibv2 import WAFLIBv2
from lib.sns_util import SNS
from lib.solution_metrics import send_metrics


waflib = WAFLIBv2()

DELAY_BETWEEN_UPDATES = 5

class RemoveExpiredIP(object):
    """
    This class contains functions to delete expired ips from waf ip set
    """

    def __init__(self, event, log):
        """
        Class init function
        """

        self.event = event
        self.log = log
        self.log.debug(self.__class__.__name__ + " Class Event:\n{}".format(event))
        
    def is_none(self, value):
        """
        Return None (string type) if the value is NoneType
        """

        if value is None:
            return 'None'
        else:
            return value
       
    def is_ddb_stream_event(self, user_identity_record):
        """
        Verify if the event comes from dynamodb stream triggered by TTl expiration
        """
        
        is_ddb_stream_event = True if self.is_none(str(user_identity_record.get('principalId'))) == 'dynamodb.amazonaws.com' \
                                   and self.is_none(str(user_identity_record.get('type'))) == 'Service' \
                              else False
        return is_ddb_stream_event
        
    def deserialize_ddb_data(self, ddb_data):
        """
        Convert a DynamoDB item to a regular dictionary
        """
        
        deserializer = TypeDeserializer()
        deserialized_ddb_data = {k: deserializer.deserialize(v) for k, v in ddb_data.items()}
        return deserialized_ddb_data
        
    def get_ip_set(self, log, scope, name, ip_set_id):
        """
        Make waf api call to get the latest ip set information for the expired ip set in DDB stream event
        """
        
        log.info('[remove_expired_id: get_ip_set] Start')
        
        if ip_set_id is None or scope is None or name is None: 
            return None
        
        response = waflib.get_ip_set_by_id(log, scope, name, ip_set_id)
        
        log.info("[remove_expired_id: get_ip_set] get_ip_set response \n{}.".format(response))
        log.info('[remove_expired_id: get_ip_set] End')
        
        return response
        
    def make_ip_list(self, log, waf_ip_list, ddb_ip_list):
        """
        Make a new kept ip list that contains ips existing in waf_ip_list but not ddb_ip_list.
        """
        
        log.info('[remove_expired_id: make_ip_list] Start')
        
        remove_ip_list = []    
        keep_ip_list = []

        log.info('[remove_expired_id: make_ip_list] waf_ip_list:\n'+ str(waf_ip_list))
        log.info('[remove_expired_id: make_ip_list] ddb_ip_list:\n'+ str(ddb_ip_list))
        
        # Get ips that should be removed. They are in both waf_ip_list and ddb_ip_list.
        remove_ip_list = list(set(waf_ip_list) & set(ddb_ip_list))
        log.info('[remove_expired_id: make_ip_list] remove_ip_list:\n'+ str(remove_ip_list))
        
        # If no ips to be removed, return None - no need to update the ip set.
        if len(remove_ip_list) == 0:
            log.info('[remove_expired_id: make_ip_list] No IPs to remove. End')
            return [], []
            
        # Get ips that should be kept. They are in waf_ip_list but not ddb_ip_list.
        keep_ip_list = list(set(waf_ip_list) - set(ddb_ip_list))
        log.info('[remove_expired_id: make_ip_list] keep_ip_list:\n'+ str(keep_ip_list))

        log.info('[remove_expired_id: make_ip_list] End')
        
        return keep_ip_list, remove_ip_list

        
    def update_ip_set(self, log, scope, name, ip_set_id, keep_ip_list, lock_token, description):
        """
        Make a WAF update API call to remove expired ip addresses from WAF ip set.
        """
        
        log.info('[remove_expired_id: update_ip_set] Start')
        
        response = waflib.update_ip_set_by_id(log, scope, name, ip_set_id, keep_ip_list, lock_token, description)
        
        log.info("[remove_expired_id: update_ip_set] response \n{}.".format(response))
        
        # Sleep for a few seconds to mitigate AWS WAF Update API call throttling issue
        sleep(DELAY_BETWEEN_UPDATES)
        
        log.info('[remove_expired_id: update_ip_set] End')
        
        return response
        
    def send_notification(self, log, topic_arn, ip_set_name, ip_set_id, ip_retention_period, lambda_function_name):
        """
        Send email notification to user about the IP expiration
        """
        
        log.info('[remove_expired_id: send_notification] Start')
        
        notify = SNS(log)
        
        subject = "AWS WAF Security Automations - IP Expiration Notification"
        message = "You are receiving this email because you have configured IP retention in AWS WAF Security Automations. " \
                  "Expired IPs have been removed from the following IP set. For details, locate and view {} lambda logs using the " \
                  "timestamp below. \n\n" \
                  "IP set name: {}\n IP set id: {}\n IP retention period (minute): {}\n Region: {}\n UTC Time: {}" \
                  .format(lambda_function_name, ip_set_name, ip_set_id, ip_retention_period, environ.get('AWS_REGION'), \
                   datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
        
        log.info("Message: {}".format(message))
        
        response = notify.publish(topic_arn, message, subject)
        
        log.debug("[remove_expired_id: send_notification] sns publish response:\n{}".format(response))
        
        log.info('[remove_expired_id: send_notification] An email notfication about the IP Expiration has been successfully sent to the user. End.')
    
    def send_anonymous_usage_data(self, log, remove_ip_list, name):
        """
        Send anonymous solution metrics
        """
        if 'SEND_ANONYMOUS_USAGE_DATA' not in environ or environ.get('SEND_ANONYMOUS_USAGE_DATA').lower() != 'yes':
            return

        log.info("[remove_expired_ip: send_anonymous_usage_data] Start")

        # Get ip set category
        if 'Whitelist' in name:
            ip_set = 'Allowlist'
        elif 'Blacklist' in name:
            ip_set = 'Denylist'
        else:
            ip_set = 'AllowOrDenylist'
        
        usage_data = {
            "data_type": "remove_expired_ip_lambda",
            "number_of_removed_ips": len(remove_ip_list),
            "ip_set": ip_set,
            "lambda_invocation_count": 1,
            "sns_email_notification": environ.get('SNS_EMAIL'),
        }

        log.info("[remove_expired_ip: send_anonymous_usage_data] Send Data")

        response = send_metrics(data=usage_data)
        response_code = response.status_code
        log.info('[remove_expired_ip: send_anonymous_usage_data] Response Code: {}'.format(response_code))
        log.info("[remove_expired_ip: send_anonymous_usage_data] End")
    
def lambda_handler(event, context):
    """
    Invoke functions to delete expired ips from waf ip set. 
    It is triggered by TTL DynamoDB Stream.
    """
    
    log = logging.getLogger()
    
    try:
        # Set Log Level
        log_level = str(environ['LOG_LEVEL'].upper())
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            log_level = 'ERROR'
        log.setLevel(log_level)
    
        log.info('[remove_expired_id: lambda_handler] Start')
        log.info("Lambda Handler Event: \n{}".format(event))
        
        response = {}
                
        reip = RemoveExpiredIP(event, log)
        
        # Remove expired ips in the event records
        for record in event['Records']:
            is_ddb_stream_event = reip.is_ddb_stream_event(reip.is_none(record.get('userIdentity',{})))
            
            # Stop if the REMOVE event is not from DDB Stream triggered by DDB TTL
            if not(is_ddb_stream_event) or reip.is_none(record.get('eventName')) != 'REMOVE':
                log.info('[remove_expired_id: lambda_handler] The event is Not the IP removal event from DynamoDB Stream triggered by DynamoDB TTL. Skip. End.')
                return response
                
            ddb_ip_set = reip.is_none(record.get('dynamodb',{}).get('OldImage',{}))
            desiralized_ddb_ip_set = reip.deserialize_ddb_data(ddb_ip_set)
            scope = reip.is_none(str(desiralized_ddb_ip_set.get('Scope')))
            name = reip.is_none(str(desiralized_ddb_ip_set.get('IPSetName')))
            ip_set_id = reip.is_none(str(desiralized_ddb_ip_set.get('IPSetId')))
            ip_retention_period = reip.is_none(str(desiralized_ddb_ip_set.get('IPRetentionPeriodMinute')))
            waf_ip_set = reip.get_ip_set(log, scope, name, ip_set_id)
            description = reip.is_none(waf_ip_set.get('IPSet',{}).get('Description'))
            waf_ip_list = reip.is_none(waf_ip_set.get('IPSet',{}).get('Addresses',[]))
            ddb_ip_list = reip.is_none(desiralized_ddb_ip_set.get('IPAdressList', []))
            keep_ip_list, remove_ip_list = reip.make_ip_list(log, waf_ip_list, ddb_ip_list)
            
            # Stop if None - no need to update ip set
            if len(remove_ip_list) == 0:
                log.info('[remove_expired_id: lambda_handler] No IPs to remove. End.')
                return response

            lock_token = reip.is_none(str(waf_ip_set.get('LockToken')))
            
            response = reip.update_ip_set(log, scope, name, ip_set_id, keep_ip_list, lock_token, description)
            
            # Send email notification to user if sns email is configured and ip set is successfully updated 
            if (environ.get('SNS_EMAIL').lower() == 'yes' and response.get('ResponseMetadata',{}).get('HTTPStatusCode') == 200):
                response = reip.send_notification(log, environ.get('SNS_TOPIC_ARN'), name, ip_set_id, ip_retention_period, context.function_name)
        
            # send anonymous solution metrics
            reip.send_anonymous_usage_data(log, remove_ip_list, name)

    except Exception as error:
        log.error(str(error))
        raise
    
    log.info('[remove_expired_id: lambda_handler] End')
    return response
