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

import logging
from os import environ
from calendar import timegm
from datetime import datetime, timedelta
from lib.dynamodb_util import DDB

class SetIPRetention(object):
    """
    This class contains functions to put ip retention info into ddb table
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
       
    def get_expiration_time(self, time, ip_retention_period_minute):
        """
        Get ip expiration time which is the TTL used by ddb table to delete ip upon expiration
        """

        utc_start_time = datetime.strptime(time, "%Y-%m-%dT%H:%M:%SZ")
        utc_end_time = utc_start_time + timedelta(seconds=60*ip_retention_period_minute)
        epoch_time = timegm(utc_end_time.utctimetuple())
        return epoch_time

    def make_item(self, event):
        """
        Extract ip retention info from event to make ddb item
        """

        item = {}
        request_parameters = self.is_none(event.get('requestParameters', {}))
        
        ip_retention_period = int(environ.get('IP_RETENTION_PEROID_ALLOWED_MINUTE')) \
                              if self.is_none(str(request_parameters.get('name')).find('Whitelist')) != -1 \
                              else int(environ.get('IP_RETENTION_PEROID_DENIED_MINUTE'))

        # If retention period is not set, stop and return
        if ip_retention_period == -1:
            self.log.info("[set_ip_retention: make_item] IP retention is not set on {}. Stop processing." \
                        .format(self.is_none(str(request_parameters.get('name')))))
            return item

        # Set a minimum 15-minute retention period
        ip_retention_period = 15 if ip_retention_period in range(0, 15) else ip_retention_period
        
        item = {
            "IPSetId": self.is_none(str(request_parameters.get('id'))),
            "IPSetName": self.is_none(str(request_parameters.get('name'))),
            "Scope": self.is_none(str(request_parameters.get('scope'))),
            "IPAdressList": self.is_none(request_parameters.get('addresses',[])),
            "LockToken": self.is_none(str(request_parameters.get('lockToken'))),
            "IPRetentionPeriodMinute": ip_retention_period,
            "CreationTime": timegm(datetime.utcnow().utctimetuple()),
            "ExpirationTime": self.get_expiration_time(event.get('eventTime'), ip_retention_period),
            "CreatedByUser": environ.get('STACK_NAME')
        }
        return item
   
    def put_item(self, table_name):
        """
        Write item into ddb table
        """
        try:
            self.log.info("[set_ip_retention: put_item] Start")

            ddb = DDB(self.log, table_name)
            
            item = self.make_item(self.event)
            
            response = {}

            # put item if it is not empty
            if bool(item):
                response = ddb.put_item(item)
            
                self.log.info("[set_ip_retention: put_item] item: \n{}".format(item))
                self.log.info("[set_ip_retention: put_item] put_item response: \n{}:".format(response))

        except Exception as error:
            self.log.error(str(error))
            raise 
        
        self.log.info("[set_ip_retention:put_item] End")

        return response


def lambda_handler(event, context):
    """
    Invoke functions to put ip retentation info into ddb table. 
    It is triggered by a CloudWatch events rule.
    """
    
    log = logging.getLogger()
    
    try:
        # Set Log Level
        log_level = str(environ['LOG_LEVEL'].upper())
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            log_level = 'ERROR'
        log.setLevel(log_level)
        
        log.info('[set_ip_retention: lambda_handler] Start')
        log.info("Lambda Handler Event: \n{}".format(event))
        
        event_detail = event.get('detail',{})
        event_user_arn = event_detail.get('userIdentity',{}).get('arn')
        response = {}
        
        # If event for UpdateIPSet api call is not created by the RemoveExpiredIP lambda, continue to put item into DDB
        if event_user_arn.find(environ.get('REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME')) == -1:
            sipr = SetIPRetention(event_detail, log)
            response = sipr.put_item(environ.get('TABLE_NAME'))
        else:
            message = "The event for UpdateIPSet API call was made by RemoveExpiredIP lambda instead of user. Skip."
            log.info(message)
            response = {"Message": message}
    except Exception as error:
        log.error(str(error))
        raise
    
    log.info('[set_ip_retention: lambda_handler] End')
    return response
