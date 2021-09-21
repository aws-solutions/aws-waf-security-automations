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
from os import environ
from botocore.config import Config
from lib.boto3_util import create_client

class SNS(object):
    def __init__(self, log):
        self.log = log
        self.sns_client = create_client('sns')

    def publish(self, topic_arn, message, subject):
        try:
            response = self.sns_client.publish(
                TopicArn=topic_arn,
                Message=message,
                Subject=subject
            )
            return response
        except Exception as e:
            self.log.error("[sns_util: publish] failed to send email notificaion: \nTopic Arn: %s\nMessage: %s", topic_arn, message)
            self.log.error(e)
            return None
