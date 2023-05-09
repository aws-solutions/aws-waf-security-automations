###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License, Version 2.0 (the "License").            #
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at                                        #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0                             #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permissions#
#  and limitations under the License.                                         #
###############################################################################

from os import environ
from partition_s3_logs import lambda_handler

def test_partition_s3_cloudfront_log(partition_s3_cloudfront_log_test_event_setup):
    try: 
        event = partition_s3_cloudfront_log_test_event_setup
        result = False
        lambda_handler(event, {})
        result = True
        environ.pop('KEEP_ORIGINAL_DATA')
        environ.pop('ENDPOINT')
    except Exception:
        raise
    assert result == True


def test_partition_s3_alb_log(partition_s3_alb_log_test_event_setup):
    try: 
        event = partition_s3_alb_log_test_event_setup
        result = False
        lambda_handler(event, {})
        result = True
        environ.pop('KEEP_ORIGINAL_DATA')
        environ.pop('ENDPOINT')
    except Exception:
        raise
    assert result == True