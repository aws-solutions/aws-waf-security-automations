###############################################################################
#  Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
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

import os
import requests
from json import dumps
from datetime import datetime


def send_metrics(data,
                 uuid=os.getenv('UUID'),
                 solution_id=os.getenv('SOLUTION_ID'),
                 url=os.getenv('METRICS_URL')):
    """Sends anonymous customer metrics to s3 via API gateway owned and
        managed by the Solutions Builder team.

    Args:
        data - anonymous customer metrics to be sent
        uuid - uuid of the solution
        solution_id: unique id of the solution
        url: url for API Gateway via which data is sent

    Return: status code returned by https post request
    """
    try:
        metrics_data = {
            "Solution": solution_id,
            "UUID": uuid,
            "TimeStamp": str(datetime.utcnow().isoformat()),
            "Data": data
            }
        json_data = dumps(metrics_data)
        headers = {'content-type': 'application/json'}
        response = requests.post(url, data=json_data, headers=headers)
        return response
    except:
        pass
