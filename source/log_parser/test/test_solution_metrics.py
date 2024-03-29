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

from lib.solution_metrics import send_metrics


def test_send_solution_metrics():
    uuid = "waf_test_00001"
    solution_id = "waf_test"
    data = {
            "test_string1": "waf_test",
            "test_string2": "test_1"
           }
    url = "https://testurl.com/generic"
    response = send_metrics(data, uuid, solution_id, url)
    assert response is not None
