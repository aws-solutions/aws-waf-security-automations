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

from add_athena_partitions import lambda_handler

def test_add_athena_partitions(athena_partitions_test_event_setup):
    try: 
        event = athena_partitions_test_event_setup
        result = False
        lambda_handler(event, {})
        result = True
    except Exception:
        raise
    assert result == True


def test_add_athena_partitions(athena_partitions_non_existent_work_group_test_event_setup):
    try: 
        event = athena_partitions_non_existent_work_group_test_event_setup
        result = False
        lambda_handler(event, {})
        result = True
    except Exception:
        assert result == False
