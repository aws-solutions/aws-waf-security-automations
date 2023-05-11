######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
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

from helper.helper import lambda_handler

def test_check_requirements(check_requirements_event, example_context, successful_response):
    result = lambda_handler(check_requirements_event, example_context)
    expected = successful_response
    assert result == expected

def test_create_uuid(create_uuid_event, example_context, successful_response):
    result = lambda_handler(create_uuid_event, example_context)
    expected = successful_response
    assert result == expected

def test_create_delivery_stream_name_event(create_delivery_stream_name_event, example_context, successful_response):
    result = lambda_handler(create_delivery_stream_name_event, example_context)
    expected = successful_response
    assert result == expected

def test_create_db_name(create_db_name_event, example_context, successful_response):
    result = lambda_handler(create_db_name_event, example_context)
    expected = successful_response
    assert result == expected

def test_error(erroneous_check_requirements_event, example_context, error_response):
    result = lambda_handler(erroneous_check_requirements_event, example_context)
    expected = error_response
    assert result == expected
    