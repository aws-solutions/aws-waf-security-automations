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

from custom_resource.custom_resource import lambda_handler

def test_set_cloud_watch_group_retention(configure_cloud_watch_group_retention_event, example_context, cloudwatch_client, successful_response):
    result = lambda_handler(configure_cloud_watch_group_retention_event,example_context)
    expected = successful_response
    assert result == expected

def test_generate_waf_log_parser_conf_create_event(generate_waf_log_parser_conf_create_event, example_context, wafv2_client, s3_bucket, s3_client, successful_response):
    result = lambda_handler(generate_waf_log_parser_conf_create_event, example_context)
    expected = successful_response
    assert result == expected

def test_generate_waf_log_parser_conf_create_event(generate_waf_log_parser_conf_update_event, example_context, wafv2_client, s3_bucket, s3_client, successful_response):
    result = lambda_handler(generate_waf_log_parser_conf_update_event, example_context)
    expected = successful_response
    assert result == expected

def test_generate_app_log_parser_conf_create_event(generate_app_log_parser_conf_create_event, example_context, wafv2_client, s3_bucket, s3_client, successful_response):
    result = lambda_handler(generate_app_log_parser_conf_create_event, example_context)
    expected = successful_response
    assert result == expected

def test_generate_app_log_parser_conf_update_event(generate_app_log_parser_conf_update_event, example_context, wafv2_client, s3_bucket, s3_client, successful_response):
    result = lambda_handler(generate_app_log_parser_conf_update_event, example_context)
    expected = successful_response
    assert result == expected

def test_configure_aws_waf_logs_create_event(configure_aws_waf_logs_create_event, example_context, wafv2_client, successful_response):
    result = lambda_handler(configure_aws_waf_logs_create_event, example_context)
    expected = successful_response
    assert result == expected

def test_configure_aws_waf_logs_update_event(configure_aws_waf_logs_update_event, example_context, wafv2_client, successful_response):
    result = lambda_handler(configure_aws_waf_logs_update_event, example_context)
    expected = successful_response
    assert result == expected
    
def test_configure_aws_waf_logs_update_event(configure_aws_waf_logs_delete_event, example_context, wafv2_client, successful_response):
    result = lambda_handler(configure_aws_waf_logs_delete_event, example_context)
    expected = successful_response
    assert result == expected

def test_configure_web_acl_delete(configure_web_acl_delete, example_context, successful_response):
    result = lambda_handler(configure_web_acl_delete, example_context)
    expected = successful_response
    assert result == expected

def test_configure_waf_log_bucket_create_event(configure_waf_log_bucket_create_event, example_context, s3_bucket, s3_client, successful_response):
    result = lambda_handler(configure_waf_log_bucket_create_event, example_context)
    expected = successful_response
    assert result == expected

def test_configure_waf_log_bucket_delete_event(configure_waf_log_bucket_delete_event, example_context, s3_bucket, s3_client, successful_response):
    result = lambda_handler(configure_waf_log_bucket_delete_event, example_context)
    expected = successful_response
    assert result == expected

def test_configure_app_access_log_bucket_create_event(configure_app_access_log_bucket_create_error_event, example_context, s3_bucket, s3_client, app_access_log_bucket_create_event_error_response):
    result = lambda_handler(configure_app_access_log_bucket_create_error_event, example_context)
    expected = app_access_log_bucket_create_event_error_response
    assert result == expected

def test_configure_app_access_log_bucket_delete_event(configure_app_access_log_bucket_delete_event, example_context, s3_bucket, s3_client, successful_response):
    result = lambda_handler(configure_app_access_log_bucket_delete_event, example_context)
    expected = successful_response
    assert result == expected