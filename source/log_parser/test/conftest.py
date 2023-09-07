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

import boto3
import pytest
from os import environ
from moto import mock_s3, mock_glue, mock_athena, mock_wafv2


S3_BUCKET_NAME = "test_bucket"
GLUE_DATABASE_NAME = "test_database"
GLUE_TABLE_NAME = "test_table"
ATHENA_WORK_GROUP_NAME = "test_work_group"
ATHENA_QUERY_OUTPUT_LOCATION = "s3://%s/athena_results/" %S3_BUCKET_NAME
REGION = "us-east-1"

# local file paths
ATHENA_QUERY_RESULT_FILE_LOCAL_PATH = "./test/test_data/test_athena_query_result.csv"
CLOUDFRONT_LOG_FILE_LOCAL_PATH = "./test/test_data/E3HXCM7PFRG6HT.2023-04-24-21.d740d76bCloudFront.gz"
ALB_LOG_FILE_LOCAL_PATH = "./test/test_data/XXXXXXXXXXXX_elasticloadbalancing_us-east-1_app.ApplicationLoadBalancer.fa87e1db7badc175_20230424T2110Z_X.X.X.X_4c8scnzy.log.gz"
WAF_LOG_FILE_LOCAL_PATH = "./test/test_data/test_waf_log.gz"
APP_LOG_CONF_FILE_LOCAL_PATH = "./test/test_data/waf_stack-app_log_conf.json"
APP_LOG_OUTPUT_FILE_LOCAL_PATH = "./test/test_data/waf-stack-app_log_out.json"
WAF_LOG_CONF_FILE_LOCAL_PATH = "./test/test_data/waf_stack-waf_log_conf.json"
WAF_LOG_OUTPUT_FILE_LOCAL_PATH = "./test/test_data/waf_stack-waf_log_out.json"

# remote S3 file keys
ATHENA_QUERY_RESULT_FILE_S3_KEY = "athena_results/test_athena_query_result.csv"
CLOUDFRONT_LOG_FILE_S3_KEY = "AWSLogs/E3HXCM7PFRG6HT.2023-04-24-21.d740d76bCloudFront.gz"
ALB_LOG_FILE_S3_KEY = "AWSLogs/XXXXXXXXXXXX/elasticloadbalancing/us-east-1/2023/04/24/XXXXXXXXXXXX_elasticloadbalancing_us-east-1_app.ApplicationLoadBalancer.fa87e1db7badc175_20230424T2110Z_X.X.X.X_4c8scnzy.log.gz"
WAF_LOG_FILE_S3_KEY = "AWSLogs/test_waf_log.gz"
APP_LOG_CONF_FILE_S3_KEY = "waf_stack-app_log_conf.json"
APP_LOG_OUTPUT_FILE_S3_KEY = "waf-stack-app_log_out.json"
WAF_LOG_CONF_FILE_S3_KEY = "waf_stack-waf_log_conf.json"
WAF_LOG_OUTPUT_FILE_S3_KEY = "waf_stack-waf_log_out.json"

# values for triggering exception
NON_EXISTENT_WORK_GROUP = 'non_existent_work_group'


@pytest.fixture(scope='module', autouse=True)
def test_aws_credentials_setup():
    """Mocked AWS Credentials for moto"""
    environ['AWS_ACCESS_KEY_ID'] = 'testing'
    environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    environ['AWS_SECURITY_TOKEN'] = 'testing'
    environ['AWS_SESSION_TOKEN'] = 'testing'
    environ['AWS_DEFAULT_REGION'] = 'us-east-1'
    environ['AWS_REGION'] = 'us-east-1'


@pytest.fixture(scope='module', autouse=True)
def test_environment_vars_setup():
    """Athena Mock Client"""
    environ['WAF_BLOCK_PERIOD'] = '240'
    environ['ERROR_THRESHOLD'] = '100'
    environ['REQUEST_THRESHOLD'] = '100'
    environ['REQUEST_THRESHOLD_BY_COUNTRY'] = ''
    environ['HTTP_FLOOD_ATHENA_GROUP_BY'] = 'None'
    environ['ATHENA_QUERY_RUN_SCHEDULE'] = '5'
    environ['STACK_NAME'] = 'waf_stack'
    environ['METRIC_NAME_PREFIX'] = 'waf_stack'
    environ['MAX_AGE_TO_UPDATE'] = '30'
    environ['LOG_LEVEL'] = 'INFO'
    environ['SEND_ANONYMIZED_USAGE_DATA'] = 'Yes'
    environ['UUID'] = 'test_uuid'
    environ['SOLUTION_ID'] = 'SO0006'
    environ['METRICS_URL'] = 'https://testurl.com/generic'


@pytest.fixture(scope='module')
def s3_client():
    with mock_s3():
        connection = boto3.client("s3", region_name=REGION)
        yield connection


@pytest.fixture(scope='module')
def s3_resource():
    with mock_s3():
        connection = boto3.resource("s3", region_name=REGION)
        yield connection


@pytest.fixture(scope='module')
def glue_client():
    with mock_glue():
        connection = boto3.client("glue", region_name=REGION)
        yield connection


@pytest.fixture(scope='module')
def athena_client():
    """Athena Mock Client"""
    with mock_athena():
        connection = boto3.client("athena", region_name=REGION)
        yield connection


@pytest.fixture(scope='module', autouse=True)
def s3_resources_setup(s3_client):
    conn = s3_client
    conn.create_bucket(Bucket=S3_BUCKET_NAME)
    conn.upload_file(ATHENA_QUERY_RESULT_FILE_LOCAL_PATH, S3_BUCKET_NAME, ATHENA_QUERY_RESULT_FILE_S3_KEY)
    conn.upload_file(CLOUDFRONT_LOG_FILE_LOCAL_PATH, S3_BUCKET_NAME, CLOUDFRONT_LOG_FILE_S3_KEY)   
    conn.upload_file(ALB_LOG_FILE_LOCAL_PATH, S3_BUCKET_NAME, ALB_LOG_FILE_S3_KEY) 
    conn.upload_file(WAF_LOG_FILE_LOCAL_PATH, S3_BUCKET_NAME, WAF_LOG_FILE_S3_KEY) 
    conn.upload_file(APP_LOG_CONF_FILE_LOCAL_PATH, S3_BUCKET_NAME, APP_LOG_CONF_FILE_S3_KEY) 
    conn.upload_file(APP_LOG_OUTPUT_FILE_LOCAL_PATH, S3_BUCKET_NAME, APP_LOG_OUTPUT_FILE_S3_KEY) 
    conn.upload_file(WAF_LOG_CONF_FILE_LOCAL_PATH, S3_BUCKET_NAME, WAF_LOG_CONF_FILE_S3_KEY) 
    conn.upload_file(WAF_LOG_OUTPUT_FILE_LOCAL_PATH, S3_BUCKET_NAME, WAF_LOG_OUTPUT_FILE_S3_KEY) 
    

@pytest.fixture(scope='module', autouse=True)
def glue_resources_setup(glue_client):
    conn = glue_client
    conn.create_database(DatabaseInput={"Name": GLUE_DATABASE_NAME})
    conn.create_table(DatabaseName=GLUE_DATABASE_NAME, TableInput={"Name": GLUE_TABLE_NAME})


@pytest.fixture(scope='module', autouse=True)
def athena_resources_setup(athena_client):
    conn = athena_client
    conn.create_work_group(
        Name=ATHENA_WORK_GROUP_NAME,
        Configuration={
            'ResultConfiguration': {
                'OutputLocation': ATHENA_QUERY_OUTPUT_LOCATION
            }
        }
    )


@pytest.fixture(scope='function')
def app_log_athena_parser_test_event_setup():
     event = {
                "resourceType": "LambdaAthenaAppLogParser",
                "glueAccessLogsDatabase": GLUE_DATABASE_NAME,
                "accessLogBucket": S3_BUCKET_NAME,
                "glueAppAccessLogsTable": GLUE_TABLE_NAME,
                "athenaWorkGroup": ATHENA_WORK_GROUP_NAME
            }
     return event


@pytest.fixture(scope='function')
def waf_log_athena_parser_test_event_setup():
     event = {
                "resourceType": "LambdaAthenaWAFLogParser",
                "glueAccessLogsDatabase": GLUE_DATABASE_NAME,
                "accessLogBucket": S3_BUCKET_NAME,
                "glueWafAccessLogsTable": GLUE_TABLE_NAME,
                "athenaWorkGroup": ATHENA_WORK_GROUP_NAME
            }
     return event


@pytest.fixture(scope='function')
def app_log_athena_query_result_test_event_setup():
     environ['APP_ACCESS_LOG_BUCKET'] = S3_BUCKET_NAME
     event = {
                "Records": [{
                    "s3": {
                        "bucket": {
                            "name": S3_BUCKET_NAME
                        },
                        "object": {
                            "key": ATHENA_QUERY_RESULT_FILE_S3_KEY
                        }
                    }
                }]
            }
     return event


@pytest.fixture(scope='function')
def waf_log_athena_query_result_test_event_setup():
     environ['WAF_ACCESS_LOG_BUCKET'] = S3_BUCKET_NAME
     event = {
                "Records": [{
                    "s3": {
                        "bucket": {
                            "name": S3_BUCKET_NAME
                        },
                        "object": {
                            "key": ATHENA_QUERY_RESULT_FILE_S3_KEY
                        }
                    }
                }]
            }
     return event


@pytest.fixture(scope='function')
def cloudfront_log_lambda_parser_test_event_setup():
     environ['APP_ACCESS_LOG_BUCKET'] = S3_BUCKET_NAME
     event = {
                "Records": [{
                    "s3": {
                        "bucket": {
                            "name": S3_BUCKET_NAME
                        },
                        "object": {
                            "key": CLOUDFRONT_LOG_FILE_S3_KEY
                        }
                    }
                }]
            }
     return event


@pytest.fixture(scope='function')
def alb_log_lambda_parser_test_event_setup():
     environ['APP_ACCESS_LOG_BUCKET'] = S3_BUCKET_NAME
     environ['IP_SET_NAME_SCANNERS_PROBESV4'] = 'scanner_probes_ip_set_name_v4'
     environ['IP_SET_ID_SCANNERS_PROBESV4'] = 'scanner_probes_ip_set_id_v4'
     environ['IP_SET_NAME_SCANNERS_PROBESV6'] = 'scanner_probes_ip_set_name_v6'
     environ['IP_SET_ID_SCANNERS_PROBESV6'] = 'scanner_probes_ip_set_id_v6'
     event = {
                "Records": [{
                    "s3": {
                        "bucket": {
                            "name": S3_BUCKET_NAME
                        },
                        "object": {
                            "key": ALB_LOG_FILE_S3_KEY
                        }
                    }
                }]
            }
     return event


@pytest.fixture(scope='function')
def waf_log_lambda_parser_test_event_setup():
     environ['WAF_ACCESS_LOG_BUCKET'] = S3_BUCKET_NAME
     environ['IP_SET_NAME_HTTP_FLOODV4'] = 'http_flood_ip_set_name_v4'
     environ['IP_SET_ID_HTTP_FLOODV4'] = 'http_flood_ip_set_id_v4'
     environ['IP_SET_NAME_HTTP_FLOODV6'] = 'http_flood_ip_set_name_v6'
     environ['IP_SET_ID_HTTP_FLOODV6'] = 'http_flood_ip_set_id_v6'
     event = {
                "Records": [{
                    "s3": {
                        "bucket": {
                            "name": S3_BUCKET_NAME
                        },
                        "object": {
                            "key": WAF_LOG_FILE_S3_KEY
                        }
                    }
                }]
            }
     return event


@pytest.fixture(scope='function')
def athena_partitions_test_event_setup():
     event = {
                "accessLogBucket": S3_BUCKET_NAME,
                "wafLogBucket": S3_BUCKET_NAME,
                "glueAccessLogsDatabase": GLUE_DATABASE_NAME,
                "glueAppAccessLogsTable": GLUE_TABLE_NAME,
                "glueWafAccessLogsTable": GLUE_TABLE_NAME,
                "athenaWorkGroup": ATHENA_WORK_GROUP_NAME
            }
     return event


@pytest.fixture(scope='function')
def athena_partitions_non_existent_work_group_test_event_setup():
     event = {
                "accessLogBucket": S3_BUCKET_NAME,
                "wafLogBucket": S3_BUCKET_NAME,
                "glueAccessLogsDatabase": GLUE_DATABASE_NAME,
                "glueAppAccessLogsTable": GLUE_TABLE_NAME,
                "glueWafAccessLogsTable": GLUE_TABLE_NAME,
                "athenaWorkGroup": NON_EXISTENT_WORK_GROUP
            }
     return event


@pytest.fixture(scope='function')
def partition_s3_cloudfront_log_test_event_setup():
     environ['KEEP_ORIGINAL_DATA'] = 'No'
     environ['ENDPOINT'] = 'CloudFront'
     event = {
                "Records": [{
                    "s3": {
                        "bucket": {
                            "name": S3_BUCKET_NAME
                        },
                        "object": {
                            "key": CLOUDFRONT_LOG_FILE_S3_KEY
                        }
                    }
                }]
            }
     return event


@pytest.fixture(scope='function')
def partition_s3_alb_log_test_event_setup():
     environ['KEEP_ORIGINAL_DATA'] = 'No'
     environ['ENDPOINT'] = 'ALB'
     event = {
                "Records": [{
                    "s3": {
                        "bucket": {
                            "name": S3_BUCKET_NAME
                        },
                        "object": {
                            "key": ALB_LOG_FILE_S3_KEY
                        }
                    }
                }]
            }
     return event