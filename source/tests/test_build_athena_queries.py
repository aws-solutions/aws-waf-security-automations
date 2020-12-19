############################################################################## 
# Copyright 2020 Amazon.com, Inc. and its affiliates. All Rights Reserved. 
#                                                                            #
#  Licensed under the Amazon Software License (the "License"). You may not   #
#  use this file except in compliance with the License. A copy of the        #
#  License is located at                                                     #
#                                                                            #
#      http://aws.amazon.com/asl/                                            #
#                                                                            #
#  or in the "license" file accompanying this file. This file is distributed #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,        #
#  express or implied. See the License for the specific language governing   #
#  permissions and limitations under the License.                            #
##############################################################################

import sys
import datetime
import logging
from log_parser import build_athena_queries, add_athena_partitions
from datetime import datetime
from freezegun import freeze_time

log_level = 'DEBUG'
logging.getLogger().setLevel(log_level)
log = logging.getLogger('test_build_athena_queries')
database_name = 'testdb'
table_name = 'testtable'
end_timestamp = datetime.strptime('May 7 2020  1:33PM', '%b %d %Y %I:%M%p')
waf_block_period = 240
error_threshold = 2000
request_threshold = 50
cloudfront_log_type = 'CLOUDFRONT'
alb_log_type = 'ALB'
waf_log_type = 'WAF'
log_bucket = 'LogBucket'


def test_build_athena_queries_for_cloudfront_logs():
    query_string = build_athena_queries.build_athena_query_for_app_access_logs(
        log, cloudfront_log_type, database_name, table_name,
        end_timestamp, waf_block_period, error_threshold)

    with open('../source/tests/cloudfront_logs_query.txt', 'r') as file:
        cloudfront_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == cloudfront_logs_query


def test_build_athena_queries_for_alb_logs():
    query_string = build_athena_queries.build_athena_query_for_app_access_logs(
        log, alb_log_type, database_name, table_name,
        end_timestamp, waf_block_period, error_threshold)

    with open('../source/tests/alb_logs_query.txt', 'r') as file:
        alb_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == alb_logs_query


def test_build_athena_queries_for_waf_logs():
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,
        end_timestamp, waf_block_period, request_threshold)

    with open('../source/tests/waf_logs_query.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == waf_logs_query


@freeze_time("2020-05-08 02:21:34", tz_offset=-4)
def test_add_athena_partitions_build_query_string():
    query_string = add_athena_partitions.build_athena_query(
        log, database_name, table_name)

    with open('../source/tests/athena_partitions_query.txt', 'r') as file:
        athena_partitions_query = file.read()
    assert type(query_string) is str
    assert query_string == athena_partitions_query
