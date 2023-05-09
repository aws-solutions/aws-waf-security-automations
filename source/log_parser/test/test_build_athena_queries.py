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

import datetime
import logging
import build_athena_queries, add_athena_partitions
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
request_threshold_by_country = '{"TR":30,"CN":100,"SE":150}'
no_request_threshold_by_country = ''
group_by_country = 'country'
group_by_uri = 'uri'
group_by_country_uri = 'country and uri'
no_group_by = 'none'
athena_query_run_schedule = 5
cloudfront_log_type = 'CLOUDFRONT'
alb_log_type = 'ALB'
waf_log_type = 'WAF'
log_bucket = 'LogBucket'


def test_build_athena_queries_for_cloudfront_logs():
    query_string = build_athena_queries.build_athena_query_for_app_access_logs(
        log, cloudfront_log_type, database_name, table_name,
        end_timestamp, waf_block_period, error_threshold)

    with open('./test/test_data/cloudfront_logs_query.txt', 'r') as file:
        cloudfront_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == cloudfront_logs_query


def test_build_athena_queries_for_alb_logs():
    query_string = build_athena_queries.build_athena_query_for_app_access_logs(
        log, alb_log_type, database_name, table_name,
        end_timestamp, waf_block_period, error_threshold)

    with open('./test/test_data/alb_logs_query.txt', 'r') as file:
        alb_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == alb_logs_query


def test_build_athena_queries_for_waf_logs_one():
    # test original waf log query one - no group by; no threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, no_request_threshold_by_country, no_group_by,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_1.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == waf_logs_query

def test_build_athena_queries_for_waf_logs_two():
    # test waf log query two - group by country; no threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, no_request_threshold_by_country, group_by_country,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_2.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == waf_logs_query

def test_build_athena_queries_for_waf_logs_three():
    # test waf log query three - group by uri; no threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, no_request_threshold_by_country, group_by_uri,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_3.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == waf_logs_query

def test_build_athena_queries_for_waf_logs_four():
    # test waf log query four - group by country and uri; no threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, no_request_threshold_by_country, group_by_country_uri,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_4.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == waf_logs_query

def test_build_athena_queries_for_waf_logs_five():
    # test waf log query five - no group by; has threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, request_threshold_by_country, no_group_by,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_5.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == waf_logs_query

def test_build_athena_queries_for_waf_logs_six():
    # test waf log query six - group by country; has threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, request_threshold_by_country, group_by_country,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_5.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == waf_logs_query

def test_build_athena_queries_for_waf_logs_seven():
    # test waf log query seven - group by uri; has threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, request_threshold_by_country, group_by_uri,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_6.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == waf_logs_query

def test_build_athena_queries_for_waf_logs_eight():
    # test waf log query eight - group by country and uri; has threshold by country
    query_string = build_athena_queries.build_athena_query_for_waf_logs(
        log, database_name, table_name,end_timestamp, waf_block_period,
        request_threshold, request_threshold_by_country, group_by_country_uri,
        athena_query_run_schedule
        )

    with open('./test/test_data/waf_logs_query_6.txt', 'r') as file:
        waf_logs_query = file.read()
    assert type(query_string) is str
    assert query_string == waf_logs_query

@freeze_time("2020-05-08 02:21:34", tz_offset=-4)
def test_add_athena_partitions_build_query_string():
    query_string = add_athena_partitions.build_athena_query(
        log, database_name, table_name)

    with open('./test/test_data/athena_partitions_query.txt', 'r') as file:
        athena_partitions_query = file.read()
    assert type(query_string) is str
    assert query_string == athena_partitions_query
