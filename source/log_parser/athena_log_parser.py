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

import csv
import datetime
from os import environ, remove
from build_athena_queries import build_athena_query_for_app_access_logs, \
    build_athena_query_for_waf_logs
from lib.boto3_util import create_client
from lib.s3_util import S3
from lambda_log_parser import LambdaLogParser


class AthenaLogParser(object):
    """
    This class includes functions to process WAF and App access logs using Athena parser
    """

    def __init__(self, log):
        self.log = log
        self.s3_util = S3(log)
        self.lambda_log_parser = LambdaLogParser(log)


    def process_athena_scheduler_event(self, event):
        self.log.debug("[athena_log_parser: process_athena_scheduler_event] Start")

        log_type = str(environ['LOG_TYPE'].upper())

        # Execute athena query for CloudFront or ALB logs
        if event['resourceType'] == 'LambdaAthenaAppLogParser' \
                and (log_type == 'CLOUDFRONT' or log_type == 'ALB'):
            self.execute_athena_query(log_type, event)

        # Execute athena query for WAF logs
        if event['resourceType'] == 'LambdaAthenaWAFLogParser':
            self.execute_athena_query('WAF', event)

        self.log.debug("[athena_log_parser: process_athena_scheduler_event] End")


    def execute_athena_query(self, log_type, event):
        self.log.debug("[athena_log_parser: execute_athena_query] Start")

        athena_client = create_client('athena')
        s3_output = "s3://%s/athena_results/" % event['accessLogBucket']
        database_name = event['glueAccessLogsDatabase']

        # Dynamically build query string using partition
        # for CloudFront or ALB logs
        if log_type == 'CLOUDFRONT' or log_type == 'ALB':
            query_string = build_athena_query_for_app_access_logs(
                self.log,
                log_type,
                event['glueAccessLogsDatabase'],
                event['glueAppAccessLogsTable'],
                datetime.datetime.utcnow(),
                int(environ['WAF_BLOCK_PERIOD']),
                int(environ['ERROR_THRESHOLD'])
            )
        else:  # Dynamically build query string using partition for WAF logs
            query_string = build_athena_query_for_waf_logs(
                self.log,
                event['glueAccessLogsDatabase'],
                event['glueWafAccessLogsTable'],
                datetime.datetime.utcnow(),
                int(environ['WAF_BLOCK_PERIOD']),
                int(environ['REQUEST_THRESHOLD']),
                environ['REQUEST_THRESHOLD_BY_COUNTRY'],
                environ['HTTP_FLOOD_ATHENA_GROUP_BY'],
                int(environ['ATHENA_QUERY_RUN_SCHEDULE'])
            )

        response = athena_client.start_query_execution(
            QueryString=query_string,
            QueryExecutionContext={'Database': database_name},
            ResultConfiguration={
                'OutputLocation': s3_output,
                'EncryptionConfiguration': {
                    'EncryptionOption': 'SSE_S3'
                }
            },
            WorkGroup=event['athenaWorkGroup']
        )

        self.log.info("[athena_log_parser: execute_athena_query] Query Execution Response: {}".format(response))
        self.log.info("[athena_log_parser: execute_athena_query] End")


    def read_athena_result_file(self, local_file_path): 
        self.log.debug("[athena_log_parser: read_athena_result_file] Start")

        outstanding_requesters = {
            'general': {},
            'uriList': {}
        }
        utc_now_timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z%z")
        with open(local_file_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # max_counter_per_min is set as 1 just to reuse lambda log parser data structure
                # and reuse update_ip_set.
                outstanding_requesters['general'][row['client_ip']] = {
                    "max_counter_per_min": row['max_counter_per_min'],
                    "updated_at": utc_now_timestamp_str
                }
        remove(local_file_path)

        self.log.debug("[athena_log_parser: read_athena_result_file] local_file_path: %s",
                       local_file_path)
        self.log.debug("[athena_log_parser: read_athena_result_file] End")

        return outstanding_requesters


    def process_athena_result(self, bucket_name, key_name, ip_set_type):
        self.log.debug("[athena_log_parser: process_athena_result] Start")

        try:
            # --------------------------------------------------------------------------------------------------------------
            self.log.info("[athena_log_parser: process_athena_result] Download file from S3")
            # --------------------------------------------------------------------------------------------------------------
            local_file_path = '/tmp/' + key_name.split('/')[-1]
            self.s3_util.download_file_from_s3(bucket_name, key_name, local_file_path)

            # --------------------------------------------------------------------------------------------------------------
            self.log.info("[athena_log_parser: process_athena_result] Read file content")
            # --------------------------------------------------------------------------------------------------------------
            outstanding_requesters = self.read_athena_result_file(local_file_path)

            # --------------------------------------------------------------------------------------------------------------
            self.log.info("[athena_log_parser: process_athena_result] Update WAF IP Sets")
            # --------------------------------------------------------------------------------------------------------------
            self.lambda_log_parser.update_ip_set(ip_set_type, outstanding_requesters)

        except Exception as e:
            self.log.error("[athena_log_parser: process_athena_result] Error to read input file")
            self.log.error(e)

        self.log.debug("[athena_log_parser: process_athena_result] End")
