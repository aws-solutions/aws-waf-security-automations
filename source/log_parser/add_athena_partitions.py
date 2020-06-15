##############################################################################
#  Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.   #
#                                                                            #
#  Licensed under the Apache License, Version 2.0 (the "License").           #
#  You may not use this file except in compliance                            #
#  with the License. A copy of the License is located at                     #
#                                                                            #
#      http://www.apache.org/licenses/LICENSE-2.0                            #
#                                                                            #
#  or in the "license" file accompanying this file. This file is             #
#  distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY  #
#  KIND, express or implied. See the License for the specific language       #
#  governing permissions  and limitations under the License.                 #
##############################################################################

import datetime
import boto3
import re
import logging
from os import environ


def lambda_handler(event, context):
    """
    This function adds a new hourly partition to athena table.
    It runs every hour, triggered by a CloudWatch event rule.
    """
    log = logging.getLogger()
    log.debug('[add-athena-partition lambda_handler] Start')
    try:
        # ---------------------------------------------------------
        # Set Log Level
        # ---------------------------------------------------------
        log_level = str(environ['LOG_LEVEL'].upper())
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            log_level = 'ERROR'
        log.setLevel(log_level)

        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        log.info(event)

        athena_client = boto3.client('athena')
        database_name = event['glueAccessLogsDatabase']
        access_log_bucket = event['accessLogBucket']
        waf_log_bucket = event['wafLogBucket']
        athena_work_group = event['athenaWorkGroup']

        try:
            # Add athena partition for cloudfront or alb logs
            if len(access_log_bucket) > 0:
                execute_athena_query(log, access_log_bucket,
                                     database_name,
                                     event['glueAppAccessLogsTable'],
                                     athena_client,
                                     athena_work_group)
        except Exception as error:
            log.error('[add-athena-partition lambda_handler] App access log Athena query execution failed: %s'%str(error))

        try:
            # Add athena partition for waf logs
            if len(waf_log_bucket) > 0:
                execute_athena_query(log, waf_log_bucket,
                                     database_name,
                                     event['glueWafAccessLogsTable'],
                                     athena_client,
                                     athena_work_group)
        except Exception as error:
            log.error('[add-athena-partition lambda_handler] WAF access log Athena query execution failed: %s'%str(error))

    except Exception as error:
        log.error(str(error))
        raise

    log.debug('[add-athena-partition lambda_handler] End')


def build_athena_query(log, database_name, table_name):
    """
    This function dynamically builds the alter table athena query
    to add partition to athena table.

    Args:
        log: logging object
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name

    Returns:
        string. Athena query string
    """

    current_timestamp = datetime.datetime.utcnow()
    year = current_timestamp.year
    month = current_timestamp.month
    day = current_timestamp.day
    hour = current_timestamp.hour

    query_string = "ALTER TABLE " \
        + database_name + "." + table_name  \
        + "\nADD IF NOT EXISTS\n"  \
        "PARTITION (\n"  \
            "\tyear = " + str(year) + ",\n"  \
            "\tmonth = " + str(month).zfill(2) + ",\n"  \
            "\tday = " + str(day).zfill(2) + ",\n"  \
            "\thour = " + str(hour).zfill(2) + ");"

    log.debug(
        "[build_athena_query] Query string:\n%s\n"
        %query_string)

    return query_string


def execute_athena_query(log, log_bucket, database_name, table_name,
                         athena_client, athena_work_group):
    """
    This function executes the alter table athena query to
    add partition to athena table.

    Args:
        log: object. logging object
        log_bucket: s3 bucket for logs(cloudfront, alb or waf logs)
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name
        athena_client: object. Athena client object

    Returns:
        None
    """

    s3_output = "s3://%s/athena_results/"%log_bucket

    query_string = build_athena_query(log, database_name, table_name)

    log.info("[execute_athena_query] Query string:\n%s  \
              \nAthena S3 Output Bucket: %s\n"%(query_string, s3_output))

    response = athena_client.start_query_execution(
        QueryString=query_string,
        QueryExecutionContext={'Database': database_name},
        ResultConfiguration={'OutputLocation': s3_output,
                'EncryptionConfiguration': {
                    'EncryptionOption': 'SSE_S3'
                }
            },
        WorkGroup=athena_work_group
    )

    log.info("[execute_athena_query] Query execution response:\n%s"%response)
