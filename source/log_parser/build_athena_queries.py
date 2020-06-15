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


def build_athena_query_for_app_access_logs(
    log, log_type, database_name, table_name, end_timestamp,
        waf_block_period, error_threshold):
    """
    This function dynamically builds athena query
    for cloudfront logs by adding partition values:
    year, month, day, hour. It splits query into three
    parts, builds them one by one and then concatenate
    them together into one final query.

    Args:
        log: logging object
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name
        end_timestamp: datetime. The end time stamp of the logs being scanned
        waf_block_period: int. The period (in minutes) to block applicable IP addresses
        error_threshold: int. The maximum acceptable bad requests per minute per IP address

    Returns:
        Athena query string
    """
    log.info(
        '[build_athena_query_for_app_access_logs] Start')

    # ------------------------------------------------
    log.debug(
        "[build_athena_query_for_app_access_logs] \
            Get start and end time stamps")
    # ------------------------------------------------
    query_string = ""
    start_timestamp = end_timestamp - \
        datetime.timedelta(seconds=60*waf_block_period)
    log.info(
        "[build_athena_query_for_app_access_logs]  \
            start time: %s; end time: %s"
            %(start_timestamp, end_timestamp))

    # -------------------------------------------------
    log.debug(
        "[build_athena_query_for_app_access_logs]  \
            Build query")
    # --------------------------------------------------
    if log_type == 'CLOUDFRONT':
        query_string = build_athena_query_part_one_for_cloudfront_logs(
            log, database_name, table_name)
    else:  # ALB logs
        query_string = build_athena_query_part_one_for_alb_logs(
            log, database_name, table_name)
    query_string = query_string +  \
        build_athena_query_part_two_for_partition(
            log, start_timestamp, end_timestamp)
    query_string = query_string +  \
        build_athena_query_part_three_for_app_access_logs(
            log, error_threshold, start_timestamp, end_timestamp)

    log.info(
        "[build_athena_query_for_app_access_logs]  \
            Query string:\n %s"%query_string)

    log.info(
        '[build_athena_query_for_app_access_logs] End')

    return query_string


def build_athena_query_for_waf_logs(
    log, database_name, table_name, end_timestamp,
        waf_block_period, request_threshold):
    """
    This function dynamically builds athena query
    for cloudfront logs by adding partition values:
    year, month, day, hour. It splits query into three
    parts, builds them one by one and then concatenate
    them together into one final query.

    Args:
        log: logging object
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name
        end_timestamp: datetime. The end time stamp of the logs being scanned
        waf_block_period: int. The period (in minutes) to block applicable IP addresses
        request_threshold: int. The maximum acceptable bad requests per minute per IP address

    Returns:
        Athena query string
    """
    log.info(
        '[build_athena_query_for_waf_logs] Start')

    # ------------------------------------------------
    log.debug(
        "[build_athena_query_for_waf_logs] \
            Get start and end time stamps")
    # ------------------------------------------------
    query_string = ""
    start_timestamp = end_timestamp - \
        datetime.timedelta(seconds=60*waf_block_period)
    log.info(
        "[build_athena_query_for_waf_logs]  \
            start time: %s; end time: %s"
            %(start_timestamp, end_timestamp))

    # -------------------------------------------------
    log.debug(
        "[build_athena_query_for_waf_logs]  \
            Build query")
    # --------------------------------------------------
    query_string = build_athena_query_part_one_for_waf_logs(
        log, database_name, table_name)
    query_string = query_string +  \
        build_athena_query_part_two_for_partition(
            log, start_timestamp, end_timestamp)
    query_string = query_string +  \
        build_athena_query_part_three_for_waf_logs(
            log, request_threshold, start_timestamp, end_timestamp)

    log.info(
        "[build_athena_query_for_waf_logs]  \
            Query string:\n %s"%query_string)

    log.info(
        '[build_athena_query_for_waf_logs] End')

    return query_string


def build_athena_query_part_one_for_cloudfront_logs(
        log, database_name, table_name):
    """
    This function dynamically builds the first part
    of the athena query.

    Args:
        log: logging object
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name

    Returns:
        Athena query string
    """
    query_string = "SELECT\n" \
                        "\tclient_ip,\n" \
                        "\tMAX_BY(counter, counter) as max_counter_per_min\n"  \
                   " FROM (\n"  \
                      "\tWITH logs_with_concat_data AS (\n"  \
                        "\t\tSELECT\n"  \
                          "\t\t\trequestip as client_ip,\n"  \
                          "\t\t\tcast(status as varchar) as status,\n"  \
                          "\t\t\tparse_datetime( concat( concat( format_datetime(date, 'yyyy-MM-dd'), '-' ), time ), 'yyyy-MM-dd-HH:mm:ss') AS datetime\n"  \
                        "\t\tFROM\n" \
                        + "\t\t\t" \
                        + database_name + "." + table_name
    log.debug(
        "[build_athena_query_part_one_for_cloudfront_logs]  \
         Query string part One:\n %s"%query_string)
    return query_string


def build_athena_query_part_one_for_alb_logs(
        log, database_name, table_name):
    """
    This function dynamically builds the first part
    of the athena query.

    Args:
        log: logging object
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name

    Returns:
        Athena query string
    """
    query_string = "SELECT\n" \
                        "\tclient_ip,\n" \
                        "\tMAX_BY(counter, counter) as max_counter_per_min\n"  \
                   " FROM (\n"  \
                      "\tWITH logs_with_concat_data AS (\n"  \
                        "\t\tSELECT\n"  \
                          "\t\t\tclient_ip,\n"  \
                          "\t\t\ttarget_status_code AS status,\n"  \
                          "\t\t\tparse_datetime(time, 'yyyy-MM-dd''T''HH:mm:ss.SSSSSS''Z') AS datetime\n"  \
                        "\t\tFROM\n" \
                        + "\t\t\t" \
                        + database_name + "." + table_name
    log.debug(
        "[build_athena_query_part_one_for_alb_logs]  \
         Query string part One:\n %s"%query_string)
    return query_string


def build_athena_query_part_one_for_waf_logs(
        log, database_name, table_name):
    """
    This function dynamically builds the first part
    of the athena query.

    Args:
        log: logging object
        database_name: string. The Athena/Glue database name
        table_name: string. The Athena/Glue table name

    Returns:
        Athena query string
    """
    query_string = "SELECT\n" \
                        "\tclient_ip,\n" \
                        "\tMAX_BY(counter, counter) as max_counter_per_min\n"  \
                   " FROM (\n"  \
                      "\tWITH logs_with_concat_data AS (\n"  \
                        "\t\tSELECT\n"  \
                          "\t\t\thttprequest.clientip as client_ip,\n"  \
                          "\t\t\tfrom_unixtime(timestamp/1000) as datetime\n"  \
                        "\t\tFROM\n" \
                        + "\t\t\t" \
                        + database_name + "." + table_name
    log.debug(
        "[build_athena_query_part_one_for_waf_logs]  \
         Query string part One:\n %s"%query_string)
    return query_string


def build_athena_query_part_two_for_partition(
        log, start_timestamp, end_timestamp):
    """
    This function dynamically builds the second part
    of the athena query, where partition values are added.
    The query will only scan the logs in the partitions
    that are between start_timestamp and end_timestamp.

    Args:
        log: logging object
        start_timestamp: datetime. The start time stamp of the logs being scanned
        end_timestamp: datetime. The end time stamp of the logs being scanned

    Returns:
        Athena query string
    """
    start_year = start_timestamp.year
    start_month = start_timestamp.month
    start_day = start_timestamp.day
    start_hour = start_timestamp.hour
    end_year = end_timestamp.year
    end_month = end_timestamp.month
    end_day = end_timestamp.day
    end_hour = end_timestamp.hour

    # same day query filter!
    if (start_timestamp.date() == end_timestamp.date()):
        log.debug(
            "[build_athena_query_part_two_for_partition] \
            Same day query filter")
        query_string = "\n\t\tWHERE year = " + str(start_year) + "\n"  \
                       "\t\tAND month = " + str(start_month).zfill(2) + "\n"  \
                       "\t\tAND day = " + str(start_day).zfill(2) + "\n"  \
                       "\t\tAND hour between "  \
                       + str(start_hour).zfill(2) + " and " + str(end_hour).zfill(2)
    # different days - cross days query filter!
    elif (start_year == end_year):
        log.debug(
            "[build_athena_query_part_two_for_partition] \
             Different days - cross days query filter")
        if (start_month == end_month):  # year and month are the same, but days are different
            query_string = "\n\t\tWHERE year = " + str(start_year) + "\n"  \
                        "\t\tAND month = " + str(start_month).zfill(2) + "\n"  \
                        "\t\tAND (\n"  \
                        "\t\t\t(day = " + str(start_day).zfill(2) + " AND hour >= " + str(start_hour).zfill(2) + ")\n"  \
                        "\t\t\tOR (day = " + str(end_day).zfill(2) + " AND hour <= " + str(end_hour).zfill(2) + ")\n"  \
                        "\t\t)\n"
        else:  # years are the same, but months and days are different
            query_string = "\n\t\tWHERE year = " + str(start_year) + "\n"  \
                        "\t\tAND (\n"  \
                        "\t\t\t(month = " + str(start_month).zfill(2) + " AND day = " + str(start_day).zfill(2) + " AND hour >= " + str(start_hour).zfill(2) + ")\n"  \
                        "\t\t\tOR (month = " + str(end_month).zfill(2) + " AND day = " + str(end_day).zfill(2) + " AND hour <= " + str(end_hour).zfill(2) + ")\n"  \
                        "\t\t)\n"
    else:  # years are different
        log.debug(
            "[build_athena_query_part_two_for_partition] \
             Different years - cross years query filter")
        query_string = "\n\t\tWHERE (year = " + str(start_year) + "\n"  \
                    "\t\t\tAND month = " + str(start_month).zfill(2) + "\n"  \
                    "\t\t\tAND day = " + str(start_day).zfill(2) + "\n"  \
                    "\t\t\tAND hour >= " + str(start_hour).zfill(2) + ")\n"  \
                    "\t\tOR (year = " + str(end_year) + "\n"  \
                    "\t\t\tAND month = " + str(end_month).zfill(2) + "\n"  \
                    "\t\t\tAND day = " + str(end_day).zfill(2) + "\n"  \
                    "\t\t\tAND hour <= " + str(end_hour).zfill(2) + ")\n"  \

    log.debug(
        "[build_athena_query_part_two_for_partition]  \
         Query string part Two:\n %s"%query_string)
    return query_string


def build_athena_query_part_three_for_app_access_logs(
        log, error_threshold, start_timestamp, end_timestamp):
    """
    This function dynamically builds the third part
    of the athena query.

    Args:
        log: logging object
        error_threshold: int. The maximum acceptable bad requests per minute per IP address
        start_timestamp: datetime. The start time stamp of the logs being scanned
        end_timestamp: datetime. The end time stamp of the logs being scanned

    Returns:
        Athena query string
    """
    query_string = "\n\t)\n"  \
                   "\tSELECT\n"  \
                   "\t\tclient_ip,\n"  \
                   "\t\tCOUNT(*) as counter\n"  \
                   "\tFROM\n"  \
                   "\t\tlogs_with_concat_data\n"  \
                   "\tWHERE\n"  \
                   "\t\tdatetime > TIMESTAMP "  \
                   + "'" + str(start_timestamp)[0:19] + "'"\
                   "\n\t\tAND status = ANY (VALUES '400', '401', '403', '404', '405')\n"  \
                   "\tGROUP BY\n"  \
                   "\t\tclient_ip,\n"  \
                   "\t\tdate_trunc('minute', datetime)\n"  \
                   "\tHAVING\n"  \
                   "\t\tCOUNT(*) >= "  \
                   + str(error_threshold) + \
                   "\n) GROUP BY\n"  \
                   "\tclient_ip\n"  \
                   "ORDER BY\n" \
                   "\tmax_counter_per_min DESC\n" \
                   "LIMIT 10000;"
    log.debug(
        "[build_athena_query_part_three_for_app_access_logs]  \
        Query string part Three:\n %s"%query_string)
    return query_string


def build_athena_query_part_three_for_waf_logs(
        log, request_threshold, start_timestamp, end_timestamp):
    """
    This function dynamically builds the third part
    of the athena query.

    Args:
        log: logging object
        error_threshold: int. The maximum acceptable bad requests per minute per IP address
        start_timestamp: datetime. The start time stamp of the logs being scanned
        end_timestamp: datetime. The end time stamp of the logs being scanned

    Returns:
        Athena query string
    """
    request_threshold_calculated = request_threshold / 5
    query_string = "\n\t)\n"  \
                   "\tSELECT\n"  \
                   "\t\tclient_ip,\n"  \
                   "\t\tCOUNT(*) as counter\n"  \
                   "\tFROM\n"  \
                   "\t\tlogs_with_concat_data\n"  \
                   "\tWHERE\n"  \
                   "\t\tdatetime > TIMESTAMP "  \
                   + "'" + str(start_timestamp)[0:19] + "'"\
                   "\n\tGROUP BY\n"  \
                   "\t\tclient_ip,\n"  \
                   "\t\tdate_trunc('minute', datetime)\n"  \
                   "\tHAVING\n"  \
                   "\t\tCOUNT(*) >= "  \
                   + str(request_threshold_calculated) + \
                   "\n) GROUP BY\n"  \
                   "\tclient_ip\n"  \
                   "ORDER BY\n" \
                   "\tmax_counter_per_min DESC\n" \
                   "LIMIT 10000;"
    log.debug(
        "[build_athena_query_part_three_for_waf_logs]  \
        Query string part Three:\n %s"%query_string)
    return query_string
