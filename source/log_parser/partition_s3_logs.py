##############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.   #
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

import re
from os import environ
from lib.boto3_util import create_client
from lib.logging_util import set_log_level

def lambda_handler(event, _):
    """
    This function is triggered by S3 event to move log files
    (upon their arrival in s3) from their original location
    to a partitioned folder structure created per timestamps
    in file names, hence allowing the usage of partitioning
    within AWS Athena.

    Sample partitioned folder structure:
      AWSLogs-Partitioned/year=2020/month=04/day=09/hour=23/

    """
    log = set_log_level()
    log.debug('[partition_s3_logs lambda_handler] Start')
    try:
        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        log.info(event)
        
        keep_original_data = str(environ['KEEP_ORIGINAL_DATA'].upper())
        endpoint = str(environ['ENDPOINT'].upper())
        log.info("\n[partition_s3_logs lambda_handler] KEEP ORIGINAL DATA: %s; End POINT: %s."
                                 %(keep_original_data, endpoint))

        s3 = create_client('s3')

        count = 0
        
        # Iterate through all records in the event
        for record in event['Records']:
            # Get S3 bucket
            bucket = record['s3']['bucket']['name']

            # Get source S3 object key
            key = record['s3']['object']['key']

            # Get file name, which should be the last one in the string
            filename = ""
            number = len(key.split('/'))
            if number >= 1:
                number = number - 1
            filename = key.split('/')[number]

            if endpoint == 'CLOUDFRONT':
                dest = parse_cloudfront_logs(key, filename)
            else:  # ALB endpoint
                dest = parse_alb_logs(key, filename)
                
            source_path = bucket + '/' + key
            dest_path = bucket + '/' + dest
            
            # Copy S3 object to destination
            s3.copy_object(Bucket=bucket, Key=dest, CopySource=source_path)

            log.info("\n[partition_s3_logs lambda_handler] Copied file %s to destination %s"%(source_path, dest_path))
            
            # Only delete source S3 object from its original folder if keeping original data is no
            if keep_original_data == 'NO':
                s3.delete_object(Bucket=bucket, Key=key)
                log.info("\n[partition_s3_logs lambda_handler] Removed file %s"%source_path)
                
            count = count + 1
            
        log.info("\n[partition_s3_logs lambda_handler] Successfully partitioned %s file(s)."%(str(count)))

    except Exception as error:
        log.error(str(error))
        raise

    log.debug('[partition_s3_logs lambda_handler] End')


def parse_cloudfront_logs(key, filename):
    # Get year, month, day and hour
    time_stamp = re.search('(\\d{4})-(\\d{2})-(\\d{2})-(\\d{2})', key)
    year, month, day, hour = time_stamp.group(0).split('-')

    # Create destination path
    dest = 'AWSLogs-Partitioned/year={}/month={}/day={}/hour={}/{}' \
           .format(year, month, day, hour, filename)

    return dest


def parse_alb_logs(key, filename):
    # Get year, month and day
    time_stamp = re.search('(\\d{4})/(\\d{2})/(\\d{2})', key)
    year, month, day = time_stamp.group(0).split('/')

    # Get hour
    time_stamp = re.search('(\\d{8})T(\\d{2})', filename)
    hour = time_stamp.group(0).split('T')[1]

    # Create destination path
    dest = 'AWSLogs-Partitioned/year={}/month={}/day={}/hour={}/{}' \
           .format(year, month, day, hour, filename)

    return dest
