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

import botocore
import string
import random
import re
import uuid
from lib.s3_util import S3

WAF_FOR_CLOUDFRONT_EXCEPTION_MESSAGE = '''
    If you are capturing AWS WAF logs for a Amazon CloudFront 
    distribution, create the stack in US East (N. Virginia).'''
INVALID_FLOOD_THRESHOLD_MESSAGE = '''
    The minimum rate-based rule rate limit per 5 minute period is 100. 
    If need to use values below that, 
    please select AWS Lambda or Amazon Athena log parser.'''
EMPTY_S3_BUCKET_NAME_EXCEPTION_MESSAGE = '''
    Failed to configure access log bucket. Name cannot be empty!'''
ACCESS_ISSUE_S3_BUCKET_EXCEPTION_MESSAGE = '''
    Failed to access the existing bucket information. 
    Check if you own this bucket and if it has proper access policy.'''
INCORRECT_REGION_S3_LAMBDA_EXCEPTION_MESSAGE = '''
    Bucket located in a different region. S3 bucket and Log Parser Lambda
    (and therefore, your CloudFormation Stack) must be created in the same Region.'''

EMPTY_S3_BUCKET_NAME_EXCEPTION = Exception(EMPTY_S3_BUCKET_NAME_EXCEPTION_MESSAGE)
ACCESS_ISSUE_S3_BUCKET_EXCEPTION = Exception(ACCESS_ISSUE_S3_BUCKET_EXCEPTION_MESSAGE)
INCORRECT_REGION_S3_LAMBDA_EXCEPTION = Exception(INCORRECT_REGION_S3_LAMBDA_EXCEPTION_MESSAGE)
WAF_FOR_CLOUDFRONT_EXCEPTION = Exception(WAF_FOR_CLOUDFRONT_EXCEPTION_MESSAGE)
INVALID_FLOOD_THRESHOLD_EXCEPTION = Exception(INVALID_FLOOD_THRESHOLD_MESSAGE)

class StackRequirements:

    def __init__(self, log):
        self.log = log
        self.s3 = S3(log)


    # --------------------------------------------------------------------------
    # Delivery stream names acceptable characters are:
    #  - Lowercase letters
    #  - Numbers
    #  - Underscores
    # Also:
    #  - It must be between 1 and 32 characters long. Names longer than that
    #    break AWS::Athena::NamedQuery database parameter
    # --------------------------------------------------------------------------
    def create_db_name(self, event: dict, response_data: dict) -> None:
        suffix = self.generate_suffix().lower()
        stack_name = self.normalize_stack_name(event['ResourceProperties']['StackName'], suffix)

        # define database name
        database_name = suffix
        if len(stack_name) > 0:
            database_name = stack_name + '_' + suffix

        response_data['DatabaseName'] = database_name
        self.log.debug(f"DatabaseName: {response_data['DatabaseName']}")


    def create_uuid(self, response_data: dict) -> None:
        response_data['UUID'] = str(uuid.uuid4())
        self.log.debug(f"UUID: {response_data['UUID']}")


    # --------------------------------------------------------------------------
    # Delivery stream names acceptable characters are:
    #  - Uppercase and lowercase letters
    #  - Numbers
    #  - Underscores
    #  - Hyphens
    #  - Periods
    # Also:
    #  - It must be between 1 and 64 characters long
    #  - AWS WAF requires a name starting with the prefix "aws-waf-logs-"
    # --------------------------------------------------------------------------
    def create_delivery_stream_name(self, event: dict, response_data: dict) -> None:
        prefix = "aws-waf-logs-"
        suffix = self.generate_suffix()
        stack_name = event['ResourceProperties']['StackName']

        stack_name = stack_name.replace(" ", "_")

        # remove everything that is not [a-zA-Z0-9] or '_' and strip '_'
        # note: remove hypens and periods for convenience
        stack_name = re.sub(r'\W', '', stack_name).strip('_')

        delivery_stream_name = prefix + "_" + suffix
        if len(stack_name) > 0:
            max_len = 64 - len(prefix) - 1 - len(suffix)
            delivery_stream_name = prefix + stack_name[:max_len] + "_" + suffix

        response_data['DeliveryStreamName'] = delivery_stream_name
        self.log.debug(f"DeliveryStreamName: {response_data['DeliveryStreamName']}")


    def verify_requirements_and_dependencies(self, event: dict):
        if self.is_active_scanner_probes_protection(event):
            self.check_app_log_bucket(
                region=event['ResourceProperties']['Region'],
                bucket_name=event['ResourceProperties']['AppAccessLogBucket']
            )

        self.check_requirements(event['ResourceProperties'])


    def is_active_scanner_probes_protection(self, event: dict) -> bool:
         return event['ResourceProperties']['ProtectionActivatedScannersProbes'] == 'yes'


    # ======================================================================================================================
    # Configure Access Log Bucket
    # ======================================================================================================================
    # ----------------------------------------------------------------------------------------------------------------------
    # Check S3 bucket requirements. This function raises exception if:
    #
    # 01. A empty bucket name is used
    # 02. The bucket already exists and was created in a account that you cant access
    # 03. The bucket already exists and was created in a different region.
    #     You can't trigger log parser lambda function from another region.
    # ----------------------------------------------------------------------------------------------------------------------
    def check_app_log_bucket(self, region: str, bucket_name: str) -> None:
        self.log.info("[check_app_log_bucket] Start")

        if bucket_name.strip() == "":
            raise EMPTY_S3_BUCKET_NAME_EXCEPTION

        exists = self.verify_bucket_existence(bucket_name)
        
        if exists:
            self.verify_bucket_region(bucket_name, region)


    def verify_bucket_region(self, bucket_name: str, region: str) -> None:
        response = None
        try:
            response = self.s3.get_bucket_location(bucket_name)
        except Exception:
            raise ACCESS_ISSUE_S3_BUCKET_EXCEPTION

        if response['LocationConstraint'] == None:
            response['LocationConstraint'] = 'us-east-1'
        elif response['LocationConstraint'] == 'EU':
            response['LocationConstraint'] = 'eu-west-1'

        if response['LocationConstraint'] != region:
            raise INCORRECT_REGION_S3_LAMBDA_EXCEPTION


    def verify_bucket_existence(self, bucket_name: str) -> bool:
        try:
            self.s3.head_bucket(bucket_name)
            return True

        except botocore.exceptions.ClientError as e:
            # If a client error is thrown, then check that it was a 404 error.
            # If it was a 404 error, then the bucket does not exist.
            error_code = int(e.response['Error']['Code'])
            self.log.info(f"[check_app_log_bucket]error_code: {error_code}. Bucket {bucket_name} doesn't exist")
            if error_code == 404:
                return False


    def check_requirements(self, resource_properties: dict) -> None:
        self.log.debug("[check_requirements] Start")

        if self.is_waf_for_cloudfront(resource_properties):
            raise WAF_FOR_CLOUDFRONT_EXCEPTION

        if self.is_invalid_flood_threshold(resource_properties):
            raise INVALID_FLOOD_THRESHOLD_EXCEPTION
                
        self.log.debug("[check_requirements] End")


    def is_waf_for_cloudfront(self, resource_properties: dict) -> bool:
        return resource_properties['HttpFloodProtectionLogParserActivated'] == "yes" and \
            resource_properties['EndpointType'].lower() == 'cloudfront' and \
            resource_properties['Region'] != 'us-east-1'
    

    def is_invalid_flood_threshold(self, resource_properties: dict) -> bool:
        return resource_properties['HttpFloodProtectionRateBasedRuleActivated'] == "yes" and \
            int(resource_properties['RequestThreshold']) < 100
    

    def generate_suffix(self) -> str:
        return ''.join([ random.choice(string.ascii_letters + string.digits) for _ in range(6) ]) #NOSONAR short random hash to serve as good enough for a suffix


    def normalize_stack_name(self, stack_name, suffix) -> str:
        # remove spaces
        stack_name = stack_name.replace(" ", "_")

        # remove everything that is not [a-z0-9] or '_' and strip '_'
        stack_name = re.sub(r'\W', '', stack_name).strip('_').lower()

        # reduce to max_len (considering random sufix + '_')
        max_len = 32 - 1 - len(suffix)
        stack_name = stack_name[:max_len].strip('_')
        return stack_name