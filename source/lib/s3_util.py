######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
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
#!/bin/python

import json
from lib.boto3_util import create_client, create_resource

class S3(object):
    def __init__(self, log):
        self.log = log
        self.s3_client = create_client('s3')
        self.s3_resource = create_resource('s3')

    def read_json_config_file_from_s3(self, bucket_name, key_name):
        try:
            file_obj = self.s3_resource.Object(bucket_name, key_name)
            file_content = file_obj.get()['Body'].read()
            config = json.loads(file_content)
            return config
        except Exception as e:
            self.log.error("[s3_util: read_json_config_file_from_s3] Error to read config file %s from bucket %s."
                           %(key_name, bucket_name))
            self.log.error(e)
            raise e

    def download_file_from_s3(self, bucket_name, key_name, local_file_path):
        try:
            self.s3_client.download_file(bucket_name, key_name, local_file_path)
        except Exception as e:
            self.log.error("[s3_util: download_file_from_s3] Error to download file %s from bucket %s."
                           %(key_name, bucket_name))
            self.log.error(e)
            raise e

    def upload_file_to_s3(self, file_path, bucket_name, key_name, 
                          extra_args={'ContentType': "application/json"}):
        try:
            self.s3_client.upload_file(file_path, bucket_name, key_name, ExtraArgs=extra_args)
        except Exception as e:
            self.log.error("[s3_util: upload_file_to_s3] Error to upload file %s to bucket %s."
                           %(file_path, bucket_name))
            self.log.error(e)
            raise e
        
    def get_head_object(self, bucket_name, key_name):
        try:
            response = self.s3_client.head_object(Bucket=bucket_name, Key=key_name)
            return response
        except Exception:
            self.log.info("[s3_util: get_head_object] File %s not found in bucket %s." 
                           %(key_name, bucket_name))
            return None
    
    def create_bucket(self, bucket_name, acl, region):
        try:
            if region == 'us-east-1': #location constraint isn't required for us-east-1
                self.s3_client.create_bucket(Bucket=bucket_name, ACL=acl)
            else:
                self.s3_client.create_bucket(Bucket=bucket_name, ACL=acl, 
                                      CreateBucketConfiguration={'LocationConstraint': region})
        except Exception as e:
            self.log.error(
                "[s3_util: create_bucket] Error creating s3 bucket: %s for acl %s in region %s."
                %(bucket_name, acl, region))
            self.log.error(e)
            raise e
    
    def wait_bucket(self, bucket_name, waiter_name):
        waiter = self.s3_client.get_waiter(waiter_name)
        waiter.wait(Bucket=bucket_name)

    def put_bucket_encryption(self, bucket_name, server_side_encryption_conf):
        try:
            response = self.s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration=server_side_encryption_conf
            )
            self.log.info("[s3_util: put_bucket_encryption]response put_bucket_encryption: \n%s" % response)
            return response
        except Exception as e:
            self.log.error("[s3_util: put_bucket_encryption] Error updating bucket encryption: %s for server side encryption config: %s"
                        %(bucket_name, server_side_encryption_conf))
            self.log.error(e)
            raise e
    
    def put_public_access_block(self, bucket_name, public_access_block_conf):
        try:
            response = self.s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration=public_access_block_conf
            )
            self.log.info("[s3_util: put_public_access_block] response: \n%s" % response)
            return response
        except Exception as e:
            self.log.error("[s3_util: put_public_access_block] Error updating bucket: %s for public access block conf: %s "
                        %(bucket_name, public_access_block_conf))
            self.log.error(e)
            raise e
    
    def head_bucket(self, bucket_name):
        try:
            response = self.s3_client.head_bucket(Bucket=bucket_name)
            self.log.info("[s3_util: head_bucket] response: \n%s" % response)
        except Exception as e:
            error_code = int(e.response['Error']['Code'])
            self.log.debug("[s3_util: head_bucket]: Operation failed on bucket %s. error code: %s"
                           %(bucket_name, error_code))
            raise e
    
    def get_bucket_logging(self, bucket_name):
        try:
            response = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            self.log.info("[s3_util: get_bucket_logging] response: \n%s" % response)
            return response
        except Exception as e:
            self.log.error("[s3_util: get_bucket_logging] Error: %s"
                           %(bucket_name))
            self.log.error(e)
            raise e
    
    def put_bucket_logging(self, bucket_name, bucket_logging_status):
        try: 
            response = self.s3_client.put_bucket_logging(
                Bucket=bucket_name,
                BucketLoggingStatus=bucket_logging_status
            )
            self.log.info("[s3_util: put_bucket_logging] response: \n%s" % response)
            return response
        except Exception as e:
            self.log.error("[s3_util: put_bucket_logging] Error: %s for bucket logging status: %s"
                           %(bucket_name, bucket_logging_status))
            self.log.error(e)
            raise e
    
    def get_bucket_notification_configuration(self, bucket_name):
        try:
            response = self.s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
            self.log.info(
                "[s3_util: get_bucket_notification_configuration] response: \n%s" % response)
            return response
        except Exception as e:
            self.log.error("[s3_util: get_bucket_notification_configuration] Error: %s"
                           %(bucket_name))
            self.log.error(e)
            raise e
    
    def put_bucket_notification_configuration(self, bucket_name, new_conf):
        try:
            response = self.s3_client.put_bucket_notification_configuration(
                Bucket=bucket_name, 
                NotificationConfiguration=new_conf)
            self.log.info(
                "[s3_util: put_bucket_notification_configuration] response: \n%s" % response)
        except Exception as e:
            self.log.error(
                "[s3_util: put_bucket_notification_configuration] Error: %s" % bucket_name)
            self.log.error(e)
            raise e
    
    def get_bucket_location(self, bucket_name):
        try:
            response = self.s3_client.get_bucket_location(Bucket=bucket_name)
            self.log.info(
                "[s3_util: get_bucket_location] response: \n%s" % response)
            return response
        except Exception as e:
            self.log.error("[s3_util: get_bucket_location] Error: %s" % bucket_name)
            self.log.error(e)
            raise e

    def put_bucket_policy(self, bucket_name, bucket_policy):
        try:
            response = self.s3_client.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)
            self.log.info(f"s3_util: put_bucket_policy response: {response}")
            return response
        except Exception as e:
            self.log.error(f"[s3_util: put_bucket_policy] Error: bucket_name: {bucket_name} bucket_policy: {bucket_policy}")
            self.log.error(e)
            raise e