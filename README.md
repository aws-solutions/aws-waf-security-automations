# AWS WAF Security Automations
A solution that contains all AWS WAF samples developed so far - waf-reactive-blacklist, waf-bad-bot-blocking, waf-block-bad-behaving and waf-reputation-lists.

## Building Lambda Package
```bash
cd deployment
./build-s3-dist.sh 
```
Create a source-bucket-base-name  as the base name for the S3 bucket location from where the template will source the Lambda code. 
The template will append '-[region_name]' to the value of the BucketName parameter and expect the source code to be located in the [BucketName]-[region_name] bucket.
Enter value of bucket name (without -region_name suffix) in template parameter BucketName.

## CloudFormation Templates (in yaml & json formats):
Located in deployment. 

## Zipped up Lambda function:
Located in deployment/dist.

***

Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
