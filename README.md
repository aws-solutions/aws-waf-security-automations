# AWS WAF Security Automations
A solution that contains all AWS WAF samples developed so far - waf-reactive-blacklist, waf-bad-bot-blocking, waf-block-bad-behaving and waf-reputation-lists.

For the full solution overview visit [AWS WAF Security Automations](https://aws.amazon.com/answers/security/aws-waf-security-automations/).

## File Structure
This project consists of microservices that facilitate the functional areas of the solution. These microservices are deployed to a serverless environment in AWS Lambda.

```
|-deployment/ [folder containing templates and build scripts]
|-source/
  |-access_handler/ [microservice for processing bad bots honeypot endpoint access. This AWS Lambda function intercepts the suspicious request and adds the source IP address to the AWS WAF block list]
  |-custom_resource/ [custom helper for CloudFormation deployment template]
  |-helper/ [custom helper for CloudFormation deployment dependency check and auxiliary functions]
  |-lib/ [library files including waf api calls and other common functions used in the solution]
  |-log_parser/ [microservice for processing access logs searching for suspicious behavior and add the corresponding source IP addresses to an AWS WAF block list]
  |-reputation_lists_parser/ [microservice for processing third-party IP reputation lists and add malicious IP addresses to an AWS WAF block list]
  |-tests/ [unit tests]
  |-timer/ [creates a sleep function for cloudformation to pace the creation of ip_sets]
```

## Getting Started

#### 01. Prerequisites
The following procedures assumes that all of the OS-level configuration has been completed. They are:

* [AWS Command Line Interface](https://aws.amazon.com/cli/)
* Python 3.8

The AWS WAF Security Automations solution is developed with Python for the microservices that run in AWS Lambda. The latest version has been tested with Python v3.8.

#### 02. Clone AWS WAF Security Automations repository
Clone the aws-waf-security-automations GitHub repository:

```
git clone https://github.com/awslabs/aws-waf-security-automations.git
```

#### 03. Run unit tests
Next, run unit tests to make sure added customization passes the tests

``` 
cd ./deployment 
chmod +x ./run-unit-tests.sh
./run-unit-tests.sh
``` 

#### 04. Declare enviroment variables:
```
export TEMPLATE_OUTPUT_BUCKET=<YOUR_TEMPLATE_OUTPUT_BUCKET> # Name for the S3 bucket where the template will be located
export DIST_OUTPUT_BUCKET=<YOUR_DIST_OUTPUT_BUCKET> # Name for the S3 bucket where customized code will reside 
export SOLUTION_NAME="aws-waf-security-automations" # name of the solution 
export VERSION=<VERSION> # version number for the customized code
export AWS_REGION=<AWS_REGION> # region where the distributable is deployed
```
#### _Note:_ You must manually create two buckets in S3 called $TEMPLATE_OUTPUT_BUCKET and $DIST_OUTPUT_BUCKET-$AWS_REGION to copy the distribution. The assets in bucket should be publicly accessible. The build-s3-dist.sh script DOES NOT do this and the CloudFormation template expects/references the REGION specific bucket.

#### 05. Build the AWS WAF Security Automations solution for deployment:
```
chmod +x ./build-s3-dist.sh && ./build-s3-dist.sh $TEMPLATE_OUTPUT_BUCKET $DIST_OUTPUT_BUCKET $SOLUTION_NAME $VERSION
```
#### 06. Upload deployment assets to your Amazon S3 buckets:
```
aws s3 cp ./deployment/global-s3-assets s3://$TEMPLATE_OUTPUT_BUCKET/aws-waf-security-automations/$VERSION --recursive --acl bucket-owner-full-control
aws s3 cp ./deployment/regional-s3-assets s3://$DIST_OUTPUT_BUCKET-$AWS_REGION/aws-waf-security-automations/$VERSION --recursive --acl bucket-owner-full-control
```
#### _Note:_ You must use proper acl and profile for the copy operation as applicable.

#### 07. Deploy the AWS WAF Security Automations solution:
* From your designated Amazon S3 bucket where you uploaded the deployment assets, copy the link location for the aws-waf-security-automations.template.
* Using AWS CloudFormation, launch the AWS WAF Security Automations solution stack using the copied Amazon S3 link for the aws-waf-security-automations.template.

***

Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
