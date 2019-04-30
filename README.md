# AWS WAF Security Automations
A solution that contains all AWS WAF samples developed so far - waf-reactive-blacklist, waf-bad-bot-blocking, waf-block-bad-behaving and waf-reputation-lists.

For the full solution overview visit [AWS WAF Security Automations](https://aws.amazon.com/answers/security/aws-waf-security-automations/).

## File Structure
This project consists of microservices that facilitate the functional areas of the solution. These microservices are deployed to a serverless environment in AWS Lambda.

```
|-deployment/ [folder containing templates and build scripts]
|-source/
  |-access-handler/ [microservice for processing bad bots honeypot endpoint access. This AWS Lambda function intercepts the suspicious request and adds the source IP address to the AWS WAF block list]
  |-custom-resource/ [custom helper for CloudFormation deployment template]
  |-helper/ [custom helper for CloudFormation deployment dependency check and auxiliary functions]
  |-log-parser/ [microservice for processing access logs searching for suspicious behavior and add the corresponding source IP addresses to an AWS WAF block list]
  |-reputation-lists-parser/ [microservice for processing third-party IP reputation lists and add malicious IP addresses to an AWS WAF block list]
```

## Getting Started

#### 01. Prerequisites
The following procedures assumes that all of the OS-level configuration has been completed. They are:

* [AWS Command Line Interface](https://aws.amazon.com/cli/)
* Node.js 8.x
* Python 3.x

The AWS WAF Security Automations solution is developed with Node.js and Python for the microservices that run in AWS Lambda. The latest version has been tested with Node.js v8.10 and Python v3.7.

#### 02. Clone AWS WAF Security Automations repository
Clone the aws-waf-security-automations GitHub repository:

```
git clone https://github.com/awslabs/aws-waf-security-automations.git
```

#### 03. Declare enviroment variables:
```
export AWS_REGION=<aws-region-code>
export VERSION_CODE=<version-code>
export DEPLOY_BUCKET=<source-bucket-base-name>
```
- **aws-region-code**: AWS region code. Ex: ```us-east-1```.
- **version-code**: version of the package. EX: ```v2.2```.
- **source-bucket-base-name**: Name for the S3 bucket location where the template will source the Lambda code from. The template will append ```-[aws-region-code]``` to this bucket name. For example: ```./build-s3-dist.sh solutions v2.2```, the template will then expect the source code to be located in the ```solutions-[aws-region-code]``` bucket.

#### 04. Build the AWS WAF Security Automations solution for deployment:
```
cd ./aws-waf-security-automations/deployment
chmod +x build-s3-dist.sh
./build-s3-dist.sh $DEPLOY_BUCKET $VERSION_CODE
```

#### 05. Upload deployment assets to your Amazon S3 bucket:
```
aws s3 cp ./dist s3://$DEPLOY_BUCKET-$AWS_REGION/aws-waf-security-automations/latest --recursive --acl bucket-owner-full-control
aws s3 cp ./dist s3://$DEPLOY_BUCKET-$AWS_REGION/aws-waf-security-automations/$VERSION_CODE --recursive --acl bucket-owner-full-control
```

#### 06. Deploy the AWS WAF Security Automations solution:
* From your designated Amazon S3 bucket where you uploaded the deployment assets, copy the link location for the aws-waf-security-automations.template.
* Using AWS CloudFormation, launch the AWS WAF Security Automations solution stack using the copied Amazon S3 link for the aws-waf-security-automations.template.

***

Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
