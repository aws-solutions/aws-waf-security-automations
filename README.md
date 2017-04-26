# aws-waf-security-automations

The [AWS WAF Security Automations](https://aws.amazon.com/answers/security/aws-waf-security-automations/) is a simple AWS-provided solution that helps you provision the AWS WAF Security Automations stack without worrying about creating and configuring the underlying AWS infrastructure. WARNING: This template creates an AWS Lambda function, an AWS WAF Web ACL, an Amazon S3 bucket, and an Amazon CloudWatch custom metric. You will be billed for the AWS resources used if you create a stack from this template.

Source code for the AWS solution "WAS WAF Security Automations".

## Cloudformation templates

- cform/aws-waf-security-automations.template

## log-parser

- code/log-parser/log-parser.py

## reputation-lists-parser

- code/reputation-lists-parser/reputation-lists-parser.js

## access-handler

- code/access-handler/access-handler.py

## custom-resource

- code/custom-resource/custom-resource.py

***

Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
