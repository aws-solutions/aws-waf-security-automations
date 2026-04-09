# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.1.3] - 2026-04-09

### Security

- Updated cryptography to version 46.0.7 to address [CVE-2026-26007](https://avd.aquasec.com/nvd/2026/cve-2026-26007/), [CVE-2026-34073](https://nvd.nist.gov/vuln/detail/CVE-2026-34073), and [CVE-2026-39892](https://avd.aquasec.com/nvd/cve-2026-39892)
- Updated werkzeug to version 3.1.6 to address [CVE-2026-27199](https://avd.aquasec.com/nvd/cve-2026-27199)
- Updated minimatch to version 3.1.5 to address [CVE-2026-26996](https://avd.aquasec.com/nvd/cve-2026-26996)
- Updated aws-cdk-lib to version 2.248.0 to address [CVE-2025-69873](https://avd.aquasec.com/nvd/cve-2025-69873), [CVE-2026-27903](https://nvd.nist.gov/vuln/detail/CVE-2026-27903), [CVE-2026-33532](https://nvd.nist.gov/vuln/detail/CVE-2026-33532), and [CVE-2026-33750](https://nvd.nist.gov/vuln/detail/CVE-2026-33750)
- Updated flatted to version 3.4.2 to address [CVE-2026-32141](https://avd.aquasec.com/nvd/cve-2026-32141) and [CVE-2026-33228](https://nvd.nist.gov/vuln/detail/CVE-2026-33228)
- Updated picomatch to versions 2.3.2 and 4.0.4 to address [CVE-2026-33671](https://nvd.nist.gov/vuln/detail/CVE-2026-33671) and [CVE-2026-33672](https://nvd.nist.gov/vuln/detail/CVE-2026-33672)
- Updated brace-expansion to versions 1.1.13 and 5.0.5 to address [CVE-2026-33750](https://nvd.nist.gov/vuln/detail/CVE-2026-33750)
- Updated requests to version 2.33.1 to address insecure temp file reuse in extract_zipped_paths()

## [4.1.2] - 2026-01-14

### Security

- Updated urllib3 to version 2.6.3 to address [CVE-2026-21441](https://avd.aquasec.com/nvd/cve-2026-21441)
- Updated werkzeug to version 3.1.5 to address [CVE-2026-21860](https://avd.aquasec.com/nvd/cve-2026-21860)

## [4.1.1] - 2025-12-29

### Security

- Updated urllib3 to version 2.6.1 to address [CVE-2025-66418](https://nvd.nist.gov/vuln/detail/CVE-2025-66418) and [CVE-2025-66471](https://nvd.nist.gov/vuln/detail/CVE-2025-66471)
- Updated js-yaml to version 4.1.1 to address [CVE-2025-64718](https://nvd.nist.gov/vuln/detail/CVE-2025-64718)
- Updated werkzeug to version 3.1.4 to address [CVE-2025-66221](https://nvd.nist.gov/vuln/detail/CVE-2025-66221)

## [4.1.0] - 2025-07-30

### Added

- Added CDK support
- Added WAF rate based rule parameters in HTTP Flood Custom Rule
- Added lambda power tools for tracing and logging

### Changed

- Updated the poetry version
- Updated dependencies to address jinja2 [CVE-2024-56201](https://nvd.nist.gov/vuln/detail/CVE-2024-56201)
- Updated dependencies: botocore, boto3, responses, coverage, certifi, charset-normalizer, pluggy, s3transfer, typing-extensions, pytest-mock, freezegun, urllib3
- Updated dependencies to address cryptography [CVE-2024-12797](https://nvd.nist.gov/vuln/detail/CVE-2024-12797)
- Updated dependency version of requests [CVE-2024-47081](https://nvd.nist.gov/vuln/detail/CVE-2024-47081)
- Updated deployment scripts based on CDK changes
- Updated datetime deprecated method for utcnow() to now(datetime.UTC)
- Updated bad bot component behavior with improved log parsing support and detection logic
- Updated waflib api, remove redundant calls
- Updated temporary folders restrictions
- Changed metrics collection services

### Fixed

- Fixed invalid CRON expression [Github issue 261](https://github.com/aws-solutions/aws-waf-security-automations/issues/261)
- Fixed Honeypot detecting IP address with CloudFront [Github issue 250](https://github.com/aws-solutions/aws-waf-security-automations/issues/250)
- Fixed CloudFormation Drift for WebACL nested stack  [Github issue 257](https://github.com/aws-solutions/aws-waf-security-automations/issues/257)

### Removed

- Removed old stack templates
- Removed access handler and Amazon API Gateway resources
- Removed http request based approach for IP detection and added WAF log based analysis to find ip for bad bot
- Removed Service Catalog AppRegistry integration

## [4.0.6] - 2024-12-17

### Changed

- Update the lambda to python 3.12

### Fixed

- Added a check for payload for logging before sanitizing and logging  [Github issue 274](https://github.com/aws-solutions/aws-waf-security-automations/issues/274)

## [4.0.5] - 2024-10-24

### Changed

- Add poetry.lock to pin dependency versions for Python code
- Adapt build scripts to use Poetry for dependency management
- Replace native Python logger with aws_lambda_powertools logger

## [4.0.4] - 2024-09-23

### Fixed

- Patched dependency version of `requests` to `2.32.3` to mitigate [CVE-2024-3651](https://nvd.nist.gov/vuln/detail/CVE-2024-3651)
- Pinned all dependencies to specific versions for reproducable builds and enable security scanning
- Allow to install latest version of `urllib3` as transitive dependency

## [4.0.3] - 2023-10-25

### Fixed

- Patched urllib3 vulnerability as it is possible for a user to specify a Cookie header and unknowingly leak information via HTTP redirects to a different origin if that user doesn't disable redirects explicitly. For more details: [CVE-2023-43804](https://nvd.nist.gov/vuln/detail/CVE-2023-43804)

## [4.0.2] - 2023-09-11

### Fixed

- Update trademarked name. From aws-waf-security-automations.zip to security-automations-for-aws-waf.zip
- Refactor to reduce code complexity
- Patched requests package vulnerability leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint. For more details: [CVE-2023-32681](https://nvd.nist.gov/vuln/detail/CVE-2023-32681) [Github issue 248](https://github.com/aws-solutions/aws-waf-security-automations/issues/248)

## [4.0.1] - 2023-05-19

### Fixed

- Updated gitignore files to resolve the issue for missing files [Github issue 244](https://github.com/aws-solutions/aws-waf-security-automations/issues/244) [Github issue 243](https://github.com/aws-solutions/aws-waf-security-automations/issues/243) [Github issue 245](https://github.com/aws-solutions/aws-waf-security-automations/issues)

## [4.0.0] - 2023-05-11

### Added

- Added support for 10 new AWS Managed Rules rule groups (AMR)
- Added support for country and URI configurations in HTTP Flood Athena log parser
- Added support for user-defined S3 prefix for application access log bucket
- Added support for CloudWatch log retention period configuration
- Added support for multiple solution deployments in the same account and region
- Added support for exporting CloudFormation stack output values
- Replaced the hard coded amazonaws.com with {AWS::URLSuffix} in BadBotHoneypot API endpoint

### Fixed

- Avoid account-wide API Gateway logging setting change by deleting the solution stack [GitHub issue 213](https://github.com/aws-solutions/aws-waf-security-automations/issues/213)
- Avoid creating a new logging bucket for an existing app access log bucket that already has logging enabled

## [3.2.5] - 2023-04-18

### Fixed

- Patch s3 logging bucket settings
- Updated the timeout for requests

## [3.2.4] - 2023-02-06

### Changed

- Upgraded pytest to mitigate CVE-2022-42969
- Upgraded requests and subsequently certifi to mitigate CVE-2022-23491

## [3.2.3] - 2022-12-13

### Changed

- Add region as prefix to application attribute group name to avoid conflict with name starting with AWS.

## [3.2.2] - 2022-12-05

### Added

- Added AppRegistry integration

## [3.2.1] - 2022-08-30

### Added

- Added support for configuring oversize handling for requests components
- Added support for configuring sensitivity level for SQL injection rule

## [3.2.0] - 2021-09-22

### Added

- Added IP retention support on Allowed and Denied IP Sets

### Changed

- Bug fixes

## [3.1.0] - 2020-10-22

### Changed

- Replaced s3 path-style with virtual-hosted style
- Added partition variable to all ARNs
- Updated bug report

## [3.0.0] - 2020-07-08

### Added

- Added an option to deploy AWS Managed Rules for WebACL on installation

### Changed

- Upgraded from WAF classic to WAFV2 API
- Eliminated dependency on NodeJS and use Python as the standardized programming language

## [2.3.3] - 2020-06-15

### Added

- Implemented Athena optimization: added partitioning for CloudFront, ALB and WAF logs and Athena queries

### Changed

- Fixed potential DoS vector within Bad Bots X-Forward-For header

## [2.3.2] - 2020-02-05

### Added

### Changed

- Fixed README file to accurately reflect script params
- Upgraded from Python 3.7 to 3.8
- Changed RequestThreshold min limit from 2000 to 100

## [2.3.1] - 2019-10-30

### Added

### Changed

- Fixed error handling of intermittent issue: (WAFStaleDataException) when calling the UpdateWebACL
- Upgrade from Node 8 to Node 10 for Lambda function
