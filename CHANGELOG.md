# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


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

### Patched

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

## [3.2] - 2021-09-22

### Added

- Added IP retention support on Allowed and Denied IP Sets

### Changed

- Bug fixes

## [3.1] - 2020-10-22

### Changed

- Replaced s3 path-style with virtual-hosted style
- Added partition variable to all ARNs
- Updated bug report

## [3.0] - 2020-07-08

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
