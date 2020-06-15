# Changelog
All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.1] - 2019-10-30
### Added
### Changed
- Fixed error handling of intermittent issue: (WAFStaleDataException) when calling the UpdateWebACL
- Upgrade from Node 8 to Node 10 for Lambda function
## [2.3.2] - 2020-02-05
### Added
### Changed
- Fixed README file to accurately reflect script params
- Upgraded from Python 3.7 to 3.8
- Changed RequestThreshold min limit from 2000 to 100
## [2.3.3] - 2020-06-15
### Added
- Implemented Athena optimization: added partitioning for CloudFront, ALB and WAF logs and Athena queries
### Changed
- Fixed potential DoS vector within Bad Bots X-Forward-For header
