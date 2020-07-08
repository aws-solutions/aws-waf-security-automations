---
name: Bug report
about: Create a report to help us improve
title: ''
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior.

**Expected behavior**
A clear and concise description of what you expected to happen.

**Please complete the following information about the solution:**
- [ ] Version: [e.g. v1.0.0]

To get the version of the solution, you can look at the description of the created CloudFormation stack. For example, "_(SO0021) - Video On Demand workflow with AWS Step Functions, MediaConvert, MediaPackage, S3, CloudFront and DynamoDB. Version **v5.0.0**_". If the description does not contain the version information, you can look at the mappings section of the template:

```yaml
Mappings:
  SourceCode:
    General:
      S3Bucket: "solutions"
      KeyPrefix: "video-on-demand-on-aws/v5.0.0"
```

- [ ] Region: [e.g. us-east-1]
- [ ] Was the solution modified from the version published on this repository?
- [ ] If the answer to the previous question was yes, are the changes available on GitHub?
- [ ] Have you checked your [service quotas](https://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html) for the sevices this solution uses?
- [ ] Were there any errors in the CloudWatch Logs?

**Screenshots**
If applicable, add screenshots to help explain your problem (please **DO NOT include sensitive information**).

**Additional context**
Add any other context about the problem here.
