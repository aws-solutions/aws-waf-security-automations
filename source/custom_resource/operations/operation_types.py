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

# list of operation names as constants
SET_CLOUDWATCH_LOGGROUP_RETENTION = "Custom::SetCloudWatchLogGroupRetention"
CONFIG_APP_ACCESS_LOG_BUCKET = "Custom::ConfigureAppAccessLogBucket"
CONFIG_WAF_LOG_BUCKET = "Custom::ConfigureWafLogBucket"
CONFIG_WEB_ACL = "Custom::ConfigureWebAcl"
CONFIG_AWS_WAF_LOGS = "Custom::ConfigureAWSWAFLogs"
GENERATE_APP_LOG_PARSER_CONF_FILE = "Custom::GenerateAppLogParserConfFile"
GENERATE_WAF_LOG_PARSER_CONF_FILE = "Custom::GenerateWafLogParserConfFile"
ADD_ATHENA_PARTITIONS = "Custom::AddAthenaPartitions"

CREATE = "Create"
UPDATE = "Update"
DELETE = "Delete"


# additional constants
RESOURCE_PROPERTIES = "ResourceProperties"
REQUEST_TYPE = "RequestType"
RESOURCE_TYPE = "ResourceType"