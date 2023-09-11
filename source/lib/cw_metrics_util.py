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

import datetime
from os import environ
from lib.boto3_util import create_client

class WAFCloudWatchMetrics(object):
    """
    This class creates a wrapper function for cloudwatch get_metric_statistics API
    and another function to add the waf cw metric statistics to the anonymized usage
    data that the solution collects
    """
    def __init__(self, log):
        self.log = log
        self.cw_client = create_client('cloudwatch')

    def get_cw_metric_statistics(self, metric_name, period_seconds, waf_rule,
                                namespace='AWS/WAFV2',
                                statistics=['Sum'], 
                                start_time=datetime.datetime.utcnow(),
                                end_time=datetime.datetime.utcnow(),
                                web_acl='STACK_NAME'):
        """
        Get a WAF CloudWatch metric given a WAF rule and metric name.
            Parameters:
                metric_name: string. The name of the metric. Optional.
                period_seconds: integer. The granularity, in seconds, of the returned data points.
                waf_rule: string. The name of the WAF rule.
                namespace: string. The namespace of the metric. Optional.
                statistics: list. The metric statistics, other than percentile. Optional.
                start_time: datetime. The time stamp that determines the first data point to return. Optional.
                end_time: datetime. The time stamp that determines the last data point to return. Optional.
                web_acl: string. The name of the WebACL. Optional

            Returns: Metric data points if any, or None
        """
        try:
            response = self.cw_client.get_metric_statistics(
                MetricName=metric_name,
                Namespace=namespace,
                Statistics=statistics,
                Period=period_seconds,
                StartTime=start_time - datetime.timedelta(seconds=period_seconds),
                EndTime=end_time,
                Dimensions=[
                    {
                        "Name": "Rule",
                        "Value": waf_rule
                    },
                    {
                        "Name": "WebACL",
                        "Value": environ.get(web_acl)
                    },
                    {
                        "Name": "Region",
                        "Value": environ.get('AWS_REGION')
                    }
                ]
            )
            self.log.debug("[cw_metrics_util: get_cw_metric_statistics] response:\n{}".format(response))
            return response if len(response['Datapoints']) > 0 else None
        except Exception as e:
            self.log.error("[cw_metrics_util: get_cw_metric_statistics] Failed to get metric %s.", metric_name)
            self.log.error(e)
            return None

    def add_waf_cw_metric_to_usage_data(self, metric_name, period_seconds, waf_rule,
                                        usage_data, usage_data_field_name, default_value):
        """
        Get the CloudWatch metric statistics given a WAF rule and metric name, and
        add it to the anonymized usage data collected by the solution.
            Parameters:
                metric_name: string. The name of the metric. Optional.
                period_seconds: integer. The granularity, in seconds, of the returned data points.
                waf_rule: string. The name of the WAF rule.
                usage_data: JSON. Anonymized customer usage data of the solution
                usage_data_field_name: string. The field name in the usage data whose value will be
                                       replaced by the waf cloudwatch metric (if any)
                default_value: number. The default value of the field in the usage data 

            Returns: JSON. usage data.
        """
        self.log.info("[cw_metrics_util: add_waf_cw_metric_to_usage_data] "
            + "Get metric %s for waf rule %s." %(metric_name, waf_rule))

        response = self.get_cw_metric_statistics(
            metric_name=metric_name,
            period_seconds=period_seconds,
            waf_rule=waf_rule
        )
        usage_data[usage_data_field_name] = \
            response['Datapoints'][0]['Sum'] if response is not None else default_value

        self.log.info("[cw_metrics_util: add_waf_cw_metric_to_usage_data] "
            + "%s  - rule %s: %s"%(metric_name, waf_rule, str(usage_data[usage_data_field_name])))

        return usage_data