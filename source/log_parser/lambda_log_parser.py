######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
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

import gzip
import json
import datetime
import os
from os import remove
from time import sleep
from urllib.parse import urlparse
from lib.waflibv2 import WAFLIBv2
from lib.s3_util import S3

TMP_DIR = '/tmp/' #NOSONAR tmp use for an insensitive workspace
FORMAT_DATE_TIME = "%Y-%m-%d %H:%M:%S %Z%z"

class LambdaLogParser(object):
    """
    This class includes functions to process WAF and App access logs using Lambda parser
    """

    def __init__(self, log):
        self.log = log
        self.config = {}
        self.delay_between_updates = 5
        self.scope = os.getenv('SCOPE')
        self.scanners = 1
        self.flood = 2
        self.s3_util = S3(log)
        self.waflib = WAFLIBv2()

        # CloudFront Access Logs
        # http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html#BasicDistributionFileFormat
        self.line_format_cloud_front = {
            'delimiter': '\t',
            'date': 0,
            'time': 1,
            'source_ip': 4,
            'uri': 7,
            'code': 8
        }

        # ALB Access Logs
        # http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
        self.line_format_alb = {
            'delimiter': ' ',
            'timestamp': 1,
            'source_ip': 3,
            'code': 9,  # GitHub issue #44. Changed from elb_status_code to target_status_code.
            'uri': 13
        }


    def read_waf_log_file(self, line): 
        line = line.decode()  # Remove the b in front of each field
        line_data = json.loads(str(line))

        request_key = datetime.datetime.fromtimestamp(int(line_data['timestamp']) / 1000.0).isoformat(
            sep='T', timespec='minutes')
        request_key += ' ' + line_data['httpRequest']['clientIp']
        uri = urlparse(line_data['httpRequest']['uri']).path

        return  request_key, uri, line_data
    

    def read_alb_log_file(self, line): 
        line_data = line.split(self.line_format_alb['delimiter'])
        request_key = line_data[self.line_format_alb['timestamp']].rsplit(':', 1)[0]
        request_key += ' ' + line_data[self.line_format_alb['source_ip']].rsplit(':', 1)[0]
        return_code_index = self.line_format_alb['code']
        uri = urlparse(line_data[self.line_format_alb['uri']]).path

        return  request_key, uri, return_code_index, line_data


    def read_cloudfront_log_file(self, line): 
        line_data = line.split(self.line_format_cloud_front['delimiter'])
        request_key = line_data[self.line_format_cloud_front['date']]
        request_key += ' ' + line_data[self.line_format_cloud_front['time']][:-3]
        request_key += ' ' + line_data[self.line_format_cloud_front['source_ip']]
        return_code_index = self.line_format_cloud_front['code']
        uri = urlparse(line_data[self.line_format_cloud_front['uri']]).path

        return  request_key, uri, return_code_index, line_data


    def update_threshold_counter(self, request_key, uri, return_code_index, line_data, counter): 
        if return_code_index == None or line_data[return_code_index] in self.config['general']['errorCodes']:
            counter['general'][request_key] = counter['general'][request_key] + 1 \
                if request_key in counter['general'].keys() else 1

            if 'uriList' in self.config and uri in self.config['uriList'].keys():
                if uri not in counter['uriList'].keys():
                    counter['uriList'][uri] = {}

                counter['uriList'][uri][request_key] = counter['uriList'][uri][request_key] + 1 \
                    if request_key in counter['uriList'][uri].keys() else 1

        return counter


    def read_log_file(self, local_file_path, log_type, error_count): 
        counter = {
            'general': {},
            'uriList': {}
        }
        outstanding_requesters = {
            'general': {},
            'uriList': {}
        }

        with gzip.open(local_file_path, 'r') as content:
            for line in content:
                try:  
                    oreq = self.read_contents(line, log_type, outstanding_requesters, counter)
                    if oreq: 
                        return oreq

                except Exception as e:
                    error_count += 1
                    self.log.error("[lambda_log_parser: get_outstanding_requesters] Error to process line: %s" % line)
                    self.log.error(str(e))
                    if error_count == 5:  #Allow 5 errors before stopping the function execution
                        raise
        remove(local_file_path)
        return counter, outstanding_requesters


    def read_contents(self, line, log_type, outstanding_requesters, counter):
        request_key = ""
        uri = ""
        return_code_index = None

        if log_type == 'waf':
            request_key, uri, line_data = self.read_waf_log_file(line)
        elif log_type == 'alb':
            line = line.decode('utf8')
            if line.startswith('#'):
                return
            request_key, uri, return_code_index, line_data = \
                self.read_alb_log_file(line)
        elif log_type == 'cloudfront':
            line = line.decode('utf8')
            if line.startswith('#'):
                return
            request_key, uri, return_code_index, line_data = \
                self.read_cloudfront_log_file(line)
        else:
            return outstanding_requesters
        
        if 'ignoredSufixes' in self.config['general'] and uri.endswith(
                tuple(self.config['general']['ignoredSufixes'])):
            self.log.debug(
                "[lambda_log_parser: get_outstanding_requesters] Skipping line %s. Included in ignoredSufixes." % line)
            return

        counter = self.update_threshold_counter(request_key, uri, return_code_index, line_data, counter)
    

    def parse_log_file(self, bucket_name, key_name, log_type):
        self.log.debug("[lambda_log_parser: parse_log_file] Start")

        # --------------------------------------------------------------------------------------------------------------
        self.log.info("[lambda_log_parser: parse_log_file] Download file from S3")
        # --------------------------------------------------------------------------------------------------------------
        local_file_path = TMP_DIR + key_name.split('/')[-1]
        self.s3_util.download_file_from_s3(bucket_name, key_name, local_file_path)

        # --------------------------------------------------------------------------------------------------------------
        self.log.info("[lambda_log_parser: parse_log_file] Read file content")
        # --------------------------------------------------------------------------------------------------------------
        error_count = 0
        counter, outstanding_requesters = self.read_log_file(local_file_path, log_type, error_count)

        return counter, outstanding_requesters


    def get_general_outstanding_requesters(self, counter, outstanding_requesters,
                                           threshold, utc_now_timestamp_str):
        for k, num_reqs in counter['general'].items():
            try:
                k = k.split(' ')[-1]
                if num_reqs >= self.config['general'][threshold]:
                    if k not in outstanding_requesters['general'].keys() or num_reqs > \
                            outstanding_requesters['general'][k]['max_counter_per_min']:
                        outstanding_requesters['general'][k] = {
                            'max_counter_per_min': num_reqs,
                            'updated_at': utc_now_timestamp_str
                        }
            except Exception:
                self.log.error(
                    "[lambda_log_parser: get_general_outstanding_requesters] \
                    Error to process general outstanding requester: %s" % k)

        return outstanding_requesters


    def get_urilist_outstanding_requesters(self, counter, outstanding_requesters,
                                           threshold, utc_now_timestamp_str):
        for uri in counter['uriList'].keys():
            for k, num_reqs in counter['uriList'][uri].items():
                try:
                    self.populate_urilist_outstanding_requesters(
                        k, num_reqs, uri, threshold, outstanding_requesters, utc_now_timestamp_str)
                except Exception:
                    self.log.error(
                        "[lambda_log_parser: get_urilist_outstanding_requesters] \
                        Error to process outstanding requester:(%s) %s" % (uri, k))

        return outstanding_requesters
    

    def populate_urilist_outstanding_requesters(self, k, num_reqs, uri, threshold, outstanding_requesters, utc_now_timestamp_str):
        k = k.split(' ')[-1]
        if num_reqs >= self.config['uriList'][uri][threshold]:
            if uri not in outstanding_requesters['uriList'].keys():
                outstanding_requesters['uriList'][uri] = {}

            if k not in outstanding_requesters['uriList'][uri].keys() or num_reqs > \
                    outstanding_requesters['uriList'][uri][k]['max_counter_per_min']:
                outstanding_requesters['uriList'][uri][k] = {
                    'max_counter_per_min': num_reqs,
                    'updated_at': utc_now_timestamp_str
                }
 

    def get_outstanding_requesters(self, log_type, counter, outstanding_requesters):
        self.log.debug("[lambda_log_parser: get_outstanding_requesters] Start")

        # --------------------------------------------------------------------------------------------------------------
        self.log.info("[lambda_log_parser: get_outstanding_requesters] Keep only outstanding requesters")
        # --------------------------------------------------------------------------------------------------------------
        threshold = 'requestThreshold' if log_type == 'waf' else "errorThreshold"
        utc_now_timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime(FORMAT_DATE_TIME)
        outstanding_requesters = self.get_general_outstanding_requesters(
            counter, outstanding_requesters,threshold, utc_now_timestamp_str)
        outstanding_requesters = self.get_urilist_outstanding_requesters(
            counter, outstanding_requesters, threshold, utc_now_timestamp_str)

        self.log.debug("[lambda_log_parser: get_outstanding_requesters] End")
        return outstanding_requesters
    

    def calculate_last_update_age(self, response):
        utc_last_modified = response['LastModified'].astimezone(datetime.timezone.utc)
        utc_now_timestamp = datetime.datetime.now(datetime.timezone.utc)
        utc_now_timestamp_str = utc_now_timestamp.strftime(FORMAT_DATE_TIME)
        last_update_age = int(((utc_now_timestamp - utc_last_modified).total_seconds()) / 60)

        return utc_now_timestamp, utc_now_timestamp_str, last_update_age


    def get_current_blocked_ips(self, bucket_name, key_name, output_key_name):
        local_file_path = TMP_DIR + key_name.split('/')[-1] + '_REMOTE.json'
        self.s3_util.download_file_from_s3(bucket_name, output_key_name, local_file_path)

        remote_outstanding_requesters = {
            'general': {},
            'uriList': {}
        }

        with open(local_file_path, 'r') as file_content:
            remote_outstanding_requesters = json.loads(file_content.read())
        remove(local_file_path)

        return remote_outstanding_requesters


    def iterate_general_list_for_existing_ip(self, k, v, outstanding_requesters, utc_now_timestamp_str):
        self.log.info(
            "[lambda_log_parser: iterate_general_list_for_existing_ip] \
            Updating general data of BLOCK %s rule" % k)
 
        outstanding_requesters['general'][k]['updated_at'] = utc_now_timestamp_str
        if v['max_counter_per_min'] > outstanding_requesters['general'][k]['max_counter_per_min']:
            outstanding_requesters['general'][k]['max_counter_per_min'] = v['max_counter_per_min']

        return outstanding_requesters    


    def iterate_general_list_for_new_ip(self, k, v, threshold, outstanding_requesters,
                                        utc_now_timestamp, force_update):
        utc_prev_updated_at = datetime.datetime.strptime(v['updated_at'],
            FORMAT_DATE_TIME).astimezone(datetime.timezone.utc)
        total_diff_min = ((utc_now_timestamp - utc_prev_updated_at).total_seconds()) / 60

        if v['max_counter_per_min'] < self.config['general'][threshold]:
            force_update = True
            self.log.info(
                "[lambda_log_parser: merge_general_outstanding_requesters] \
                %s is bellow the current general threshold" % k)

        elif total_diff_min < self.config['general']['blockPeriod']:
            self.log.debug("[merge_general_outstanding_requesters] Keeping %s in general" % k)
            outstanding_requesters['general'][k] = v

        else:
            force_update = True
            self.log.info("[lambda_log_parser: merge_general_outstanding_requesters] \
                          %s expired in general" % k)

        return outstanding_requesters, force_update 


    def merge_general_outstanding_requesters(self, threshold, remote_outstanding_requesters,
                                             outstanding_requesters, utc_now_timestamp_str,
                                             utc_now_timestamp, force_update):
        try:
            for k, v in remote_outstanding_requesters['general'].items():
                try:
                    if k in outstanding_requesters['general'].keys():
                        self.iterate_general_list_for_existing_ip(
                            k, v, outstanding_requesters, utc_now_timestamp_str)
    
                    else:
                        remote_outstanding_requesters, force_update = \
                        self.iterate_general_list_for_new_ip(
                            k, v, threshold, outstanding_requesters, utc_now_timestamp, force_update)

                except Exception as e:
                    self.log.error("[lambda_log_parser: merge_outstanding_requesters] Error merging general %s rule" % k)
                    self.log.error(str(e))
        except Exception as e:
            self.log.error("[lambda_log_parser: merge_outstanding_requesters] Failed to process general group.")
            self.log.error(str(e))
        
        return remote_outstanding_requesters, force_update


    def iterate_urilist_for_existing_uri(self, uri, k, v, outstanding_requesters, utc_now_timestamp_str):
        self.log.info(
            "[lambda_log_parser: iterate_urilist_for_existing_uri] \
            Updating uriList (%s) data of BLOCK %s rule" % (uri, k))

        outstanding_requesters['uriList'][uri][k]['updated_at'] = utc_now_timestamp_str
        if v['max_counter_per_min'] > outstanding_requesters['uriList'][uri][k]['max_counter_per_min']:
            outstanding_requesters['uriList'][uri][k]['max_counter_per_min'] = v['max_counter_per_min']

        return outstanding_requesters
    

    def iterate_urilist_for_new_uri(self, uri, k, v, threshold, utc_now_timestamp,
                                         outstanding_requesters, force_update):
        utc_prev_updated_at = datetime.datetime.strptime(
            v['updated_at'], FORMAT_DATE_TIME).astimezone(datetime.timezone.utc)
        total_diff_min = ((utc_now_timestamp - utc_prev_updated_at).total_seconds()) / 60

        if v['max_counter_per_min'] < self.config['uriList'][uri][threshold]:
            force_update = True
            self.log.info(
                "[lambda_log_parser: iterate_urilist_for_new_uri] \
                %s is bellow the current uriList (%s) threshold" % (
                k, uri))

        elif total_diff_min < self.config['general']['blockPeriod']:
            self.log.debug(
                "[lambda_log_parser: iterate_urilist_for_new_uri] \
                Keeping %s in uriList (%s)" % (k, uri))

            if uri not in outstanding_requesters['uriList'].keys():
                outstanding_requesters['uriList'][uri] = {}

            outstanding_requesters['uriList'][uri][k] = v

        else:
            force_update = True
            self.log.info(
                "[lambda_log_parser: iterate_urilist_for_new_uri] \
                %s expired in uriList (%s)" % (k, uri))
                                
        return outstanding_requesters, force_update


    def iterate_urilist(self, uri, threshold, remote_outstanding_requesters, outstanding_requesters,
                        utc_now_timestamp_str, utc_now_timestamp, force_update):
        for k, v in remote_outstanding_requesters['uriList'][uri].items():
            try:
                if uri in outstanding_requesters['uriList'].keys() and k in \
                        outstanding_requesters['uriList'][uri].keys():

                    outstanding_requesters = self.iterate_urilist_for_existing_uri(
                        uri, k, v, outstanding_requesters, utc_now_timestamp_str)

                else:
                    outstanding_requesters, force_update = self.iterate_urilist_for_new_uri(
                        uri, k, v, threshold, utc_now_timestamp,
                        outstanding_requesters, force_update)

            except Exception:
                self.log.error(
                    "[lambda_log_parser: iterate_urilist] Error merging uriList (%s) %s rule" % (uri, k))
                
            return outstanding_requesters, force_update
    
    
    def merge_urilist_outstanding_requesters(self, threshold, remote_outstanding_requesters, outstanding_requesters,
                                             utc_now_timestamp_str, utc_now_timestamp, force_update):
        try:
            if 'uriList' not in self.config or len(self.config['uriList']) == 0:
                force_update = True
                self.log.info(
                    "[lambda_log_parser: merge_urilist_outstanding_requesters] Current config file does not contain uriList anymore")
            else:
                for uri in remote_outstanding_requesters['uriList'].keys():
                    if 'ignoredSufixes' in self.config['general'] and uri.endswith(
                            tuple(self.config['general']['ignoredSufixes'])):
                        force_update = True
                        self.log.info(
                            "[lambda_log_parser: merge_urilist_outstanding_requesters] %s is in current ignored suffixes list." % uri)
                        continue

                    outstanding_requesters, force_update = self.iterate_urilist(
                        uri, threshold, remote_outstanding_requesters, outstanding_requesters,
                        utc_now_timestamp_str, utc_now_timestamp, force_update)
        except Exception:
            self.log.error("[lambda_log_parser: merge_outstanding_requesters] Failed to process uriList group.")
        
        return outstanding_requesters, force_update


    def merge_outstanding_requesters(self, bucket_name, key_name, log_type, output_key_name, outstanding_requesters):
        self.log.debug("[lambda_log_parser: merge_outstanding_requesters] Start")

        force_update = False
        need_update = False

        # Get metadata of object key_name
        response = self.s3_util.get_head_object(bucket_name, output_key_name)
        if response is None:
            self.log.info("[lambda_log_parser: merge_outstanding_requesters] No file to be merged.")
            need_update = True
            return outstanding_requesters, need_update

        # --------------------------------------------------------------------------------------------------------------
        self.log.info("[lambda_log_parser: merge_outstanding_requesters] Calculate Last Update Age")
        # --------------------------------------------------------------------------------------------------------------
        utc_now_timestamp, utc_now_timestamp_str, last_update_age = self.calculate_last_update_age(response)
 
        # --------------------------------------------------------------------------------------------------------------
        self.log.info("[lambda_log_parser: merge_outstanding_requesters] Download current blocked IPs")
        # --------------------------------------------------------------------------------------------------------------
        remote_outstanding_requesters = self.get_current_blocked_ips(bucket_name, key_name, output_key_name)

        # ----------------------------------------------------------------------------------------------------------
        self.log.info("[lambda_log_parser: merge_outstanding_requesters] Process outstanding requesters files")
        # ----------------------------------------------------------------------------------------------------------
        threshold = 'requestThreshold' if log_type == 'waf' else "errorThreshold"
        if 'general' in remote_outstanding_requesters:
            remote_outstanding_requesters, force_update = self.merge_general_outstanding_requesters(
                threshold, remote_outstanding_requesters, outstanding_requesters,
                utc_now_timestamp_str, utc_now_timestamp, force_update)
        if 'uriList' in remote_outstanding_requesters:    
            outstanding_requesters, force_update = self.merge_urilist_outstanding_requesters(
                threshold, remote_outstanding_requesters, outstanding_requesters,
                utc_now_timestamp_str, utc_now_timestamp, force_update)
    
        need_update = (force_update or
                    last_update_age > int(os.getenv('MAX_AGE_TO_UPDATE')) or
                    len(outstanding_requesters['general']) > 0 or
                    len(outstanding_requesters['uriList']) > 0)

        self.log.debug("[lambda_log_parser: merge_outstanding_requesters] End")
        return outstanding_requesters, need_update


    def write_output(self, bucket_name, key_name, output_key_name, outstanding_requesters):
        self.log.debug("[lambda_log_parser: write_output] Start")

        try:
            current_data = TMP_DIR + key_name.split('/')[-1] + '_LOCAL.json'
            with open(current_data, 'w') as outfile:
                json.dump(outstanding_requesters, outfile)

            self.s3_util.upload_file_to_s3(current_data, bucket_name, output_key_name)
            remove(current_data)

        except Exception as e:
            self.log.error("[lambda_log_parser: write_output] Error to write output file")
            self.log.error(e)

        self.log.debug("[lambda_log_parser: write_output] End")


    def merge_lists(self, outstanding_requesters):
        self.log.debug("[lambda_log_parser: merge_lists] Start to merge general and uriList into a single list")

        unified_outstanding_requesters = outstanding_requesters['general']
        for uri in outstanding_requesters['uriList'].keys():
            for k in outstanding_requesters['uriList'][uri].keys():
                if (k not in unified_outstanding_requesters.keys() or
                        outstanding_requesters['uriList'][uri][k]['max_counter_per_min'] >
                        unified_outstanding_requesters[k]['max_counter_per_min']):
                    unified_outstanding_requesters[k] = outstanding_requesters['uriList'][uri][k]

        self.log.debug("[lambda_log_parser: merge_lists] End")
        return unified_outstanding_requesters


    def truncate_list(self, unified_outstanding_requesters):
        self.log.debug("[lambda_log_parser: truncate_list] " +
                       "Start to truncate [if necessary] list to respect WAF ip range limit")

        ip_range_limit = int(os.getenv('LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION'))
        if len(unified_outstanding_requesters) > ip_range_limit:
            ordered_unified_outstanding_requesters = sorted(
                unified_outstanding_requesters.items(),
                key=lambda kv: kv[1]['max_counter_per_min'], reverse=True)
            unified_outstanding_requesters = {}
            for key, value in ordered_unified_outstanding_requesters:
                if counter < ip_range_limit:
                    unified_outstanding_requesters[key] = value
                    counter += 1
                else:
                    break

        self.log.debug("[lambda_log_parser: truncate_list] End")
        return unified_outstanding_requesters 


    def build_ip_list_to_block(self, unified_outstanding_requesters):
        self.log.debug("[lambda_log_parser: truncate_list] Start to build list of ips to be blocked")

        addresses_v4 = []
        addresses_v6 = []

        for k in unified_outstanding_requesters.keys():
            ip_type = self.waflib.which_ip_version(self.log, k)
            source_ip = self.waflib.set_ip_cidr(self.log, k)

            if ip_type == "IPV4":
                addresses_v4.append(source_ip)
            elif ip_type == "IPV6":
                addresses_v6.append(source_ip)

        self.log.debug("[lambda_log_parser: truncate_list] End")
        return addresses_v4, addresses_v6
 

    def update_ip_set(self, ip_set_type, outstanding_requesters):
        self.log.info("[update_ip_set] Start")

        # With wafv2 api we need to pass the scope, name and arn of an IPSet to manipulate the Address list
        # We also can only put source_ips in the appropriate IPSets based on IP version
        # Depending on the ip_set_type, we choose the appropriate set of IPSets and Names

        # initialize as SCANNER_PROBES IPSets
        ipset_name_v4 = None
        ipset_name_v6 = None
        ipset_arn_v4 = None
        ipset_arn_v6 = None

        # switch if type of IPSets are HTTP_FLOOD
        if ip_set_type == self.flood:
            ipset_name_v4 = os.getenv('IP_SET_NAME_HTTP_FLOODV4')
            ipset_name_v6 = os.getenv('IP_SET_NAME_HTTP_FLOODV6')
            ipset_arn_v4 = os.getenv('IP_SET_ID_HTTP_FLOODV4')
            ipset_arn_v6 = os.getenv('IP_SET_ID_HTTP_FLOODV6')
        elif ip_set_type == self.scanners:
            ipset_name_v4 = os.getenv('IP_SET_NAME_SCANNERS_PROBESV4')
            ipset_name_v6 = os.getenv('IP_SET_NAME_SCANNERS_PROBESV6')
            ipset_arn_v4 = os.getenv('IP_SET_ID_SCANNERS_PROBESV4')
            ipset_arn_v6 = os.getenv('IP_SET_ID_SCANNERS_PROBESV6')

        counter = 0
        try:
            if ipset_arn_v4 == None or ipset_arn_v6 == None:
                self.log.info("[update_ip_set] Ignore process when ip_set_id is None")
                return
            
            # --------------------------------------------------------------------------------------------------------------
            self.log.info("[update_ip_set] Merge general and uriList into a single list")
            # --------------------------------------------------------------------------------------------------------------
            unified_outstanding_requesters = self.merge_lists(outstanding_requesters)

            # --------------------------------------------------------------------------------------------------------------
            self.log.info("[update_ip_set] Truncate [if necessary] list to respect WAF limit")
            # --------------------------------------------------------------------------------------------------------------
            unified_outstanding_requesters = self.truncate_list(unified_outstanding_requesters)

            # --------------------------------------------------------------------------------------------------------------
            self.log.info("[update_ip_set] Block remaining outstanding requesters")
            # --------------------------------------------------------------------------------------------------------------
            addresses_v4, addresses_v6 = self.build_ip_list_to_block(unified_outstanding_requesters)

            # --------------------------------------------------------------------------------------------------------------
            self.log.info("[ update_ip_set] Commit changes in WAF IP set")
            # --------------------------------------------------------------------------------------------------------------
            response = self.waflib.update_ip_set(self.log, self.scope, ipset_name_v4, ipset_arn_v4, addresses_v4)
            self.log.debug("[update_ip_set] update ipsetv4 response: \n%s" % response)

            # Sleep for a few seconds to mitigate AWS WAF Update API call throttling issue
            sleep(self.delay_between_updates)
            
            response = self.waflib.update_ip_set(self.log, self.scope, ipset_name_v6, ipset_arn_v6, addresses_v6)
            self.log.debug("[update_ip_set] update ipsetv6 response: \n%s" % response)

        except Exception as error:
            self.log.error(str(error))
            self.log.error("[update_ip_set] Error to update waf ip set")

        self.log.info("[update_ip_set] End")
        return counter


    def process_log_file(self, bucket_name, key_name, conf_filename, output_filename, log_type, ip_set_type):
        self.log.debug("[lambda_log_parser: process_log_file] Start")
       
        # --------------------------------------------------------------------------------------------------------------
        self.log.info("[lambda_log_parser: process_log_file] Reading input data and get outstanding requesters")
        # --------------------------------------------------------------------------------------------------------------
        self.config = self.s3_util.read_json_config_file_from_s3(bucket_name, conf_filename)
        counter, outstanding_requesters = self.parse_log_file(bucket_name, key_name, log_type)
        outstanding_requesters = self.get_outstanding_requesters(log_type, counter, outstanding_requesters)
        outstanding_requesters, need_update = self.merge_outstanding_requesters(
            bucket_name, key_name, log_type, output_filename, outstanding_requesters)

        if need_update:
            # ----------------------------------------------------------------------------------------------------------
            self.log.info("[process_log_file] Update new blocked requesters list to S3")
            # ----------------------------------------------------------------------------------------------------------
            self.write_output(bucket_name, key_name, output_filename, outstanding_requesters)

            # ----------------------------------------------------------------------------------------------------------
            self.log.info("[process_log_file] Update WAF IP Set")
            # ----------------------------------------------------------------------------------------------------------
            self.update_ip_set(ip_set_type, outstanding_requesters)

        else:
            # ----------------------------------------------------------------------------------------------------------
            self.log.info("[process_log_file] No changes identified")
            # ----------------------------------------------------------------------------------------------------------

        self.log.debug('[process_log_file] End')