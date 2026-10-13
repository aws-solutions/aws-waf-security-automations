# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import unittest
from unittest.mock import Mock, MagicMock, patch
from lambda_log_parser import LambdaLogParser

class TestProcessLogFile(unittest.TestCase):
    def setUp(self):
        self.log = Mock()
        self.s3_util = Mock()
        self.parser = LambdaLogParser(self.log)

        # Mock s3_util and its method
        self.parser.s3_util = self.s3_util
        self.s3_util.read_json_config_file_from_s3 = MagicMock(return_value={"test": "config"})

        # Mock parser methods
        self.parser.parse_log_file = MagicMock()
        self.parser.is_empty_counter = MagicMock()
        self.parser.get_outstanding_requesters = MagicMock()
        self.parser.merge_outstanding_requesters = MagicMock()
        self.parser.write_output = MagicMock()
        self.parser.update_ip_set = MagicMock()
        self.parser.bad_bot_ips_to_ip_set = MagicMock()

    def test_process_log_file_with_updates(self):
        """Test processing log file with updates needed"""
        # Setup
        bucket_name = "test-bucket"
        key_name = "test-key"
        conf_filename = "config.json"
        output_filename = "output.json"
        log_type = "waf"
        ip_set_type = 1

        # Configure mocks
        self.parser.parse_log_file.return_value = (
            {"general": {"192.0.2.1": 1}, "uriList": {}},  # counter
            {"general": {}, "uriList": {}},                 # outstanding_requesters
            []                                             # bad_bot_ips
        )
        self.parser.is_empty_counter.return_value = False
        self.parser.merge_outstanding_requesters.return_value = ({"general": {"192.0.2.1": 1}}, True)

        # Execute
        self.parser.process_log_file(bucket_name, key_name, conf_filename,
                                     output_filename, log_type, ip_set_type)

        # Assert
        self.parser.write_output.assert_called_once()
        self.parser.update_ip_set.assert_called_once()
        self.parser.bad_bot_ips_to_ip_set.assert_not_called()

    def test_process_log_file_empty_counter(self):
        """Test processing log file with empty counter"""
        # Setup
        bucket_name = "test-bucket"
        key_name = "test-key"
        conf_filename = "config.json"
        output_filename = "output.json"
        log_type = "waf"
        ip_set_type = 1

        # Configure mocks
        self.parser.parse_log_file.return_value = (
            {"general": {}, "uriList": {}},  # empty counter
            {"general": {}, "uriList": {}},  # outstanding_requesters
            []                              # bad_bot_ips
        )
        self.parser.is_empty_counter.return_value = True

        # Execute
        self.parser.process_log_file(bucket_name, key_name, conf_filename,
                                     output_filename, log_type, ip_set_type)

        # Assert
        self.parser.get_outstanding_requesters.assert_not_called()
        self.parser.write_output.assert_not_called()
        self.parser.update_ip_set.assert_not_called()

    def test_process_log_file_with_bad_bot_ips(self):
        """Test processing log file with bad bot IPs"""
        # Setup
        bucket_name = "test-bucket"
        key_name = "test-key"
        conf_filename = "config.json"
        output_filename = "output.json"
        log_type = "waf"
        ip_set_type = 1

        # Configure mocks
        self.parser.parse_log_file.return_value = (
            {"general": {}, "uriList": {}},  # empty counter
            {"general": {}, "uriList": {}},  # outstanding_requesters
            ["192.0.2.1", "192.0.2.2"]      # bad_bot_ips
        )
        self.parser.is_empty_counter.return_value = True

        # Execute
        self.parser.process_log_file(bucket_name, key_name, conf_filename,
                                     output_filename, log_type, ip_set_type)

        # Assert
        self.parser.bad_bot_ips_to_ip_set.assert_called_once_with(["192.0.2.1", "192.0.2.2"])
        self.parser.get_outstanding_requesters.assert_not_called()
        self.parser.write_output.assert_not_called()

    @patch.dict(os.environ, {}, clear=False)
    def test_process_log_file_full_log_reads_config(self):
        """Full-log parse (default, non bad-bot-only) must load the threshold config."""
        os.environ.pop("BAD_BOT_LOG_PARSER", None)

        self.parser.parse_log_file.return_value = (
            {"general": {}, "uriList": {}},
            {"general": {}, "uriList": {}},
            []
        )
        self.parser.is_empty_counter.return_value = True

        self.parser.process_log_file("test-bucket", "test-key", "config.json",
                                     "output.json", "waf", 2)

        self.s3_util.read_json_config_file_from_s3.assert_called_once_with(
            "test-bucket", "config.json")
        self.assertEqual(self.parser.config, {"test": "config"})

    @patch.dict(os.environ, {"BAD_BOT_LOG_PARSER": "true"})
    def test_process_log_file_bad_bot_only_skips_config(self):
        self.parser.parse_log_file.return_value = (
            {"general": {}, "uriList": {}},  
            {"general": {}, "uriList": {}},
            ["192.0.2.1"]                  
        )
        self.parser.is_empty_counter.return_value = True

        self.parser.process_log_file("test-bucket", "test-key", "config.json",
                                     "output.json", "waf", 2)

        self.s3_util.read_json_config_file_from_s3.assert_not_called()
        self.assertEqual(self.parser.config, {})
        self.parser.bad_bot_ips_to_ip_set.assert_called_once_with(["192.0.2.1"])
        self.parser.get_outstanding_requesters.assert_not_called()
        self.parser.write_output.assert_not_called()
        self.parser.update_ip_set.assert_not_called()


if __name__ == "__main__":
    unittest.main()