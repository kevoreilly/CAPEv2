import unittest
from unittest.mock import patch, MagicMock
from lib.cuckoo.common.cape_utils import cape_name_from_yara
from lib.cuckoo.common.cape_utils import static_config_parsers

class TestCapeUtils(unittest.TestCase):
    @patch("lib.cuckoo.common.cape_utils.File.yara_hit_provides_detection")
    @patch("lib.cuckoo.common.cape_utils.File.get_cape_name_from_yara_hit")
    def test_cape_name_from_yara(self, mock_get_cape_name_from_yara_hit, mock_yara_hit_provides_detection):
        details = {
            "cape_yara": [
                {"rule": "test_rule_1"},
                {"rule": "test_rule_2"}
            ]
        }
        pid = 1234
        results = {}

        mock_yara_hit_provides_detection.side_effect = [False, True]
        mock_get_cape_name_from_yara_hit.return_value = "test_name"

        name = cape_name_from_yara(details, pid, results)

        self.assertEqual(name, "test_name")
        self.assertIn("detections2pid", results)
        self.assertIn(str(pid), results["detections2pid"])
        self.assertIn("test_name", results["detections2pid"][str(pid)])

    @patch("lib.cuckoo.common.cape_utils.File.yara_hit_provides_detection")
    def test_cape_name_from_yara_no_detection(self, mock_yara_hit_provides_detection):
        details = {
            "cape_yara": [
                {"rule": "test_rule_1"}
            ]
        }
        pid = 1234
        results = {}

        mock_yara_hit_provides_detection.return_value = False

        name = cape_name_from_yara(details, pid, results)

        self.assertIsNone(name)
        self.assertNotIn("detections2pid", results)

    def test_cape_name_from_yara_no_cape_yara(self):
        details = {}
        pid = 1234
        results = {}

        name = cape_name_from_yara(details, pid, results)

        self.assertIsNone(name)
        self.assertNotIn("detections2pid", results)

class TestStaticConfigParsers(unittest.TestCase):
    @patch("lib.cuckoo.common.cape_utils.HAVE_CAPE_EXTRACTORS", True)
    @patch("lib.cuckoo.common.cape_utils.cape_malware_parsers")
    def test_static_config_parsers_cape_extractors(self, mock_cape_malware_parsers):
        cape_name = "test_cape"
        file_path = "/path/to/file"
        file_data = b"test data"
        mock_parser = MagicMock()
        mock_parser.extract_config.return_value = {"key": "value"}
        mock_cape_malware_parsers.__contains__.return_value = True
        mock_cape_malware_parsers.__getitem__.return_value = mock_parser
        result = static_config_parsers(cape_name, file_path, file_data)
        self.assertIn(cape_name, result)
        self.assertIn("key", result[cape_name])
        self.assertEqual(result[cape_name]["key"], ["value"])

    @patch("lib.cuckoo.common.cape_utils.HAS_MWCP", True)
    @patch("lib.cuckoo.common.cape_utils.mwcp_decoders")
    @patch("lib.cuckoo.common.cape_utils.mwcp")
    def test_static_config_parsers_mwcp(self, mock_mwcp, mock_mwcp_decoders):
        cape_name = "test_mwcp"
        file_path = "/path/to/file"
        file_data = b"test data"
        mock_report = MagicMock()
        mock_report.as_dict_legacy.return_value = {"key": "value"}
        mock_report.errors = []
        mock_mwcp.run.return_value = mock_report
        mock_mwcp_decoders.__contains__.return_value = True
        result = static_config_parsers(cape_name, file_path, file_data)
        self.assertIn(cape_name, result)
        self.assertIn("key", result[cape_name])
        self.assertEqual(result[cape_name]["key"], ["value"])

    @patch("lib.cuckoo.common.cape_utils.HAS_MALWARECONFIGS", True)
    @patch("lib.cuckoo.common.cape_utils.rat_decoders")
    @patch("lib.cuckoo.common.cape_utils.fileparser.FileParser")
    def test_static_config_parsers_malwareconfigs(self, mock_FileParser, mock_rat_decoders):
        cape_name = "test_rat"
        file_path = "/path/to/file"
        file_data = b"test data"
        mock_file_info = MagicMock()
        mock_file_info.malware_name = cape_name
        mock_FileParser.return_value = mock_file_info
        mock_module = MagicMock()
        mock_module.config = {"key": "value"}
        mock_rat_decoders.__contains__.return_value = True
        mock_rat_decoders.__getitem__.return_value = {"obj": lambda: mock_module}
        result = static_config_parsers(cape_name, file_path, file_data)
        self.assertIn(cape_name, result)
        self.assertIn("key", result[cape_name])
        self.assertEqual(result[cape_name]["key"], ["value"])

    def test_static_config_parsers_no_extractors(self):
        cape_name = "test_none"
        file_path = "/path/to/file"
        file_data = b"test data"
        result = static_config_parsers(cape_name, file_path, file_data)
        self.assertEqual(result, {cape_name: {}})

if __name__ == "__main__":
    unittest.main()
