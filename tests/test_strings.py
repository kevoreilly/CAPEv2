import unittest
from unittest.mock import patch

from lib.cuckoo.common.integrations.strings import extract_strings


class TestExtractStrings(unittest.TestCase):
    @patch("lib.cuckoo.common.integrations.strings.processing_cfg")
    @patch("lib.cuckoo.common.integrations.strings.Path")
    def test_extract_strings_from_file(self, mock_path, mock_cfg):
        mock_cfg.strings.enabled = True
        mock_cfg.strings.on_demand = False
        mock_cfg.strings.nullterminated_only = False
        mock_cfg.strings.minchars = 4

        mock_path.return_value.exists.return_value = True
        mock_path.return_value.read_bytes.return_value = b"test\x00string\x00data"

        result = extract_strings(filepath="dummy_path")
        self.assertIn("test", result)
        self.assertIn("string", result)
        self.assertIn("data", result)

    @patch("lib.cuckoo.common.integrations.strings.processing_cfg")
    def test_extract_strings_from_data(self, mock_cfg):
        mock_cfg.strings.enabled = True
        mock_cfg.strings.on_demand = False
        mock_cfg.strings.nullterminated_only = False
        mock_cfg.strings.minchars = 4

        data = b"test\x00string\x00data"
        result = extract_strings(data=data)
        self.assertIn("test", result)
        self.assertIn("string", result)
        self.assertIn("data", result)

    @patch("lib.cuckoo.common.integrations.strings.processing_cfg")
    def test_extract_strings_with_dedup(self, mock_cfg):
        mock_cfg.strings.enabled = True
        mock_cfg.strings.on_demand = False
        mock_cfg.strings.nullterminated_only = False
        mock_cfg.strings.minchars = 4

        data = b"test\x00test\x00data"
        result = extract_strings(data=data, dedup=True)
        self.assertEqual(len(result), 2)
        self.assertIn("test", result)
        self.assertIn("data", result)

    @patch("lib.cuckoo.common.integrations.strings.processing_cfg")
    def test_extract_strings_with_minchars(self, mock_cfg):
        mock_cfg.strings.enabled = True
        mock_cfg.strings.on_demand = False
        mock_cfg.strings.nullterminated_only = False
        mock_cfg.strings.minchars = 6

        data = b"test\x00string\x00data"
        result = extract_strings(data=data)
        self.assertNotIn("test", result)
        self.assertIn("string", result)
        self.assertNotIn("data", result)

    @patch("lib.cuckoo.common.integrations.strings.processing_cfg")
    def test_extract_strings_nullterminated_only(self, mock_cfg):
        mock_cfg.strings.enabled = True
        mock_cfg.strings.on_demand = False
        mock_cfg.strings.nullterminated_only = True
        mock_cfg.strings.minchars = 4

        data = b"test\x00string\x00data\x00"
        result = extract_strings(data=data)
        self.assertIn("test", result)
        self.assertIn("string", result)
        self.assertIn("data", result)

if __name__ == "__main__":
    unittest.main()
