import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from lib.cuckoo.common.integrations.parse_office import Office

data_dir = Path(__file__).parent / "data" / "office"
rtf_path = data_dir / "rtf_exploit.doc"


class TestParseOffice(unittest.TestCase):
    @patch("lib.cuckoo.common.integrations.parse_office.RtfObjParser")
    @patch("lib.cuckoo.common.integrations.parse_office.path_exists")
    @patch("lib.cuckoo.common.integrations.parse_office.hashlib.sha256")
    def test_parse_rtf(self, mock_sha256, mock_path_exists, MockRtfObjParser):
        # Setup
        mock_sha256.return_value.hexdigest.return_value = "dummy_sha256"
        mock_path_exists.return_value = False
        mock_rtfobj = MagicMock()
        mock_rtfobj.format_id = 1
        mock_rtfobj.is_package = False
        mock_rtfobj.is_ole = False
        mock_rtfobj.rawdata = b"rawdata"
        mock_rtfobj.start = 0
        MockRtfObjParser.return_value.objects = [mock_rtfobj]

        office = Office(
            file_path="dummy_path",
            task_id="dummy_task_id",
            sha256="dummy_sha256",
            options={},
        )

        # Execute
        result = office._parse_rtf(b"dummy_data")

        # Verify
        expected_result = {
            "1": [
                {
                    "class_name": "",
                    "size": len(mock_rtfobj.rawdata),
                    "filename": "object_00000000.raw",
                    "type_embed": "",
                    "CVE": "",
                    "sha256": "dummy_sha256",
                    "index": "00000000h",
                }
            ]
        }
        self.assertEqual(result, expected_result)


    @pytest.mark.skipif(not data_dir.exists(), reason="Required data file is not present")
    @pytest.mark.skipif(not rtf_path.exists(), reason="Required data file is not present")
    def test_parse_real_rtf(self):
        office = Office(
            file_path=rtf_path,
            task_id="1",
            sha256="5b307600b1ceb84f29315c95e5b21776eb6154b79214528629e4fc2310cd50e3",
            options={},
        )
        result = office._parse_rtf(Path(rtf_path).read_bytes())

        assert result == {
            "2": [
                {
                    "class_name": "Equation.3",
                    "size": 3584,
                    "filename": "object_0000272F.bin",
                    "type_embed": "Embedded",
                    "CVE": "Microsoft Equation 3.0 (Known Related to CVE-2017-11882 or CVE-2018-0802)",
                    "sha256": "c00b73082638eda4af3d5318aba64ae32d23f703a02c7338d5e34230a7855e70",
                    "index": "0000272Fh",
                }
            ]
        }


if __name__ == "__main__":
    unittest.main()
