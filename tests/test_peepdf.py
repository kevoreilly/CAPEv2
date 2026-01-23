from pathlib import Path

import pytest

from lib.cuckoo.common.integrations.peepdf import peepdf_parse

data_dir = Path(__file__).parent / "data" / "malware"
pdf_path = data_dir / "ad6cedb0d1244c1d740bf5f681850a275c4592281cdebb491ce533edd9d6a77d"

expected_result = {
    "Info": {
        "Creator": "Scribus 1.3.3.12",
        "Producer": "Scribus PDF Library 1.3.3.12",
        "Author": ""
    },
    "Dates": [],
    "Keywords": {},
    "JSStreams": [
        {
            "Object ID": 13,
            "Offset": 872,
            "Size": 1255,
        }
    ],
    "All_URLs": [],
    "JS_URLs": ["http://78.109.30.5/count/005AD56F/load.php?pdf=a684eceee76fc522773286a895bc8436\x00"],
}

pdfresult = {"Info": {}, "Dates": [], "Keywords": {}, "JSStreams": [], "All_URLs": [], "JS_URLs": []}


@pytest.mark.skipif(not data_dir.exists(), reason="Required data file is not present")
class TestPeepdf:
    """Class to test peepdf_parse."""
    @pytest.mark.skipif(not pdf_path.exists(), reason="Required data file is not present")
    def test_peepdf_parse_valid_pdf(self):
        """Test parsing a valid PDF sample."""
        result = peepdf_parse(str(pdf_path), pdfresult)
        del result["JSStreams"][0]["Data"]
        assert result == expected_result
