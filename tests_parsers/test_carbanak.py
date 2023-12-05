import pytest

from modules.processing.parsers.CAPE.Carbanak import extract_config


@pytest.mark.skip(reason="Broken")
def test_carbanak():
    with open("tests/data/malware/9c9f7174d1c79569ac3464aa9a997d09d44c2094ce1b80a5e63c115edc140c56", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"c2_domains": ["blizko.net", "blizko.org"], "version": "1.7"}
