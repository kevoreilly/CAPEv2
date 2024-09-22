import pytest

from modules.processing.parsers.CAPE.QakBot import extract_config


@pytest.mark.skip(reason="Missed file")
def test_qakbot():
    with open("tests/data/malware/0cb0d77ac38df36fff891e072dea96401a8c1e8ff40d6ac741d5a2942aaeddbb", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"C2": "anscowerbrut.com", "Campaign": 2738000827}
