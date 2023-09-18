from modules.processing.parsers.CAPE.DarkGate import extract_config


def test_darkgate():
    with open("tests/data/malware/1c3ae64795b61034080be00601b947819fe071efd69d7fc791a99ec666c2043d", "rb") as data:
        conf = extract_config(data.read())
        assert conf["C2"] == ["http://80.66.88.145"]
