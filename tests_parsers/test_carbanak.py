from modules.processing.parsers.CAPE.Carbanak import extract_config


def test_carbanak():
    with open("tests/data/malware/c9c1b06cb9c9bd6fc4451f5e2847a1f9524bb2870d7bb6f0ee09b9dd4e3e4c84", "rb") as data:
        conf = extract_config(data.read())
        assert conf["C2"] == ["5.161.223.210:443", "207.174.30.226:443"]
