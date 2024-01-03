from modules.processing.parsers.CAPE.Carbanak import extract_config


def test_carbanak():
    with open("tests/data/malware/81502b895611f61494996ea3e3e3244af97911968acf777b016c405b178bbf66", "rb") as data:
        conf = extract_config(data.read())
        assert conf["C2"] == ["166.1.160.180:443", "166.1.190.169:443"]
