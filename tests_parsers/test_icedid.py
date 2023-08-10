from modules.processing.parsers.CAPE.IcedIDLoader import extract_config


def test_icedid():
    with open("tests/data/malware/7aaf80eb1436b946b2bd710ab57d2dcbaad2b1553d45602f2f3af6f2cfca5212", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"C2": "anscowerbrut.com", "Campaign": 2738000827}
