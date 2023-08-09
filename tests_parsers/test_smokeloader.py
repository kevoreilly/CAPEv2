from modules.processing.parsers.CAPE.SmokeLoader import extract_config


def test_smokeloader():
    with open("tests/data/malware/6929fff132c05ae7d348867f4ea77ba18f84fb8fae17d45dde3571c9e33f01f8", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"C2s": ["http://host-file-host6.com/", "http://host-host-file8.com/"]}
