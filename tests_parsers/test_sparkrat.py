from modules.processing.parsers.CAPE.SparkRAT import extract_config


def test_sparkrat():
    with open("tests/data/malware/ec349cfacc7658eed3640f1c475eb958c5f05bae7c2ed74d4cdb7493176daeba", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "secure": False,
            "host": "67.217.62.106",
            "port": 4443,
            "path": "/",
            "uuid": "8dc7e7d8f8576f3e55a00850b72887db",
            "key": "a1348fb8969ad7a9f85ac173c2027622135e52e0e6d94d10e6a81916a29648ac",
        }
