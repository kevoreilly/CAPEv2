from contextlib import suppress

from modules.processing.parsers.CAPE.SparkRAT import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.SparkRAT import convert_to_MACO

    HAVE_MACO = True


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
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "SparkRAT",
                "identifier": ["8dc7e7d8f8576f3e55a00850b72887db"],
                "other": {
                    "secure": False,
                    "host": "67.217.62.106",
                    "port": 4443,
                    "path": "/",
                    "uuid": "8dc7e7d8f8576f3e55a00850b72887db",
                    "key": "a1348fb8969ad7a9f85ac173c2027622135e52e0e6d94d10e6a81916a29648ac",
                },
                "http": [{"uri": "http://67.217.62.106:4443/", "hostname": "67.217.62.106", "port": 4443, "path": "/"}],
            }
