from contextlib import suppress

from modules.processing.parsers.CAPE.SmokeLoader import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.SmokeLoader import convert_to_MACO

    HAVE_MACO = True


def test_smokeloader():
    with open("tests/data/malware/6929fff132c05ae7d348867f4ea77ba18f84fb8fae17d45dde3571c9e33f01f8", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"C2s": ["http://host-file-host6.com/", "http://host-host-file8.com/"]}
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "SmokeLoader",
                "other": {"C2s": ["http://host-file-host6.com/", "http://host-host-file8.com/"]},
                "http": [
                    {"uri": "http://host-file-host6.com/", "usage": "c2"},
                    {"uri": "http://host-host-file8.com/", "usage": "c2"},
                ],
            }
