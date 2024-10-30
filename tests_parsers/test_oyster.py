# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from contextlib import suppress

from modules.processing.parsers.CAPE.Oyster import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.Oyster import convert_to_MACO

    HAVE_MACO = True


def test_oyster():
    with open("tests/data/malware/8bae0fa9f589cd434a689eebd7a1fde949cc09e6a65e1b56bb620998246a1650", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "C2": ["https://connectivity-check.linkpc.net/"],
            "Dll Version": "v1.0 #ads 2",
            "Strings": ["api/connect", "Content-Type: application/json", "api/session"],
        }
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "Oyster",
                "version": "v1.0 #ads 2",
                "decoded_strings": ["api/connect", "Content-Type: application/json", "api/session"],
                "other": {
                    "C2": ["https://connectivity-check.linkpc.net/"],
                    "Dll Version": "v1.0 #ads 2",
                    "Strings": ["api/connect", "Content-Type: application/json", "api/session"],
                },
                "http": [{"uri": "https://connectivity-check.linkpc.net/", "usage": "c2"}],
            }
