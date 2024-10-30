# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from contextlib import suppress

from modules.processing.parsers.CAPE.Quickbind import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.Quickbind import convert_to_MACO

    HAVE_MACO = True


def test_quickbind():
    with open("tests/data/malware/bfcb215f86fc4f8b4829f6ddd5acb118e80fb5bd977453fc7e8ef10a52fc83b7", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "Encryption Key": "24de21a8dc08434c",
            "Mutex": ["15432a4d-34ca-4d0d-a4ac-04df9a373862"],
            "C2": ["185.49.69.41"],
        }
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "Quickbind",
                "mutex": ["15432a4d-34ca-4d0d-a4ac-04df9a373862"],
                "other": {
                    "Encryption Key": "24de21a8dc08434c",
                    "Mutex": ["15432a4d-34ca-4d0d-a4ac-04df9a373862"],
                    "C2": ["185.49.69.41"],
                },
                "http": [{"hostname": "185.49.69.41", "usage": "c2"}],
                "encryption": [{"key": "24de21a8dc08434c"}],
            }
