# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from contextlib import suppress

from modules.processing.parsers.CAPE.KoiLoader import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.KoiLoader import convert_to_MACO

    HAVE_MACO = True


def test_koiloader():
    with open("tests/data/malware/b462e3235c7578450b2b56a8aff875a3d99d22f6970a01db3ba98f7ecb6b01a0", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"C2": ["http://91.202.233.209/hypermetropia.php", "https://admiralpub.ca/wp-content/uploads/2017"]}
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "KoiLoader",
                "other": {"C2": ["http://91.202.233.209/hypermetropia.php", "https://admiralpub.ca/wp-content/uploads/2017"]},
                "http": [
                    {"uri": "http://91.202.233.209/hypermetropia.php", "usage": "c2"},
                    {"uri": "https://admiralpub.ca/wp-content/uploads/2017", "usage": "c2"},
                ],
            }
