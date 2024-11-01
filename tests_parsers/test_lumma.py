# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from contextlib import suppress

from modules.processing.parsers.CAPE.Lumma import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.Lumma import convert_to_MACO

    HAVE_MACO = True


def test_lumma():
    with open("tests/data/malware/5d58bc449693815f6fb0755a364c4cd3a8e2a81188e431d4801f2fb0b1c2de8f", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "C2": [
                "delaylacedmn.site",
                "writekdmsnu.site",
                "agentyanlark.site",
                "bellykmrebk.site",
                "underlinemdsj.site",
                "commandejorsk.site",
                "possiwreeste.site",
                "famikyjdiag.site",
                "agentyanlark.site",
            ]
        }
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "Lumma",
                "other": {
                    "C2": [
                        "delaylacedmn.site",
                        "writekdmsnu.site",
                        "agentyanlark.site",
                        "bellykmrebk.site",
                        "underlinemdsj.site",
                        "commandejorsk.site",
                        "possiwreeste.site",
                        "famikyjdiag.site",
                        "agentyanlark.site",
                    ]
                },
                "http": [
                    {"hostname": "delaylacedmn.site", "usage": "c2"},
                    {"hostname": "writekdmsnu.site", "usage": "c2"},
                    {"hostname": "agentyanlark.site", "usage": "c2"},
                    {"hostname": "bellykmrebk.site", "usage": "c2"},
                    {"hostname": "underlinemdsj.site", "usage": "c2"},
                    {"hostname": "commandejorsk.site", "usage": "c2"},
                    {"hostname": "possiwreeste.site", "usage": "c2"},
                    {"hostname": "famikyjdiag.site", "usage": "c2"},
                    {"hostname": "agentyanlark.site", "usage": "c2"},
                ],
            }
