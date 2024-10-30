# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from contextlib import suppress

from modules.processing.parsers.CAPE.RedLine import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.RedLine import convert_to_MACO

    HAVE_MACO = True


def test_redline():
    with open("tests/data/malware/000608d875638ba7d6c467ece976c1496e6a6ec8ce3e7f79e0fd195ae3045078", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "Authorization": "9059ea331e4599de3746df73ccb24514",
            "C2": "77.91.68.68:19071",
            "Botnet": "krast",
            "Key": "Formative",
        }
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "RedLine",
                "other": {
                    "Authorization": "9059ea331e4599de3746df73ccb24514",
                    "C2": "77.91.68.68:19071",
                    "Botnet": "krast",
                    "Key": "Formative",
                },
                "http": [{"hostname": "77.91.68.68", "port": 19071, "usage": "c2"}],
            }
