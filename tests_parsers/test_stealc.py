# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from modules.processing.parsers.CAPE.Stealc import extract_config


def test_stealc():
    with open("tests/data/malware/619751f5ed0a9716318092998f2e4561f27f7f429fe6103406ecf16e33837470", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "C2": ["http://95.217.125.57"],
        }
