# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from modules.processing.parsers.CAPE.Oyster import extract_config


def test_oyster():
    with open("tests/data/malware/8bae0fa9f589cd434a689eebd7a1fde949cc09e6a65e1b56bb620998246a1650", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "C2": ["https://connectivity-check.linkpc.net/"],
            "Dll Version": "v1.0 #ads 2",
            "Strings": ["api/connect", "Content-Type: application/json", "api/session"],
        }
