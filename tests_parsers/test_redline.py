# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from modules.processing.parsers.CAPE.RedLine import extract_config


def test_redline():
    with open("tests/data/malware/redline", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"C2": "77.91.68.68:19071", "Botnet": "krast", "Key": "Formative"}
