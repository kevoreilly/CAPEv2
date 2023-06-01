# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# import pytest

from modules.processing.parsers.CAPE.BumbleBee import extract_config

"""
This is a quick POC
The idea is to have folder with samples that is scanned with yara and automatically calls extractors on detection

"""

def test_bumblebee():
    with open("tests/data/malware/d0f51ff313ede61e1c4d7d57b644507a4bd46455e3e617e66c922c8c0c07024b.mbam", "rb") as data:
        conf = extract_config(data)
        assert conf == {"Botnet ID": "YTBSBbNTWU", "Campaign ID": "1904r", "Data": "XNgHUGLrCD", "C2s": ["444"]}
