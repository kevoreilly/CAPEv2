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
    with open("tests/data/malware/f8a6eddcec59934c42ea254cdd942fb62917b5898f71f0feeae6826ba4f3470d", "rb") as data:
        conf = extract_config(data)
        print(sorted(conf))
        assert conf == {"Botnet ID": "YTBSBbNTWU", "Campaign ID": "1904r", "Data": "XNgHUGLrCD", "C2s": ["444"]}
