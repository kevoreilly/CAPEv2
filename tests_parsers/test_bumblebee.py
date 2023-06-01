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
    with open("tests/data/malware/33a3c20cf70977346acf57a190b46beff92a3d417e7593036a400c93011a0061", "rb") as data:
        conf = extract_config(data)
        assert conf == {"Botnet ID": "YTBSBbNTWU", "Campaign ID": "1904r", "Data": "XNgHUGLrCD", "C2s": ["444"]}
