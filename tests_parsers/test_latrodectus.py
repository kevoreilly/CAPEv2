# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from modules.processing.parsers.CAPE.Zloader import extract_config


def test_latrodectus():
    with open("tests/data/malware/a547cff9991a713535e5c128a0711ca68acf9298cc2220c4ea0685d580f36811", "rb") as data:
        conf = extract_config(data.read())
        del conf["Strings"]
        assert conf == {
            "Campaign ID": "445271760",
            "C2": ["https://peermangoz.me", "https://aprettopizza.world/live/"],
            "Group name": "Olimp",
        }
