# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from contextlib import suppress

from modules.processing.parsers.CAPE.BumbleBee import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.BumbleBee import convert_to_MACO

    HAVE_MACO = True


def test_bumblebee():
    with open("tests/data/malware/f8a6eddcec59934c42ea254cdd942fb62917b5898f71f0feeae6826ba4f3470d", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"Botnet ID": "YTBSBbNTWU", "Campaign ID": "1904r", "Data": "XNgHUGLrCD", "C2s": ["444"]}
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "BumbleBee",
                "campaign_id": ["1904r"],
                "identifier": ["YTBSBbNTWU"],
                "other": {"Botnet ID": "YTBSBbNTWU", "Campaign ID": "1904r", "Data": "XNgHUGLrCD", "C2s": ["444"]},
                "binaries": [{"data": "XNgHUGLrCD"}],
                "http": [{"hostname": "444", "usage": "c2"}],
            }
