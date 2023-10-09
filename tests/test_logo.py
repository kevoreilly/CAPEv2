# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common import logo


def test_logo(capsys):
    logo.logo()
    captured = capsys.readouterr()
    assert "CAPE: Config and Payload Extraction" in captured.out
