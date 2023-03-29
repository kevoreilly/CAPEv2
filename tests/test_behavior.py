# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.config import Config
from modules.processing.behavior import ParseProcessLog

cfg = Config("processing")


class TestParseProcessLog:
    def test_init(self):
        assert (
            str(ParseProcessLog("CAPEv2/tests/test_bson.bson", cfg.behavior))
            == "<ParseProcessLog log-path: CAPEv2/tests/test_bson.bson>"
        )
