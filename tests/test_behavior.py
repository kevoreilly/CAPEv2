# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from modules.processing.behavior import ParseProcessLog


class TestParseProcessLog:
    def test_init(self):
        assert (
            str(ParseProcessLog(log_path="CAPE/tests/test_bson.bson")) == "<ParseProcessLog log-path: 'CAPE/tests/test_bson.bson'>"
        )
