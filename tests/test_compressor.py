# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import pathlib

from lib.cuckoo.common.compressor import CuckooBsonCompressor


class TestCuckooBsonCompresson:
    def test_init(self):
        assert CuckooBsonCompressor()

    def test_run(self):
        file_path = os.path.join(pathlib.Path(__file__).absolute().parent.as_posix(), "test_bson.bson")
        CuckooBsonCompressor().run(file_path=file_path)
        try:
            os.unlink("CAPEv2/tests/test_bson.bson.compressed")
        except Exception as e:
            print(("Exception cleaning up, should be fine:" + str(e)))
