# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pathlib

from lib.cuckoo.common.compressor import CuckooBsonCompressor
from lib.cuckoo.common.path_utils import path_delete


class TestCuckooBsonCompresson:
    def test_init(self):
        assert CuckooBsonCompressor()

    def test_run(self):
        file_path = os.path.join(pathlib.Path(__file__).absolute().parent.as_posix(), "test_bson.bson")
        try:
            CuckooBsonCompressor().run(file_path=file_path)
        finally:
            try:
                path_delete(os.path.dirname(file_path) + "/test_bson.bson.compressed")
            except Exception as e:
                print(("Exception cleaning up, should be fine:" + str(e)))
