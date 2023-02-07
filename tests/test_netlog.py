# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import pathlib

import pytest

from lib.cuckoo.common.netlog import BsonParser

# Might require newer pymongo, works with 3.11.4


@pytest.fixture
def bson_file():
    class mock_handle:
        def __init__(self, filename):
            print(filename)
            self.file_handle = open(filename, "rb")
            self.process_log = ()

        def log_process(self, a, b, c, d, e, f):
            self.process_log = (a, b, c, d, e, f)

        def log_thread(self, a, b):
            pass

        def log_environ(self, a, b):
            pass

        def log_call(self, a, b, c, d):
            pass

        def read(self, num):
            return self.file_handle.read(num)

    yield mock_handle(pathlib.Path(__file__).absolute().parent.as_posix() + "/test_bson.bson")


class TestBsonParser:
    def test_init(self, bson_file):
        assert BsonParser(bson_file)

    def test_read_next_message(self, bson_file):
        b = BsonParser(bson_file)
        b.read_next_message()
        assert len(bson_file.process_log) == 0

        b.read_next_message()
        assert bson_file.process_log == (
            [0, 0, 1, 0, 2360, 0, 0, 0],
            datetime.datetime(2020, 11, 6, 9, 34, 36, 359375),
            1976,
            476,
            b"C:\\Windows\\sysnative\\lsass.exe",
            "lsass.exe",
        )
