# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import tempfile
import unittest

import httpretty
import pytest

from lib.cuckoo.common.path_utils import path_delete, path_write_file
from lib.cuckoo.common.web_utils import (
    _download_file,
    force_int,
    get_file_content,
    parse_request_arguments,
)


@pytest.fixture
def paths():
    path_list = []
    for i in range(3):
        path_list += [tempfile.NamedTemporaryFile(delete=False).name]
        _ = path_write_file(path_list[i], str(i + 10), mode="text")
    yield path_list
    try:
        for i in path_list:
            path_delete(i)
    except Exception as e:
        print(("Error cleaning up, probably fine:" + str(e)))


@pytest.fixture
def path():
    onepath = tempfile.NamedTemporaryFile(delete=False)
    _ = path_write_file(onepath.name, "1338", mode="text")
    yield onepath.name
    try:
        path_delete(onepath.name)
    except Exception as e:
        print(("Error cleaning up, probably fine:" + str(e)))


def test_get_file_content(paths):
    assert get_file_content(paths) == b"10"


def test_get_file_contents_path(path):
    assert get_file_content(path) == b"1338"


@httpretty.activate
def test__download_file():
    httpretty.register_uri(httpretty.GET, "http://mordor.eye/onering", body="frodo")
    assert _download_file(route=None, url="http://mordor.eye/onering", options="dne_abc=123,dne_def=456") == b"frodo"


@pytest.fixture
def mock_request():
    class MockReq:
        POST = {"clock": "03-31-2021 14:24:36"}

    yield MockReq()


def test_parse_request_arguments(mock_request):
    ret = parse_request_arguments(mock_request)

    assert ret == (
        "",
        "",
        0,
        0,
        "",
        "",
        "",
        None,
        "",
        False,
        "03-31-2021 14:24:36",
        False,
        False,
        None,
        None,
        None,
        "",
        "",
    )


def test_force_int():
    assert force_int(value="1") == 1
    assert force_int(value="$") == 0


if __name__ == "__main__":
    unittest.main()
