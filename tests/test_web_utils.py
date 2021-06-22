# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function

import pytest
import tempfile
import os
import httpretty

from lib.cuckoo.common.web_utils import get_file_content, _download_file, parse_request_arguments, force_int

@pytest.fixture
def paths():
    path_list = []
    for i in range(0, 3):
        path_list += [tempfile.NamedTemporaryFile(delete=False).name]
        with open(path_list[i], "w") as f:
            f.write(str(i + 10))
    yield path_list
    try:
        for i in path_list:
            os.unlink(i)
    except Exception as e:
        print(("Error cleaning up, probably fine:" + str(e)))


@pytest.fixture
def path():
    onepath = tempfile.NamedTemporaryFile(delete=False)
    with open(onepath.name, mode="w") as f:
        f.write("1338")
    yield onepath.name
    try:
        os.unlink(onepath.name)
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
        None,
        None,
        None,
        None,
        False,
        None,
        None,
        None,
        None,
        "",
    )


def test_force_int():
    assert force_int(value="1") == 1
    assert force_int(value="$") == 0
