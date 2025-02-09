# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import io
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import httpretty
import pytest
import pyzipper
import requests

from lib.cuckoo.common.path_utils import path_delete, path_write_file
from lib.cuckoo.common.web_utils import (
    _download_file,
    _malwarebazaar_dl,
    download_from_vt,
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
        None,
        None,
        None,
        None,
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


class TestMalwareBazaarDownload(unittest.TestCase):
    @patch("requests.post")
    def test_malwarebazaar_dl_success(self, mock_post):
        # Mock the response from requests.post
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.content = io.BytesIO()
        with pyzipper.AESZipFile(mock_response.content, "w", encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(b"infected")
            zf.writestr("sample.txt", "sample content")
        mock_post.return_value = mock_response

        # Call the function
        result = _malwarebazaar_dl("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        # Check the result
        self.assertEqual(result, b"sample content")

    @patch("requests.post")
    def test_malwarebazaar_dl_file_not_found(self, mock_post):
        # Mock the response from requests.post
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.content = b"file_not_found"
        mock_post.return_value = mock_response

        # Call the function
        result = _malwarebazaar_dl("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        # Check the result
        assert not result

    @patch("requests.post")
    def test_malwarebazaar_dl_bad_zip_file(self, mock_post):
        # Mock the response from requests.post
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.content = b"not a zip file"
        mock_post.return_value = mock_response

        # Call the function
        result = _malwarebazaar_dl("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        # Check the result
        assert not result

    @patch("requests.post")
    def test_malwarebazaar_dl_exception(self, mock_post):
        # Mock the response from requests.post to raise an exception
        mock_post.side_effect = requests.exceptions.RequestException

        # Call the function
        result = _malwarebazaar_dl("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        # Check the result
        assert not result


class TestDownloadFromVT(unittest.TestCase):
    @patch("lib.cuckoo.common.web_utils.thirdpart_aux")
    def test_download_from_vt_with_vtdl_key(self, mock_thirdpart_aux):
        settings = MagicMock()
        settings.VTDL_KEY = "dummy_vtdl_key"
        details = {"errors": []}
        samples = ["sample1"]
        opt_filename = "sample.txt"
        mock_thirdpart_aux.return_value = details
        result = download_from_vt(samples, details, opt_filename, settings)
        self.assertEqual(result["headers"]["x-apikey"], "dummy_vtdl_key")
        self.assertEqual(result["service"], "VirusTotal")
        mock_thirdpart_aux.assert_called_once_with(samples, "vt", opt_filename, details, settings)

    @patch("lib.cuckoo.common.web_utils.thirdpart_aux")
    def test_download_from_vt_with_apikey_in_details(self, mock_thirdpart_aux):
        settings = MagicMock()
        settings.VTDL_KEY = None
        details = {"apikey": "dummy_apikey", "errors": []}
        samples = ["sample1"]
        opt_filename = "sample.txt"
        mock_thirdpart_aux.return_value = details
        result = download_from_vt(samples, details, opt_filename, settings)
        self.assertEqual(result["headers"]["x-apikey"], "dummy_apikey")
        self.assertEqual(result["service"], "VirusTotal")
        mock_thirdpart_aux.assert_called_once_with(samples, "vt", opt_filename, details, settings)

    def test_download_from_vt_no_apikey(self):
        settings = MagicMock()
        settings.VTDL_KEY = None
        details = {"errors": []}
        samples = ["sample1"]
        opt_filename = "sample.txt"
        result = download_from_vt(samples, details, opt_filename, settings)
        self.assertIn({"error": "Apikey not configured, neither passed as opt_apikey"}, result["errors"])
        self.assertNotIn("headers", result)
        self.assertNotIn("service", result)


if __name__ == "__main__":
    unittest.main()
