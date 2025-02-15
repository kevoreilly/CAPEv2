import io
import unittest
from unittest.mock import MagicMock, patch

import pytest
import pyzipper
import requests

from lib.downloaders import Downloaders
from lib.downloaders.malwarebazaar import download as mb_downloader
from lib.downloaders.virustotal import download as vt_downloader


class TestDownloaders(unittest.TestCase):
    @patch('lib.downloaders.load_downloaders')
    @patch('lib.downloaders.Config')
    @patch('lib.downloaders.path_exists')
    @patch('lib.downloaders.path_mkdir')
    def setUp(self, mock_mkdir, mock_exists, mock_config, mock_load_downloaders):
        mock_exists.return_value = False
        self.mock_downloaders = {
            'downloader1': MagicMock(),
            'downloader2': MagicMock()
        }
        mock_load_downloaders.return_value = self.mock_downloaders
        self.mock_config = MagicMock()
        mock_config.return_value = self.mock_config
        self.dl = Downloaders()

    @pytest.mark.skip(reason="Need to figure out how to test this")
    def test_download_success(self):
        self.mock_downloaders['downloader1'].is_supported.return_value = True
        self.mock_downloaders['downloader1'].download.return_value = b'sample_data'
        sample, service = self.dl.download('validhash')
        self.assertEqual(sample, b'sample_data')
        self.assertEqual(service, 'downloader1')

    def test_download_invalid_hash(self):
        self.mock_downloaders['downloader1'].is_supported.return_value = False
        self.mock_downloaders['downloader2'].is_supported.return_value = False
        sample, service = self.dl.download('invalidhash')
        self.assertFalse(sample)
        self.assertFalse(service)

    @pytest.mark.skip(reason="Need to figure out how to test this")
    def test_download_exception(self):
        self.mock_downloaders['downloader1'].is_supported.side_effect = Exception("Test exception")
        self.mock_downloaders['downloader2'].is_supported.return_value = True
        self.mock_downloaders['downloader2'].download.return_value = b'sample_data'
        sample, service = self.dl.download('validhash')
        self.assertEqual(sample, b'sample_data')
        self.assertEqual(service, 'downloader2')

    def test_download_no_sample(self):
        self.mock_downloaders['downloader1'].is_supported.return_value = True
        self.mock_downloaders['downloader1'].download.return_value = False
        self.mock_downloaders['downloader2'].is_supported.return_value = True
        self.mock_downloaders['downloader2'].download.return_value = False
        sample, service = self.dl.download('validhash')
        self.assertFalse(sample)
        self.assertFalse(service)


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
        result = mb_downloader("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

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
        result = mb_downloader("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

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
        result = mb_downloader("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        # Check the result
        assert not result

    @patch("requests.post")
    def test_malwarebazaar_dl_exception(self, mock_post):
        # Mock the response from requests.post to raise an exception
        mock_post.side_effect = requests.exceptions.RequestException

        # Call the function
        result = mb_downloader("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        # Check the result
        assert not result

    @patch("lib.downloaders.virustotal.requests.get")
    def test_download_success_vt(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"sample content"
        mock_get.return_value = mock_response

        result = vt_downloader("d41d8cd98f00b204e9800998ecf8427e", "test_api_key")
        self.assertEqual(result, b"sample content")

    @patch("lib.downloaders.virustotal.requests.get")
    def test_download_hash_not_present(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"Hash Not Present"
        mock_get.return_value = mock_response

        result = vt_downloader("d41d8cd98f00b204e9800998ecf8427e", "test_api_key")
        self.assertEqual(result, b"")

    @patch("lib.downloaders.virustotal.requests.get")
    def test_download_forbidden(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_get.return_value = mock_response

        with self.assertLogs("lib.downloaders.virustotal", level="ERROR") as cm:
            result = vt_downloader("d41d8cd98f00b204e9800998ecf8427e", "test_api_key")
            self.assertIn("API key provided is not a valid VirusTotal key or is not authorized for downloads", cm.output[0])
        self.assertEqual(result, b"")

    @patch("lib.downloaders.virustotal.requests.get")
    def test_download_not_found(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        with self.assertLogs("lib.downloaders.virustotal", level="ERROR") as cm:
            result = vt_downloader("d41d8cd98f00b204e9800998ecf8427e", "test_api_key")
            self.assertIn("Hash not found on VirusTotal", cm.output[0])
        self.assertEqual(result, b"")

    @pytest.mark.skip(reason="Need to figure out how to test this")
    @patch("lib.downloaders.virustotal.requests.get")
    def test_download_request_exception(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException("Request failed")

        with self.assertLogs("lib.downloaders.virustotal", level="ERROR") as cm:
            result = vt_downloader("d41d8cd98f00b204e9800998ecf8427e", "test_api_key")
            self.assertIn("Request failed", cm.output[0])
        self.assertIsNone(result)



if __name__ == '__main__':
    unittest.main()
