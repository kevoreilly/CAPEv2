import unittest
from unittest.mock import MagicMock, patch

from lib.downloaders import Downloaders


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

if __name__ == '__main__':
    unittest.main()
