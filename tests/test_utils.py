# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
from tcr_misc import random_string

from unittest import mock
import pytest
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.path_utils import path_mkdir
from lib.cuckoo.common import utils



def test_get_memdump_path(mocker):
    ret_path = utils.get_memdump_path(memdump_id=123)
    assert ret_path.rsplit("/", 4)[-4:] == "storage/analyses/123/memory.dmp".split("/")


class TestValidateReferrer:
    def test_validate_referrer(self):
        assert utils.validate_referrer(url="http://foo.example.com:1337/bar") == "http://foo.example.com:1337/bar"

    def test_validate_referrer_bad_url(self):
        assert utils.validate_referrer(url="irc://foo.example.com:1337") is None

    def test_validate_referrer_no_url(self):
        assert utils.validate_referrer(url=None) is None


@pytest.fixture
def rnd_tmp_folder():
    random_file_name = random_string()
    yield random_file_name
    try:
        os.rmdir("/tmp/" + random_file_name)
    except Exception as e:
        print(("Error cleaning up, probably fine:" + str(e)))


class TestFileOps:
    def test_create_folders_no_folders(self):
        utils.create_folders(root="foo")

    def test_create_folder_default(self):
        with pytest.raises(CuckooOperationalError):
            utils.create_folder()

    """
    def test_create_folder(self, rnd_tmp_folder):
        utils.create_folder(root="/tmp", folder=rnd_tmp_folder)
        assert test_create_folder_err("/tmp/" + rnd_tmp_folder) is True
    """

    def test_create_folder_err(self, rnd_tmp_folder, mocker):
        mocker.patch("pathlib.Path.mkdir", side_effect=OSError)
        with pytest.raises(CuckooOperationalError):
            utils.create_folder(root="/tmp", folder=rnd_tmp_folder)

    def test_delete_folder(self, rnd_tmp_folder):
        folder = "/tmp/" + rnd_tmp_folder
        path_mkdir(folder)
        utils.delete_folder(folder)

    def test_delete_folder_err(self, rnd_tmp_folder, mocker):
        folder = "/tmp/" + rnd_tmp_folder
        path_mkdir(folder)
        mocker.patch("shutil.rmtree", side_effect=OSError)
        with pytest.raises(CuckooOperationalError):
            utils.delete_folder(folder)


class TestConvertChar:
    def test_utf(self):
        assert "\\xe9", utils.convert_char("\xe9")

    def test_digit(self):
        assert "9" == utils.convert_char("9")

    def test_literal(self):
        assert "e" == utils.convert_char("e")

    def test_punctation(self):
        assert "." == utils.convert_char(".")

    def test_whitespace(self):
        assert " " == utils.convert_char(" ")


class TestConvertToPrintable:
    def test_utf(self):
        assert "\\xe9" == utils.convert_to_printable("\xe9")

    def test_digit(self):
        assert "9" == utils.convert_to_printable("9")

    def test_literal(self):
        assert "e" == utils.convert_to_printable("e")

    def test_punctation(self):
        assert "." == utils.convert_to_printable(".")

    def test_whitespace(self):
        assert " " == utils.convert_to_printable(" ")

    def test_non_printable(self):
        assert r"\x0b" == utils.convert_to_printable(chr(11))


class TestIsPrintable:
    def test_utf(self):
        assert not utils.is_printable("\xe9")

    def test_digit(self):
        assert utils.is_printable("9")

    def test_literal(self):
        assert utils.is_printable("e")

    def test_punctation(self):
        assert utils.is_printable(".")

    def test_whitespace(self):
        assert utils.is_printable(" ")

    def test_non_printable(self):
        assert not utils.is_printable(chr(11))


class TestConvertFilenameChar:
    def test_convert_filename_char(self):
        assert utils.convert_filename_char("\u00A3") == "\\xa3"

    def test_convert_filename_char_allowed(self):
        assert utils.convert_filename_char("!") == "!"


class TestIsSaneFilename:
    def test_is_sane_filename(self):
        assert utils.is_sane_filename("abc") is True

    def test_is_sane_filename_not(self):
        assert utils.is_sane_filename("\n") is False


class TestSanitizePathname:
    def test_sanitize_pathname(self):
        assert utils.sanitize_pathname("abc") == "abc"

    def test_sanitize_pathname_not(self):
        assert utils.sanitize_pathname("\nabc") == "\\x0aabc"


class TestPrettyPrintRetval:
    def test_pretty_print_retval_no_lookup(self):
        assert utils.pretty_print_retval(status=False, retval="0") is None

    def test_pretty_print_retval(self):
        assert utils.pretty_print_retval(status=False, retval="0xc0000139") == "ENTRYPOINT_NOT_FOUND"

    def test_pretty_print_retval_err(self):
        assert utils.pretty_print_retval(status=False, retval="-") is None

    def test_pretty_print_retval_true_status(self):
        assert utils.pretty_print_retval(status=True, retval="0") is None


@pytest.mark.skip
def test_is_safelisted_domain():
    from lib.cuckoo.common.safelist import is_safelisted_domain
    assert is_safelisted_domain("java.com") is True
    assert is_safelisted_domain("java2.com") is False
    assert is_safelisted_domain("crl.microsoft.com") is True


    @pytest.fixture
    def mock_config(mocker):
        mock_config = mocker.patch("lib.cuckoo.common.utils.config")
        mock_config.cuckoo.get.return_value = b"/tmp"
        return mock_config

    @pytest.fixture
    def mock_path_exists(mocker):
        return mocker.patch("lib.cuckoo.common.utils.path_exists", return_value=False)

    @pytest.fixture
    def mock_path_mkdir(mocker):
        return mocker.patch("lib.cuckoo.common.utils.path_mkdir")

    @pytest.fixture
    def mock_tempfile(mocker):
        return mocker.patch("lib.cuckoo.common.utils.tempfile.mkdtemp", return_value="/tmp/cuckoo-tmp/upload_1234")

    @pytest.fixture
    def mock_open(mocker):
        return mocker.patch("builtins.open", mock.mock_open())

    def test_store_temp_file_bytes(mock_config, mock_path_exists, mock_path_mkdir, mock_tempfile, mock_open):
        filedata = b"test data"
        filename = "testfile.txt"
        result = utils.store_temp_file(filedata, filename)
        assert result == b"/tmp/cuckoo-tmp/upload_1234/testfile.txt"
        mock_open.assert_called_once_with(b"/tmp/cuckoo-tmp/upload_1234/testfile.txt", "wb")
        mock_open().write.assert_called_once_with(filedata)

    def test_store_temp_file_filelike(mock_config, mock_path_exists, mock_path_mkdir, mock_tempfile, mock_open):
        filedata = mock.Mock()
        filedata.read.side_effect = [b"chunk1", b"chunk2", b""]
        filename = "testfile.txt"
        result = utils.store_temp_file(filedata, filename)
        assert result == b"/tmp/cuckoo-tmp/upload_1234/testfile.txt"
        mock_open.assert_called_once_with(b"/tmp/cuckoo-tmp/upload_1234/testfile.txt", "wb")
        mock_open().write.assert_has_calls([mock.call(b"chunk1"), mock.call(b"chunk2")])

    def test_store_temp_file_with_path(mock_config, mock_path_exists, mock_path_mkdir, mock_tempfile, mock_open):
        filedata = b"test data"
        filename = "testfile.txt"
        path = b"/custom/path"
        result = utils.store_temp_file(filedata, filename, path)
        assert result == b"/custom/path/upload_1234/testfile.txt"
        mock_open.assert_called_once_with(b"/custom/path/upload_1234/testfile.txt", "wb")
        mock_open().write.assert_called_once_with(filedata)

    def test_store_temp_file_path_exists(mock_config, mocker, mock_tempfile, mock_open):
        mock_path_exists = mocker.patch("lib.cuckoo.common.utils.path_exists", return_value=True)
        filedata = b"test data"
        filename = "testfile.txt"
        result = utils.store_temp_file(filedata, filename)
        assert result == b"/tmp/cuckoo-tmp/upload_1234/testfile.txt"
        mock_open.assert_called_once_with(b"/tmp/cuckoo-tmp/upload_1234/testfile.txt", "wb")
        mock_open().write.assert_called_once_with(filedata)
        mock_path_exists.assert_called_once_with("/tmp/cuckoo-tmp")

    def test_store_temp_file_path_mkdir_error(mock_config, mocker, mock_tempfile):
        # mock_path_exists = mocker.patch("lib.cuckoo.common.utils.path_exists", return_value=False)
        mock_path_mkdir = mocker.patch("lib.cuckoo.common.utils.path_mkdir", side_effect=OSError)
        filedata = b"test data"
        filename = "testfile.txt"
        with pytest.raises(CuckooOperationalError):
            utils.store_temp_file(filedata, filename)
        mock_path_mkdir.assert_called_once_with("/tmp/cuckoo-tmp")

