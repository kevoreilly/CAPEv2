# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import io
import os
import shutil
import tempfile

import pytest

from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.files import Files, Folders, Storage, open_exclusive
from lib.cuckoo.common.path_utils import path_exists, path_write_file

# from lib.cuckoo.common.safelist import is_safelisted_domain


def getuser():
    # if HAVE_PWD:
    #     return pwd.getpwuid(os.getuid())[0]
    return ""


def set_cwd(dir):
    return dir


@pytest.fixture
def dir_setup():
    dirpath = tempfile.mkdtemp()
    dir_to_copy = tempfile.mkdtemp()
    file_to_copy = tempfile.NamedTemporaryFile(dir=dir_to_copy, delete=False).name.rsplit("/", 1)[-1]
    yield dir_to_copy, dirpath, file_to_copy
    try:
        shutil.rmtree(dirpath)
        shutil.rmtree(dir_to_copy)
    except Exception as e:
        print(("Tried to remove temp dirs, failed. Probably OK: " + str(e)))


class TestCreateFolders:
    def setup(self):
        self.tmp_dir = tempfile.gettempdir()

    def test_root_folder(self):
        """Test single folder creation based on the root parameter."""
        Folders.create(os.path.join(self.tmp_dir, "foo"))
        assert path_exists(os.path.join(self.tmp_dir, "foo"))
        os.rmdir(os.path.join(self.tmp_dir, "foo"))

    def test_single_folder(self):
        """Test single folder creation."""
        Folders.create(self.tmp_dir, "foo")
        assert path_exists(os.path.join(self.tmp_dir, "foo"))
        os.rmdir(os.path.join(self.tmp_dir, "foo"))

    def test_multiple_folders(self):
        """Test multiple folder creation."""
        Folders.create(self.tmp_dir, ["foo", "bar"])
        assert path_exists(os.path.join(self.tmp_dir, "foo"))
        assert path_exists(os.path.join(self.tmp_dir, "bar"))
        os.rmdir(os.path.join(self.tmp_dir, "foo"))
        os.rmdir(os.path.join(self.tmp_dir, "bar"))

    def test_copy_folder(self, dir_setup):
        """Test recursive folder copy."""

        Folders.copy(dir_setup[0], dir_setup[1])

        assert os.path.isfile("%s/%s" % (dir_setup[0], dir_setup[2]))

    def test_duplicate_folder(self):
        """Test a duplicate folder creation."""
        Folders.create(self.tmp_dir, "foo")
        assert path_exists(os.path.join(self.tmp_dir, "foo"))
        Folders.create(self.tmp_dir, "foo")
        os.rmdir(os.path.join(self.tmp_dir, "foo"))

    def test_delete_folder(self):
        """Test folder deletion #1."""
        Folders.create(self.tmp_dir, "foo")
        assert path_exists(os.path.join(self.tmp_dir, "foo"))
        Folders.delete(os.path.join(self.tmp_dir, "foo"))
        assert not path_exists(os.path.join(self.tmp_dir, "foo"))

    def test_delete_folder2(self):
        """Test folder deletion #2."""
        Folders.create(self.tmp_dir, "foo")
        assert path_exists(os.path.join(self.tmp_dir, "foo"))
        Folders.delete(self.tmp_dir, "foo")
        assert not path_exists(os.path.join(self.tmp_dir, "foo"))

    @pytest.mark.skipif("sys.platform != 'linux2'")
    def test_create_invld_linux(self):
        """Test creation of a folder we can't access."""
        with pytest.raises(CuckooOperationalError):
            Folders.create("/invalid/directory")

    @pytest.mark.skipif("sys.platform != 'win32'")
    def test_create_invld_windows(self):
        """Test creation of a folder we can't access."""
        with pytest.raises(CuckooOperationalError):
            Folders.create("Z:\\invalid\\directory")

    def test_delete_invld(self):
        """Test deletion of a folder we can't access."""
        dirpath = tempfile.mkdtemp()

        os.chmod(dirpath, 0)
        with pytest.raises(CuckooOperationalError):
            Folders.delete(dirpath)

        os.chmod(dirpath, 0o775)
        Folders.delete(dirpath)

    def test_create_tuple(self):
        dirpath = tempfile.mkdtemp()
        Folders.create(dirpath, "a")
        Folders.create((dirpath, "a"), "b")
        Files.create((dirpath, "a", "b"), "c.txt", b"nested")

        filepath = os.path.join(dirpath, "a", "b", "c.txt")
        assert open(filepath, "rb").read() == b"nested"


class TestCreateFile:
    def test_create(self):
        dirpath = tempfile.mkdtemp()
        Files.create(dirpath, "a.txt", b"foo")
        assert open(os.path.join(dirpath, "a.txt"), "rb").read() == b"foo"
        shutil.rmtree(dirpath)

    def test_create_bytesio(self):
        dirpath = tempfile.mkdtemp()
        filepath = Files.create(dirpath, "a.txt", io.BytesIO(b"A" * 1024 * 1024))
        assert open(filepath, "rb").read() == b"A" * 1024 * 1024

    def test_create_tuple(self):
        dirpath = tempfile.mkdtemp()
        Folders.create(dirpath, "foo")
        Files.create((dirpath, "foo"), "a.txt", b"bar")

        filepath = os.path.join(dirpath, "foo", "a.txt")
        assert open(filepath, "rb").read() == b"bar"


class TestStorage:
    def test_basename(self):
        assert Storage.get_filename_from_path("C:\\a.txt") == "a.txt"
        assert Storage.get_filename_from_path("C:/a.txt") == "a.txt"
        assert Storage.get_filename_from_path("C:\\\x00a.txt") == "\x00a.txt"
        assert Storage.get_filename_from_path("/tmp/a.txt") == "a.txt"
        assert Storage.get_filename_from_path("../../b.txt") == "b.txt"
        assert Storage.get_filename_from_path("..\\..\\c.txt") == "c.txt"


def test_open_exclusive():
    fpath = os.path.join(tempfile.mkdtemp(), "yeet.exclusive")
    _ = path_write_file(fpath, "42421337Test", mode="text")

    with pytest.raises(OSError):
        open_exclusive(fpath, bufsize=1)
