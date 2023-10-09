# Copyright (C) 2021 CSIT
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import sys
from contextlib import contextmanager, suppress
from typing import Dict

import pytest

testfile_dir = os.path.dirname(__file__)
module_dir = os.path.join(testfile_dir, "", "../..", "analyzer", "windows")
sys.path.append(module_dir)

from lib.common.exceptions import CuckooPackageError
from lib.cuckoo.common.path_utils import path_delete, path_exists
from modules.packages.zip_compound import ZipCompound

# Note: References "single_layer_json.zip" and "multi_layer_json.zip" files
option_curdir = os.path.expandvars("%USERPROFILE%\\Desktop\\whatmeow")
option_filename = "some_EXECutable.exe"

dest_folders = (
    os.path.expandvars("%userprofile%\\Desktop\\testcape\\a\\b\\c"),
    os.path.expandvars("%userprofile%\\Desktop\\testcape\\d\\e\\f"),
    os.path.expandvars("%userprofile%\\Desktop\\testcape\\capetest"),
)


@contextmanager
def cleanup():
    try:
        yield
    finally:
        global option_curdir
        test_folder = os.path.expandvars("%userprofile%\\Desktop\\testcape")
        to_remove = (test_folder, option_curdir)

        for folder in to_remove:
            try:
                shutil.rmtree(folder)
            except FileNotFoundError:
                continue


def generate_analysis_dict(curdir: bool = False, file: bool = False) -> Dict[str, str]:
    global option_curdir, option_filename
    options = {}
    if curdir:
        options["curdir"] = option_curdir
    if file:
        options["file"] = option_filename
    return options


def test_analysis_dict():
    global option_curdir, option_filename

    assert generate_analysis_dict() == {}
    assert generate_analysis_dict(curdir=True) == {"curdir": option_curdir}
    assert generate_analysis_dict(file=True) == {"file": option_filename}
    assert generate_analysis_dict(curdir=True, file=True) == {"curdir": option_curdir, "file": option_filename}


def test_curdir():
    """Test the curdir submission option
    Checks if the files are at the right "curdir" location
    """
    global option_curdir
    files = ("__configuration1.json", "test_executable.exe", "test_loadable.dll", "test_notes.txt", "test_notes_immovable.txt")

    def check_files(expected_dir):
        # Checks whether all the files are present inside the specified directory.
        for f in files:
            path_to_check = os.path.join(expected_dir, f)
            assert path_exists(path_to_check)

    def cleanup_temp():
        for f in files:
            with suppress(FileNotFoundError):
                path_delete(os.path.join(os.path.expandvars("%TEMP%"), f))

    # Assumes that "file" submission option is provided (required)
    # No JSON config
    # No curdir, defaults to %TEMP.
    try:
        y = ZipCompound(options=generate_analysis_dict(file=True))
        y.prepare_zip_compound("./files/single_layer_json.zip", "__configuration0.json")
        check_files(os.path.expandvars("%TEMP%"))
    finally:
        cleanup_temp()

    # Curdir, specified by "option_curdir"
    with cleanup():
        z = ZipCompound(options=generate_analysis_dict(curdir=True, file=True))
        z.prepare_zip_compound("./files/single_layer_json.zip", "__configuration0.json")
        check_files(option_curdir)


def test_invalid_file_option():
    """Test invalid `file` submission
    Should fail if `file` was not provided during submission and no JSON
    or `file` value is not supported
    """

    z = ZipCompound(options=generate_analysis_dict(curdir=True))

    # No `file` and no JSON --> should fail
    with cleanup():
        with pytest.raises(CuckooPackageError) as e:
            z.prepare_zip_compound("./files/single_layer_json.zip", "__configuration0.json")
        assert "File must be specified" in str(e.value)

    # Wrong `file` (no extension) and no JSON --> should fail
    z.options["file"] = "test_executable"
    with cleanup():
        with pytest.raises(CuckooPackageError) as e:
            z.prepare_zip_compound("./files/single_layer_json.zip", "__configuration0.json")
        assert "no extension recognised" in str(e.value)


def test_valid_file_option():
    """Test valid file submission option"""
    global dest_folders, option_curdir

    expected_filename = "test_executable.exe"
    expected_path = os.path.join(dest_folders[0], expected_filename)

    # `File` + no json (+curdir) --> covered under test_curdir()

    # No `file` + json --> json provided
    with cleanup():
        y = ZipCompound(options=generate_analysis_dict(curdir=True))
        file_name, file_path = y.prepare_zip_compound("./files/single_layer_json.zip", "__configuration1.json")
        assert file_name == expected_filename
        assert file_path == expected_path

    # `file` + json (+curdir) --> json overwrites
    with cleanup():
        z = ZipCompound(options=generate_analysis_dict(curdir=True, file=True))
        file_name, file_path = z.prepare_zip_compound("./files/single_layer_json.zip", "__configuration1.json")
        assert file_name == expected_filename
        assert file_path == expected_path


def test_folder_extraction():
    """Tests the simple moving of folders, with "target_file" being a file
    in the root directory of the zip
    """
    global dest_folders

    def check_moved_files():
        expected_files = (
            os.path.join(option_curdir, "__configuration1.json"),
            os.path.join(option_curdir, "__configuration2.json"),
            os.path.join(dest_folders[0], "test_executable.exe"),
            os.path.join(dest_folders[1], "folder", "test_notes_immovable.txt"),
            os.path.join(dest_folders[1], "folder\\kewl", "test_notes.txt"),
            os.path.join(dest_folders[2], "fld\\nested", "testfile.txt"),
            os.path.join(dest_folders[2], "fld\\nested\\last", "test_loadable.dll"),
        )
        for f in expected_files:
            assert path_exists(f)

    with cleanup():
        z = ZipCompound(options=generate_analysis_dict(curdir=True, file=True))
        z.prepare_zip_compound("./files/multi_layer_json.zip", "__configuration1.json")
        check_moved_files()


def test_invalid_json_target():
    """When "target_file" is a relative path, but its containing folder
    is moved before the specified "target_file"
    """
    global dest_folders

    # Tests JSON "target_file" whose containing directory is shifted
    with cleanup():
        with pytest.raises(CuckooPackageError) as e:
            z = ZipCompound(options=generate_analysis_dict(curdir=True, file=True))
            z.prepare_zip_compound("./files/multi_layer_json.zip", "__configuration2.json")
        assert "Error getting the correct path" in str(e.value)


def test_json_target_1():
    # When JSON "target_file" is a relative path but its containing folder is not moved
    expected_filename = "test_loadable.dll"
    expected_filepath = os.path.join(option_curdir, "fld\\nested\\last", "test_loadable.dll")
    with cleanup():
        z = ZipCompound(options=generate_analysis_dict(curdir=True, file=True))
        filename, filepath = z.prepare_zip_compound("./files/multi_layer_json.zip", "__configuration3.json")
        assert filename == expected_filename
        assert filepath == expected_filepath


def test_json_target_2():
    # When JSON "target_file" is a relative path, moved before moving its containing folder
    expected_filename = "test_loadable.dll"
    expected_filepath = os.path.join(dest_folders[2], "fld\\nested\\last", "test_loadable.dll")

    def check_moved():
        expected_files = (
            os.path.join(option_curdir, "__configuration1.json"),
            os.path.join(option_curdir, "__configuration2.json"),
            os.path.join(dest_folders[0], "test_executable.exe"),
            os.path.join(dest_folders[2], "test_notes_immovable.txt"),
            os.path.join(dest_folders[1], "kewl", "test_notes.txt"),
            os.path.join(dest_folders[2], "fld\\nested\\last", "test_loadable.dll"),
        )
        for f in expected_files:
            assert path_exists(f)

    with cleanup():
        z = ZipCompound(options=generate_analysis_dict(curdir=True, file=True))
        filename, filepath = z.prepare_zip_compound("./files/multi_layer_json.zip", "__configuration4.json")
        assert filename == expected_filename
        assert filepath == expected_filepath
        # Sanity check
        check_moved()
