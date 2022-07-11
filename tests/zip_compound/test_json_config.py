# Copyright (C) 2021 CSIT
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

import os
import sys

import pytest

testfile_dir = os.path.dirname(__file__)
module_dir = os.path.join(testfile_dir, "", "../..", "analyzer", "windows")
sys.path.append(module_dir)

from lib.common.exceptions import CuckooPackageError
from lib.core.compound import extract_json_data


def test_invalid_json():
    with pytest.raises(CuckooPackageError) as e:
        extract_json_data("./files", "misconfiguration.json")
    assert "JSON decode error" in str(e.value)

    data = extract_json_data("./files", "nosuchfile")
    assert data == {}


def test_json():
    data = extract_json_data("./files", "example_config.json")
    assert data["path_to_extract"]["a.exe"] == "%USERPROFILE%\\Desktop\\a\\b\\c"
    assert data["path_to_extract"]["folder_b"] == "%appdata%"
    assert data["target_file"] == "a.exe"
