# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pathlib

import pytest
from tcr_misc import get_sample

from lib.cuckoo.common.icon import PEGroupIconDir


@pytest.fixture
def sample():
    def get_binary_data(sample_location):
        with open(sample_location, mode="rb") as f:
            return f.read()

    def _grab_sample(sample_hash):
        sample_location = pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        get_sample(hash=sample_hash, download_location=sample_location)
        return get_binary_data(sample_location)

    return _grab_sample


class TestPEGroupIconDir:
    # Sample taken from https://www.scintilla.org/wscite32_446.zip
    @pytest.mark.skip(reason="TODO")
    def test_init(self, sample):
        return_obj = PEGroupIconDir(data=sample("438117c7bd53653b3113903bcdb8bd369904a152b524b4676b18a626c2b60e82"))
        assert len(return_obj.icons) == 3

    @pytest.mark.skip(reason="TODO")
    def test_get_icon_file(self, sample):
        return_obj = PEGroupIconDir(data=sample("438117c7bd53653b3113903bcdb8bd369904a152b524b4676b18a626c2b60e82"))
        assert (
            return_obj.get_icon_file(idx=0, data=b"FOOBAR")
            == b"\x00\x00\x01\x00\x01\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x16\x00\x00\x00FOOBAR"
        )
