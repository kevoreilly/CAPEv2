# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import pathlib
from unittest.mock import MagicMock

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


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("buffer is not large enough"),
        OSError("Unsupported BMP header type (1852795252)"),
    ],
)
def test_get_icon_info_logs_debug_not_error(caplog, monkeypatch, exc):
    import pefile

    import lib.cuckoo.common.integrations.parse_pe as parse_pe

    pe_helper = parse_pe.PortableExecutable("/tmp/fake.exe")

    fake_entry = MagicMock()
    fake_entry.id = 1
    fake_entry.directory.entries = [MagicMock(data=MagicMock(struct=MagicMock(OffsetToData=0, Size=16)))]

    fake_group_dir = MagicMock()
    fake_group_dir.id = pefile.RESOURCE_TYPE["RT_GROUP_ICON"]
    fake_group_dir.directory.entries = [fake_entry]

    fake_icon_dir = MagicMock()
    fake_icon_dir.id = pefile.RESOURCE_TYPE["RT_ICON"]
    fake_icon_dir.directory.entries = [fake_entry]

    fake_pe = MagicMock()
    fake_pe.DIRECTORY_ENTRY_RESOURCE.entries = [fake_group_dir, fake_icon_dir]
    fake_pe.get_memory_mapped_image.return_value = b"\x00" * 64

    fake_icon_meta = MagicMock(bWidth=32, bHeight=32, wBitCount=32, nID=1)
    fake_peicon = MagicMock()
    fake_peicon.icons = [fake_icon_meta]
    fake_peicon.get_icon_file.return_value = b"bad_icon_bytes"

    monkeypatch.setattr(parse_pe, "PEGroupIconDir", lambda data: fake_peicon)
    monkeypatch.setattr(parse_pe.Image, "open", MagicMock(side_effect=exc))

    with caplog.at_level(logging.DEBUG, logger=parse_pe.__name__):
        res = pe_helper.get_icon_info(fake_pe)

    assert res == (None, None, None, None)
    assert not any(r.levelname == "ERROR" for r in caplog.records)

