# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pathlib
import struct
import tempfile
from unittest import mock

import pytest

from lib.cuckoo.common.quarantine import bytearray_xor, mbam_unquarantine, mse_unquarantine, trend_unquarantine, unquarantine

# from tcr_misc import get_sample


"""
@pytest.fixture
def grab_sample():
    def _grab_sample(sample_hash):
        sample_location = pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        get_sample(hash=sample_hash, download_location=sample_location)
        return sample_location

    return _grab_sample
"""

QUARANTINED_DATA = b"\xff\xee\xdd\xcc\xbb\xaa"


@pytest.fixture
def empty_file():
    empty_file = tempfile.NamedTemporaryFile(suffix=".but")
    yield empty_file
    empty_file.close()


@pytest.fixture
def temp_trend_qarantined_pe(tmp_path):
    def trend_tag(code: int, tag_data: bytes) -> bytes:
        return struct.pack("<BH", code, len(tag_data)) + tag_data

    def write_quarantine_file(dir):
        tags = b"".join(
            [
                trend_tag(1, ("C:\\" + "\0").encode("utf-16le")),
                trend_tag(2, ("dangerous.exe" + "\0").encode("utf-16le")),
                trend_tag(3, b"win32"),
                trend_tag(4, b"\x00"),
                trend_tag(5, b"\x01"),
                trend_tag(6, b"\x00\x00\x00\x00"),
                trend_tag(7, b"\x01\x00\x00\x00"),
            ]
        )
        magic = 0x58425356
        offset = len(tags) + 10
        numtags = 7
        header = struct.pack("<IIH", magic, offset, numtags)
        file_data = bytearray(header)
        file_data.extend(tags)
        file_data.extend(b"\x00" * 10)
        file_data.extend(QUARANTINED_DATA)
        file_data = bytearray_xor(file_data, 0xFF)
        qfilepath = os.path.join(dir, "quarantined_file")
        with open(qfilepath, "wb") as qfil:
            qfil.write(file_data)
        return qfilepath

    qpath = write_quarantine_file(tmp_path)
    yield qpath
    os.unlink(qpath)


class TestUnquarantine:
    # disabled for test
    """
    def test_mcafee(self, grab_sample):
        sample_hash = "14f715be9d422d367d0a5233515fa1c770728e4a3ff396b1936d1fa30965cc5d"
        sample_location = grab_sample(sample_hash)
        assert (
            unquarantine(sample_location).rsplit(b"/", 1)[-1] == b"14f715be9d422d367d0a5233515fa1c770728e4a3ff396b1936d1fa30965cc5d"
        )

    def test_kaspersky(self, grab_sample):
        sample_hash = "b1c3bea84e2b5931b2ef8397e8ea3ee982cceacaa3987bf870cb712cd5015cc0"
        sample_location = grab_sample(sample_hash)
        assert unquarantine(sample_location).rsplit(b"/", 1)[-1] == b"KAVDequarantineFile"

    def test_trend(self, grab_sample):
        sample_hash = "0b2a20864392f2dd911aed79218e0ed44fd77b299d4b9bd9108c59fe4e551baf"
        sample_location = grab_sample(sample_hash)
        assert (
            unquarantine(sample_location).rsplit(b"/", 1)[-1] == b"0b2a20864392f2dd911aed79218e0ed44fd77b299d4b9bd9108c59fe4e551baf"
        )

    def test_xorff(self, grab_sample):
        sample_hash = "f78151a41250f2bb1b5ca6bd61a427ad1fcf353febb1461e68c52025490827e2"
        sample_location = grab_sample(sample_hash)
        assert (
            xorff_unquarantine(sample_location).rsplit(b"/", 1)[-1]
            == b"f78151a41250f2bb1b5ca6bd61a427ad1fcf353febb1461e68c52025490827e2"
        )

    """

    """
    tmp_path = unquarantine(filename)
    if tmp_path:
        filename = tmp_path
    """

    @pytest.mark.skipif(
        not (pathlib.Path(__file__).parent / "data" / "quarantine").exists(), reason="Required data file is not present"
    )
    def test_mbam(self):
        assert (
            mbam_unquarantine("tests/data/quarantine/d0f51ff313ede61e1c4d7d57b644507a4bd46455e3e617e66c922c8c0c07024b.mbam").rsplit(
                b"/", 1
            )[-1]
            == b"MBAMDequarantineFile"
        )

    @pytest.mark.skipif(
        not (pathlib.Path(__file__).parent / "data" / "quarantine").exists(), reason="Required data file is not present"
    )
    def test_mse(self):
        assert (
            mse_unquarantine("tests/data/quarantine/70dbb01654db5a1518091377f27f9a382657c5e32ecdec5074680215dc3a7f65.mse").rsplit(
                b"/", 1
            )[-1]
            == b"d8e43dfb7662e0eeb26821f"
        )

    """
    def test_sep(self, grab_sample):
        sample_hash = "24589c208c371766bfe9f12fbbc02805500cfee75b3fb051ca8d3ba51edf0cac"
        sample_location = grab_sample(sample_hash)
        assert unquarantine(sample_location).rsplit(b"/", 1)[-1] == b"recycler.lnk"
    """

    def test_ext_err(self, empty_file):
        assert unquarantine(empty_file.name) is None

    def test_trend_unquarantine_normal_file(self, temp_pe32):
        """Test only the file header (first 10 bytes) is XOR'd for non-quarantined files."""
        # The expected output is None
        expected = None

        def bytearray_xor_wrapper(data, key):
            expected_header_length = 10
            actual_header_length = len(data)
            # We only want to see the 10 byte header here if the file is not
            # quarantined.
            assert expected_header_length == actual_header_length
            return data

        def store_temp_file_(filedata, filename, path=None):
            return expected

        # Mock `store_temp_file` to give us visibility into the call.
        with mock.patch("lib.cuckoo.common.quarantine.store_temp_file") as mock_store_temp_file:
            mock_store_temp_file.side_effect = store_temp_file_
            # Mock `bytearray_xor` to give us visibility into any calls.
            with mock.patch("lib.cuckoo.common.quarantine.bytearray_xor") as bytearray_xor_mock:
                bytearray_xor_mock.side_effect = bytearray_xor_wrapper
                actual = trend_unquarantine(temp_pe32)
        # Check there is only a single call to `bytearray_xor`. Two calls means
        # it XOR'd the whole file, which is not what we want.
        bytearray_xor_mock.assert_called_once()
        # Check that it didn't try to save any new files.
        mock_store_temp_file.assert_not_called()
        # Ensure `None` response when no action was performed.
        assert actual == expected

    def test_trend_unquarantine_quarantined_file(self, temp_trend_qarantined_pe, tmp_path):
        """Test the whole file is XOR'd for quarantined files."""
        # We expect the output to be None
        expected = os.path.join(tmp_path, "unqarantined_file")

        def store_temp_file_(filedata, filename, path=None):
            return expected

        # Mock `store_temp_file` to give us visibility into the call.
        with mock.patch("lib.cuckoo.common.quarantine.store_temp_file") as mock_store_temp_file:
            mock_store_temp_file.side_effect = store_temp_file_
            # Mock `bytearray_xor` to give us visibility into the calls.
            with mock.patch("lib.cuckoo.common.quarantine.bytearray_xor") as mock_bytearray_xor:
                mock_bytearray_xor.side_effect = bytearray_xor
                actual = trend_unquarantine(temp_trend_qarantined_pe)
        # Check there are two calls to `bytearray_xor`. One for the header and
        # one for the full file.
        mock_bytearray_xor.assert_has_calls([mock.call(mock.ANY, mock.ANY), mock.call(mock.ANY, mock.ANY)])
        # Assert that it attempts to create a new file with unquarantined data.
        # mock_store_temp_file.assert_called_once_with(QUARANTINED_DATA, mock.ANY)
        # Check that `trend_unquarantine` returns the filepath of the new file.
        assert actual == expected
