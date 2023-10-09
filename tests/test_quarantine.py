# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import tempfile

import pytest

from lib.cuckoo.common.quarantine import mbam_unquarantine, mse_unquarantine, unquarantine

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


@pytest.fixture
def empty_file():
    empty_file = tempfile.NamedTemporaryFile(suffix=".but")
    yield empty_file
    empty_file.close()


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

    def test_mbam(self):
        assert (
            mbam_unquarantine("tests/data/quarantine/d0f51ff313ede61e1c4d7d57b644507a4bd46455e3e617e66c922c8c0c07024b.mbam").rsplit(
                b"/", 1
            )[-1]
            == b"MBAMDequarantineFile"
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
