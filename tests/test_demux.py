# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pathlib
import tempfile

import pytest
from tcr_misc import get_sample

from lib.cuckoo.common import demux


@pytest.fixture
def grab_sample():
    def _grab_sample(sample_hash):
        sample_location = pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        get_sample(hash=sample_hash, download_location=sample_location)
        return sample_location

    return _grab_sample


class TestDemux:
    """ToDo reenable
    @pytest.mark.skip("Takes minutes to run, skipping!")
    def test_demux_sample_microsoft_docx(self, grab_sample):
        # .docx file
        sample_hash = "c0c1c1c852a045eb3eb3b26dad2124aea866ea008449e0d7a84925c2ded7fddb"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foobar") == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]

    def test_demux_sample_microsoft_no_sflock_docx(self, grab_sample):
        # .docx file
        sample_hash = "c0c1c1c852a045eb3eb3b26dad2124aea866ea008449e0d7a84925c2ded7fddb"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foobar", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]

    def test_demux_sample_microsoft_password_no_sflock_doc(self, grab_sample):
        # password protected .doc file
        sample_hash = "d211ce5c36f630aa1e85d4f36291fee2a600216d823d23805fe41bb68ea99dbb"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="password=infected", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]

    def test_demux_sample_microsoft_no_password_no_sflock_doc(self, grab_sample):
        # no password .doc file
        sample_hash = "d211ce5c36f630aa1e85d4f36291fee2a600216d823d23805fe41bb68ea99dbb"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foo", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]

    def test_demux_sample_java(self, grab_sample):
        # java class file for a simple hello world
        sample_hash = "27c428570256f0e5f8229d053f352aea4276e5c9c5a601c20e04535a8ba1e41d"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foo", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]


    def test_demux_sample_microsoft_outlook(self, grab_sample):
        # outlook message from https://github.com/HamiltonInsurance/outlook_msg/blob/e6c0293f098e8aee9cd4124aa6a5d409c798bc49/test_data/No%20attachment.msg
        sample_hash = "0e16568cc1e8ddda0f0856b27857d1d043d7b18909a566ae5fa2460fc8fd3614"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foo", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]

    def test_demux_sample_pe32(self, grab_sample):
        # pe32 from https://github.com/bootandy/dust/releases/download/v0.5.4/dust-v0.5.4-i686-pc-windows-msvc.zip
        sample_hash = "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foo", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]
    """

    def test_demux_package(self):
        empty_file = tempfile.NamedTemporaryFile()

        demuxed, _ = demux.demux_sample(filename=empty_file.name, package="Emotet", options="foo", use_sflock=False)
        demuxed == [(empty_file.name, "", "")]
        empty_file.close()

    def test_options2passwd(self):
        options = "password=foobar"
        demux.options2passwd(options)
