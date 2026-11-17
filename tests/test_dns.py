# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import socket
import unittest.mock as mock

import pytest

import lib.cuckoo.common.dns as cape_dns


@pytest.mark.parametrize(
    "name",
    [
        "example.com",
        "example.com.",
        "8.8.8.8.in-addr.arpa.",
        "_dmarc.example.com",
        "localhost",
        "münchen.de",
        "1.2.3.4",
        "a." * 126 + "a",
    ],
)
def test_is_valid_dns_name_accepts_valid_names(name):
    assert cape_dns._is_valid_dns_name(name) is True


@pytest.mark.parametrize(
    "name",
    [
        None,
        "",
        "   ",
        "localhost\x00\x00",
        "example\x00.com",
        "foo\x01bar.com",
        "foo\x7f.com",
        "foo bar.com",
        "foo\\x00.com",
        ".",
        ".example.com",
        "a..b.com",
        "a" * 64 + ".com",
        "".join(chr(0x4E00 + i * 977) for i in range(21)),
        "a." * 126 + "ab",
    ],
)
def test_is_valid_dns_name_rejects_malformed_names(name):
    assert cape_dns._is_valid_dns_name(name) is False


@pytest.mark.parametrize(
    "name",
    [
        "example\x00.com",
        "localhost\x00\x00\x00",
        "",
        "   ",
        ".",
        ".example.com",
        "a..b.com",
        "a" * 64 + ".com",
        "".join(chr(0x4E00 + i * 977) for i in range(21)),
    ],
)
def test_gethostbyname_and_resolve_thread_skip_invalid_names(name):
    with mock.patch("lib.cuckoo.common.dns.socket.gethostbyname") as mock_ghbn:
        result_ghbn = cape_dns.gethostbyname(name)
        result_thread = cape_dns.resolve_thread(name)
        assert result_ghbn == ""
        assert result_thread == ""
        assert result_ghbn != "0.0.0.0"
        mock_ghbn.assert_not_called()


def test_gethostbyname_valid_and_exception_handling():
    with mock.patch("lib.cuckoo.common.dns.socket.gethostbyname", return_value="93.184.216.34") as mock_ghbn:
        assert cape_dns.gethostbyname("example.com") == "93.184.216.34"
        mock_ghbn.assert_called_once_with("example.com")

    with mock.patch("lib.cuckoo.common.dns.socket.gethostbyname", side_effect=socket.gaierror("NXDOMAIN")):
        assert cape_dns.gethostbyname("missing.example.invalid") == ""

    with mock.patch("lib.cuckoo.common.dns.socket.gethostbyname", side_effect=UnicodeError("label empty or too long")):
        assert cape_dns.gethostbyname("example.com") == ""

    with mock.patch("lib.cuckoo.common.dns.socket.gethostbyname", side_effect=ValueError("embedded null byte")):
        assert cape_dns.gethostbyname("example.com") == ""


def test_resolve_cares_skips_invalid_handles_empty_socks_and_destroys_channel(monkeypatch):
    fake_pycares = mock.MagicMock()
    monkeypatch.setattr(cape_dns, "pycares", fake_pycares, raising=False)
    monkeypatch.setattr(cape_dns, "HAVE_CARES", True)

    with mock.patch("lib.cuckoo.common.dns.select.select") as mock_select:
        assert cape_dns.resolve_cares("localhost\x00\x00") == ""
        assert cape_dns.resolve_cares("") == ""
        fake_pycares.Channel.assert_not_called()
        mock_select.assert_not_called()

    # Empty socket set must not call select.select(DNS_TIMEOUT) and must destroy the channel.
    chan_empty = mock.MagicMock()
    chan_empty.getsock.return_value = ([], [])
    fake_pycares.Channel.return_value = chan_empty
    with mock.patch("lib.cuckoo.common.dns.select.select") as mock_select:
        assert cape_dns.resolve_cares("example.com") == ""
        mock_select.assert_not_called()
        chan_empty.destroy.assert_called_once()

    # Exception inside c-ares call must still destroy the channel cleanly.
    chan_err = mock.MagicMock()
    chan_err.gethostbyname.side_effect = ValueError("embedded null byte")
    fake_pycares.Channel.return_value = chan_err
    assert cape_dns.resolve_cares("example.com") == ""
    chan_err.destroy.assert_called_once()


def test_resolve_doh_and_resolve_skip_invalid_names_across_backends(monkeypatch):
    fake_session = mock.MagicMock()
    fake_pycares = mock.MagicMock()
    monkeypatch.setattr(cape_dns, "HAVE_REQUESTS", True)
    monkeypatch.setattr(cape_dns, "DOH_SESSION", fake_session)
    monkeypatch.setattr(cape_dns, "pycares", fake_pycares, raising=False)

    for bad_name in ("", "localhost\x00\x00", ".example.com", "a..b.com"):
        monkeypatch.setattr(cape_dns, "USE_DOH", True)
        monkeypatch.setattr(cape_dns, "HAVE_CARES", False)
        assert cape_dns.resolve_doh(bad_name) == ""
        assert cape_dns.resolve(bad_name) == ""

        monkeypatch.setattr(cape_dns, "USE_DOH", False)
        monkeypatch.setattr(cape_dns, "HAVE_CARES", True)
        assert cape_dns.resolve(bad_name) == ""

        monkeypatch.setattr(cape_dns, "HAVE_CARES", False)
        with mock.patch("lib.cuckoo.common.dns.socket.gethostbyname") as mock_ghbn:
            assert cape_dns.resolve(bad_name) == ""
            mock_ghbn.assert_not_called()

    fake_session.get.assert_not_called()
    fake_pycares.Channel.assert_not_called()
