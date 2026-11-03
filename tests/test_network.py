# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import unittest.mock as mock
from pathlib import Path

import modules.processing.network as net


def test_pcap2_port_587_handler_1arg(tmp_path: Path):
    """Ensure port 587 handler passes tlsmaster when httpreplay.cut.smtp_handler accepts it."""
    mock_smtp_handler = mock.MagicMock(return_value="smtp_with_tls")
    mock_cut = mock.MagicMock(smtp_handler=mock_smtp_handler)
    mock_httpreplay = mock.MagicMock(cut=mock_cut)

    with mock.patch.object(net, "httpreplay", mock_httpreplay, create=True):
        tlsmaster = {"secret": "0123456789abcdef"}
        pcap2 = net.Pcap2(str(tmp_path / "dummy.pcap"), tlsmaster, str(tmp_path / "network"))

        assert 587 in pcap2.handlers
        res = pcap2.handlers[587]()

        mock_smtp_handler.assert_called_once_with(tlsmaster)
        assert res == "smtp_with_tls"


def test_pcap2_port_587_handler_0arg_fallback(tmp_path: Path):
    """Ensure port 587 handler falls back to 0-arg call if smtp_handler raises TypeError."""

    def fake_smtp_handler(*args):
        if args:
            raise TypeError("smtp_handler() takes 0 positional arguments but 1 was given")
        return "smtp_plain_fallback"

    mock_cut = mock.MagicMock(smtp_handler=mock.MagicMock(side_effect=fake_smtp_handler))
    mock_httpreplay = mock.MagicMock(cut=mock_cut)

    with mock.patch.object(net, "httpreplay", mock_httpreplay, create=True):
        tlsmaster = {"secret": "0123456789abcdef"}
        pcap2 = net.Pcap2(str(tmp_path / "dummy.pcap"), tlsmaster, str(tmp_path / "network"))

        assert 587 in pcap2.handlers
        res = pcap2.handlers[587]()

        assert res == "smtp_plain_fallback"


def test_pcap2_smtp_handler_static_method():
    """Directly test Pcap2._smtp_handler helper with 1-arg and 0-arg implementations."""
    mock_cut_1arg = mock.MagicMock(smtp_handler=mock.MagicMock(return_value="tls_ok"))
    mock_httpreplay_1arg = mock.MagicMock(cut=mock_cut_1arg)

    with mock.patch.object(net, "httpreplay", mock_httpreplay_1arg, create=True):
        assert net.Pcap2._smtp_handler("tls_secret") == "tls_ok"
        mock_cut_1arg.smtp_handler.assert_called_once_with("tls_secret")

    def raise_typeerror(*args):
        if args:
            raise TypeError("takes 0 positional arguments")
        return "plain_ok"

    mock_cut_0arg = mock.MagicMock(smtp_handler=mock.MagicMock(side_effect=raise_typeerror))
    mock_httpreplay_0arg = mock.MagicMock(cut=mock_cut_0arg)

    with mock.patch.object(net, "httpreplay", mock_httpreplay_0arg, create=True):
        assert net.Pcap2._smtp_handler("tls_secret") == "plain_ok"
