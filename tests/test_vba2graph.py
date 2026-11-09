# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from unittest.mock import MagicMock

import pytest

from lib.cuckoo.common.integrations import vba2graph


def test_vba2graph_does_not_monkeypatch_detect_vba_stomping():
    olevba = pytest.importorskip("oletools.olevba")
    # Real method on VBA_Parser must remain intact rather than being replaced with lambda self: False
    assert olevba.VBA_Parser.detect_vba_stomping.__name__ != "<lambda>"


def test_vba2graph_from_vba_object_returns_false_without_oletools(monkeypatch):
    monkeypatch.setattr(vba2graph, "HAVE_OLETOOLS", False)
    assert vba2graph.vba2graph_from_vba_object("/tmp/nonexistent.doc") is False


def test_vba2graph_from_vba_object_always_closes_vba_on_error(monkeypatch):
    mock_vba = MagicMock()
    mock_vba.extract_macros.side_effect = RuntimeError("broken stream")

    monkeypatch.setattr(vba2graph, "HAVE_OLETOOLS", True)
    monkeypatch.setattr(vba2graph, "VBA_Parser", MagicMock(return_value=mock_vba), raising=False)

    with pytest.raises(RuntimeError, match="broken stream"):
        vba2graph.vba2graph_from_vba_object("/tmp/broken.docm")

    mock_vba.close.assert_called_once()
