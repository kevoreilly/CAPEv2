import sys
from unittest.mock import Mock

import pytest

import utils.process as process


def test_main_reconciles_mongodb_indexes_before_modules(monkeypatch):
    calls = []

    monkeypatch.setattr(sys, "argv", ["process.py", "auto"])
    monkeypatch.setattr(process, "init_database", Mock())
    monkeypatch.setattr(process, "init_logging", Mock(return_value=[]))

    monkeypatch.setattr(
        process,
        "check_webgui_mongo",
        Mock(side_effect=lambda **kwargs: calls.append(("mongo", kwargs))),
    )
    monkeypatch.setattr(
        process,
        "init_modules",
        Mock(side_effect=lambda: calls.append(("modules", {}))),
    )
    monkeypatch.setattr(
        process,
        "autoprocess",
        Mock(side_effect=RuntimeError("stop after startup")),
    )

    with pytest.raises(RuntimeError, match="stop after startup"):
        process.main()

    assert calls == [
        ("mongo", {"exit_on_connection_failure": False}),
        ("modules", {}),
    ]
