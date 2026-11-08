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


def test_build_arg_parser_reads_conf_and_custom_processor_env(tmp_path):
    conf_dir = tmp_path / "conf"
    custom_dir = tmp_path / "custom" / "conf"
    conf_dir.mkdir(parents=True, exist_ok=True)
    custom_dir.mkdir(parents=True, exist_ok=True)

    (conf_dir / "cape-processor.env").write_text(
        "# Comment line\n"
        "CAPE_PARALLEL=5\n"
        "CAPE_PROCESSING_TIMEOUT=600 # inline comment\n"
        "export CAPE_ENGINE='prefork'\n",
        encoding="utf-8",
    )
    (custom_dir / "cape-processor.env").write_text(
        'CAPE_PARALLEL="2"\n'
        "CAPE_MAXTASKSPERCHILD=0\n",
        encoding="utf-8",
    )

    # Standalone CLI (no INVOCATION_ID): custom/conf overrides conf/
    parser = process.build_arg_parser(cuckoo_root=str(tmp_path), environ={})
    args = parser.parse_args([])
    assert args.parallel == 2
    assert args.processing_timeout == 600
    assert args.maxtasksperchild == 0
    assert args.engine == "prefork"

    # Explicit CLI environment variable overrides .env files outside systemd
    parser_cli_env = process.build_arg_parser(
        cuckoo_root=str(tmp_path),
        environ={"CAPE_PARALLEL": "4"},
    )
    assert parser_cli_env.parse_args([]).parallel == 4

    # Explicit CLI flag (-p) overrides everything
    assert parser_cli_env.parse_args(["-p", "3"]).parallel == 3


def test_build_arg_parser_custom_env_overrides_stale_systemd_unit_default(tmp_path):
    """If an existing host has an older /lib/systemd/system/cape-processor.service
    with Environment=CAPE_PARALLEL=7 and without EnvironmentFile=.../custom/conf/cape-processor.env,
    custom/conf/cape-processor.env must still take effect under systemd (INVOCATION_ID)."""
    custom_dir = tmp_path / "custom" / "conf"
    custom_dir.mkdir(parents=True, exist_ok=True)
    (custom_dir / "cape-processor.env").write_text("CAPE_PARALLEL=2\n", encoding="utf-8")

    parser = process.build_arg_parser(
        cuckoo_root=str(tmp_path),
        environ={"INVOCATION_ID": "systemd-unit-123", "CAPE_PARALLEL": "7"},
    )
    assert parser.parse_args([]).parallel == 2


def test_build_arg_parser_clamps_invalid_parallel(tmp_path):
    custom_dir = tmp_path / "custom" / "conf"
    custom_dir.mkdir(parents=True, exist_ok=True)
    (custom_dir / "cape-processor.env").write_text("CAPE_PARALLEL=0\n", encoding="utf-8")

    parser = process.build_arg_parser(cuckoo_root=str(tmp_path), environ={})
    assert parser.parse_args([]).parallel == 1

    (custom_dir / "cape-processor.env").write_text("CAPE_PARALLEL=invalid\n", encoding="utf-8")
    parser_bad = process.build_arg_parser(cuckoo_root=str(tmp_path), environ={})
    assert parser_bad.parse_args([]).parallel == 1
