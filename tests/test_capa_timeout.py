# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import sys
from pathlib import Path
from types import SimpleNamespace

from lib.cuckoo.common import process_timeout
from lib.cuckoo.common.integrations import capa as capa_mod
from lib.cuckoo.common.integrations import floss as floss_mod


def _enable_capa_config(monkeypatch, **overrides):
    monkeypatch.setattr(capa_mod, "HAVE_FLARE_CAPA", True)
    monkeypatch.setattr(capa_mod, "HAVE_MALCAT_CAPA", False)
    monkeypatch.setattr(capa_mod, "rules", object())
    monkeypatch.setattr(capa_mod.integrations_conf.flare_capa, "enabled", True)
    monkeypatch.setattr(capa_mod.integrations_conf.flare_capa, "on_demand", False)
    monkeypatch.setitem(capa_mod.integrations_conf.flare_capa, "static", True)
    monkeypatch.setitem(capa_mod.integrations_conf.flare_capa, "timeout", 60)
    monkeypatch.setitem(capa_mod.integrations_conf.flare_capa, "task_timeout", 180)
    monkeypatch.setitem(capa_mod.integrations_conf.flare_capa, "on_demand_timeout", 180)
    monkeypatch.setitem(capa_mod.integrations_conf.flare_capa, "skip_packed", True)
    for key, val in overrides.items():
        monkeypatch.setitem(capa_mod.integrations_conf.flare_capa, key, val)


def test_flare_capa_per_call_timeout_returns_empty_and_logs_warning(tmp_path, monkeypatch, caplog):
    process_timeout.reset_task_budgets()
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x90" * 64)
    _enable_capa_config(monkeypatch, timeout=7, task_timeout=180)

    seen_timeouts = []

    def fake_run_with_timeout(fn, timeout, *args, **kwargs):
        seen_timeouts.append(timeout)
        raise TimeoutError("timed out")

    monkeypatch.setattr(capa_mod, "run_with_timeout", fake_run_with_timeout)

    with caplog.at_level(logging.WARNING, logger=capa_mod.__name__):
        res = capa_mod.flare_capa_details(str(sample), "static")

    assert res == {}
    assert seen_timeouts == [7.0]
    assert any("timed out after 7.0s" in r.message for r in caplog.records)
    process_timeout.reset_task_budgets()


def test_flare_capa_result_unavailable_returns_empty_and_logs_warning(tmp_path, monkeypatch, caplog):
    process_timeout.reset_task_budgets()
    sample = tmp_path / "crash.exe"
    sample.write_bytes(b"MZ" + b"\x90" * 64)
    _enable_capa_config(monkeypatch)

    def fake_run_with_timeout(fn, timeout, *args, **kwargs):
        raise process_timeout.ResultUnavailableError("crashed")

    monkeypatch.setattr(capa_mod, "run_with_timeout", fake_run_with_timeout)

    with caplog.at_level(logging.WARNING, logger=capa_mod.__name__):
        res = capa_mod.flare_capa_details(str(sample), "static")

    assert res == {}
    assert any("terminated unexpectedly" in r.message for r in caplog.records)
    process_timeout.reset_task_budgets()


def test_flare_capa_cumulative_task_timeout_exhaustion_warns_once(tmp_path, monkeypatch, caplog):
    process_timeout.reset_task_budgets()
    f1 = tmp_path / "f1.exe"
    f2 = tmp_path / "f2.exe"
    f3 = tmp_path / "f3.exe"
    f1.write_bytes(b"MZ_1")
    f2.write_bytes(b"MZ_2")
    f3.write_bytes(b"MZ_3")
    _enable_capa_config(monkeypatch, timeout=10, task_timeout=5)

    calls = []
    clock = [100.0]
    monkeypatch.setattr(capa_mod.time, "monotonic", lambda: clock[0])

    def fake_run_with_timeout(fn, timeout, *args, **kwargs):
        calls.append((args[0], timeout))
        clock[0] += 6.0  # exhaust the 5s per-task budget on first file
        return {"CAPABILITY": {"ns": ["done"]}}

    monkeypatch.setattr(capa_mod, "run_with_timeout", fake_run_with_timeout)

    with caplog.at_level(logging.WARNING, logger=capa_mod.__name__):
        r1 = capa_mod.flare_capa_details(str(f1), "static")
        r2 = capa_mod.flare_capa_details(str(f2), "static")
        r3 = capa_mod.flare_capa_details(str(f3), "static")

    assert r1 == {"CAPABILITY": {"ns": ["done"]}}
    assert r2 == {}
    assert r3 == {}
    assert calls == [(str(f1), 5.0)]
    budget_warnings = [r for r in caplog.records if "per-task budget" in r.message]
    assert len(budget_warnings) == 1

    # Resetting budgets restores CAPA execution for the next task.
    process_timeout.reset_task_budgets()
    assert capa_mod.flare_capa_details(str(f2), "static") == {"CAPABILITY": {"ns": ["done"]}}
    assert len(calls) == 2
    process_timeout.reset_task_budgets()


def test_flare_capa_on_demand_uses_on_demand_timeout_and_bypasses_budget_and_cache(tmp_path, monkeypatch):
    process_timeout.reset_task_budgets()
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x41" * 32)
    _enable_capa_config(monkeypatch, timeout=10, task_timeout=5, on_demand_timeout=123, skip_packed=True)

    # Exhaust task budget and populate task cache with empty result for this SHA256.
    process_timeout.record_task_budget_elapsed("flare_capa", 99.0)
    sha = capa_mod._file_sha256(str(sample))
    process_timeout.set_cached_task_result("flare_capa", sha, {})

    seen = []

    def fake_run_with_timeout(fn, timeout, file_path, disable_progress, skip_packed):
        seen.append((timeout, file_path, skip_packed))
        return {"CAPABILITY": {"ns": ["ondemand_cap"]}}

    monkeypatch.setattr(capa_mod, "run_with_timeout", fake_run_with_timeout)

    res = capa_mod.flare_capa_details(str(sample), "static", on_demand=True)
    assert res == {"CAPABILITY": {"ns": ["ondemand_cap"]}}
    assert seen == [(123.0, str(sample), False)]
    assert process_timeout._TASK_BUDGET_SPENT["flare_capa"] == 99.0
    process_timeout.reset_task_budgets()


def test_flare_capa_per_task_sha256_dedup(tmp_path, monkeypatch):
    process_timeout.reset_task_budgets()
    p1 = tmp_path / "copy1.exe"
    p2 = tmp_path / "copy2.exe"
    payload = b"MZ_duplicate_binary_content"
    p1.write_bytes(payload)
    p2.write_bytes(payload)
    _enable_capa_config(monkeypatch)

    calls = []

    def fake_run_with_timeout(fn, timeout, *args, **kwargs):
        calls.append(args[0])
        return {"CAPABILITY": {"ns": ["dedup_cap"]}}

    monkeypatch.setattr(capa_mod, "run_with_timeout", fake_run_with_timeout)

    r1 = capa_mod.flare_capa_details(str(p1), "static")
    r1["CAPABILITY"]["ns"].append("caller_mutation")
    r2 = capa_mod.flare_capa_details(str(p2), "static")

    assert len(calls) == 1
    assert r2 == {"CAPABILITY": {"ns": ["dedup_cap"]}}

    process_timeout.reset_task_budgets()
    r3 = capa_mod.flare_capa_details(str(p2), "static")
    assert len(calls) == 2
    assert r3 == {"CAPABILITY": {"ns": ["dedup_cap"]}}
    process_timeout.reset_task_budgets()


def _setup_fake_capa_execution(monkeypatch, detected_format, has_limitation=False):
    fake_rules = SimpleNamespace(rules={})
    fake_sigs = [Path("/tmp/fake_sig.sig")]
    calls = {"get_extractor": [], "get_file_extractors": []}

    class _DummyMatch:
        matches = {}

    class _DummyCaps:
        matches = {}

    fake_capa = SimpleNamespace(
        helpers=SimpleNamespace(get_auto_format=lambda p: detected_format),
        features=SimpleNamespace(
            common=SimpleNamespace(
                FORMAT_PE="pe",
                FORMAT_DOTNET="dotnet",
                STATIC_FORMATS={"pe", "dotnet", "elf", "sc32", "sc64"},
            )
        ),
        loader=SimpleNamespace(
            BACKEND_VIV="vivisect",
            BACKEND_DOTNET="dotnet",
            get_file_extractors=lambda p, fmt: calls["get_file_extractors"].append((p, fmt)) or ["file_ext"],
            get_extractor=lambda path, fmt, os_, backend, sigpaths, save_ws, disable_progress=True: (
                calls["get_extractor"].append((path, fmt, backend, list(sigpaths))) or "extractor"
            ),
            collect_metadata=lambda *a, **k: SimpleNamespace(analysis=SimpleNamespace(layout=None)),
            compute_layout=lambda *a, **k: "layout",
        ),
        capabilities=SimpleNamespace(
            common=SimpleNamespace(
                find_file_capabilities=lambda r, fe, ff: _DummyCaps(),
                has_static_limitation=lambda r, caps, is_standalone=True: has_limitation,
                find_capabilities=lambda r, ext, disable_progress=True: _DummyCaps(),
            )
        ),
        exceptions=SimpleNamespace(
            UnsupportedArchError=type("UnsupportedArchError", (Exception,), {}),
            UnsupportedOSError=type("UnsupportedOSError", (Exception,), {}),
        ),
    )

    monkeypatch.setattr(capa_mod, "_ensure_capa_loaded", lambda force=False: True)
    monkeypatch.setattr(capa_mod, "rules", fake_rules)
    monkeypatch.setattr(capa_mod, "signatures", fake_sigs)
    monkeypatch.setattr(capa_mod, "rules_path", "/tmp/capa-rules", raising=False)
    monkeypatch.setattr(capa_mod, "capa", fake_capa, raising=False)
    monkeypatch.setattr(capa_mod, "FORMAT_AUTO", "auto", raising=False)
    monkeypatch.setattr(capa_mod, "OS_AUTO", "auto", raising=False)
    monkeypatch.setattr(capa_mod, "UnsupportedFormatError", type("UnsupportedFormatError", (Exception,), {}), raising=False)
    monkeypatch.setattr(capa_mod, "EmptyReportError", type("EmptyReportError", (Exception,), {}), raising=False)
    monkeypatch.setattr(capa_mod, "rd", SimpleNamespace(ResultDocument=SimpleNamespace(from_capa=lambda m, r, matches: "doc")), raising=False)
    monkeypatch.setattr(capa_mod, "render_dictionary", lambda doc: {"CAPABILITY": {"ns": ["ok"]}})
    monkeypatch.setitem(sys.modules, "capa.helpers", fake_capa.helpers)
    return calls, fake_sigs


def test_run_capa_static_passes_flirt_signatures_for_pe_viv(monkeypatch, tmp_path):
    sample = tmp_path / "pe.exe"
    sample.write_bytes(b"MZ")
    calls, fake_sigs = _setup_fake_capa_execution(monkeypatch, detected_format="pe", has_limitation=False)

    res = capa_mod._run_capa_static(str(sample), disable_progress=True, skip_packed=True)
    assert res == {"CAPABILITY": {"ns": ["ok"]}}
    assert len(calls["get_file_extractors"]) == 1
    assert calls["get_extractor"] == [(Path(sample), "pe", "vivisect", fake_sigs)]


def test_run_capa_static_routes_dotnet_to_backend_dotnet(monkeypatch, tmp_path):
    sample = tmp_path / "dotnet.exe"
    sample.write_bytes(b"MZ")
    calls, _ = _setup_fake_capa_execution(monkeypatch, detected_format="dotnet", has_limitation=False)

    res = capa_mod._run_capa_static(str(sample), disable_progress=True, skip_packed=True)
    assert res == {"CAPABILITY": {"ns": ["ok"]}}
    assert calls["get_file_extractors"] == []
    assert calls["get_extractor"] == [(Path(sample), "dotnet", "dotnet", [])]


def test_run_capa_static_skip_packed_short_circuits_on_static_limitation(monkeypatch, tmp_path, caplog):
    sample = tmp_path / "packed.exe"
    sample.write_bytes(b"MZ")
    calls, _ = _setup_fake_capa_execution(monkeypatch, detected_format="pe", has_limitation=True)

    with caplog.at_level(logging.INFO, logger=capa_mod.__name__):
        res = capa_mod._run_capa_static(str(sample), disable_progress=True, skip_packed=True)

    assert res == {}
    assert len(calls["get_file_extractors"]) == 1
    assert calls["get_extractor"] == []
    assert any("static limitation" in r.message for r in caplog.records)


def test_run_capa_static_skips_non_static_and_corrupt_pe_without_vivisect(monkeypatch, tmp_path, caplog):
    archive = tmp_path / "report.zip"
    archive.write_bytes(b"PK\x03\x04")
    calls, _ = _setup_fake_capa_execution(monkeypatch, detected_format="vmray", has_limitation=False)

    with caplog.at_level(logging.WARNING, logger=capa_mod.__name__):
        assert capa_mod._run_capa_static(str(archive), disable_progress=True, skip_packed=True) == {}
    assert calls["get_extractor"] == []
    assert any("non-static format vmray" in r.message for r in caplog.records)

    def _raise_unsupported(_path):
        raise capa_mod.UnsupportedFormatError("bad header")

    monkeypatch.setattr(sys.modules["capa.helpers"], "get_auto_format", _raise_unsupported)
    with caplog.at_level(logging.WARNING, logger=capa_mod.__name__):
        assert capa_mod._run_capa_static(str(archive), disable_progress=True, skip_packed=True) == {}
    assert calls["get_extractor"] == []


def _enable_floss_config(monkeypatch, **overrides):
    monkeypatch.setattr(floss_mod, "HAVE_FLOSS", True)
    monkeypatch.setattr(floss_mod.integrations_conf.floss, "enabled", True)
    monkeypatch.setattr(floss_mod.integrations_conf.floss, "on_demand", False)
    monkeypatch.setitem(floss_mod.integrations_conf.floss, "timeout", 60)
    monkeypatch.setitem(floss_mod.integrations_conf.floss, "task_timeout", 180)
    monkeypatch.setitem(floss_mod.integrations_conf.floss, "on_demand_timeout", 180)
    monkeypatch.setitem(floss_mod.integrations_conf.floss, "min_length", 5)
    monkeypatch.setitem(floss_mod.integrations_conf.floss, "static_strings", False)
    monkeypatch.setitem(floss_mod.integrations_conf.floss, "stack_strings", True)
    monkeypatch.setitem(floss_mod.integrations_conf.floss, "tight_strings", True)
    monkeypatch.setitem(floss_mod.integrations_conf.floss, "decoded_strings", True)
    monkeypatch.setitem(floss_mod.integrations_conf.floss, "sigs_path", "data/flare-signatures")
    for key, val in overrides.items():
        monkeypatch.setitem(floss_mod.integrations_conf.floss, key, val)


def test_floss_timeout_crash_budget_and_sha256_dedup(tmp_path, monkeypatch, caplog):
    process_timeout.reset_task_budgets()
    f1 = tmp_path / "a.exe"
    f2 = tmp_path / "b.exe"
    f3 = tmp_path / "c.exe"
    f1.write_bytes(b"MZ_FLOSS_SAME")
    f2.write_bytes(b"MZ_FLOSS_SAME")
    f3.write_bytes(b"MZ_FLOSS_OTHER")
    _enable_floss_config(monkeypatch, timeout=9, task_timeout=20, on_demand_timeout=150)

    # 1. TimeoutError -> {}
    monkeypatch.setattr(floss_mod, "run_with_timeout", lambda *a, **k: (_ for _ in ()).throw(TimeoutError("too slow")))
    with caplog.at_level(logging.WARNING, logger=floss_mod.__name__):
        assert floss_mod.Floss(str(f1), "pe").run() == {}
    assert any("FLOSS -> timed out after 9.0s" in r.message for r in caplog.records)

    # 2. ResultUnavailableError -> {}
    process_timeout.reset_task_budgets()
    monkeypatch.setattr(
        floss_mod,
        "run_with_timeout",
        lambda *a, **k: (_ for _ in ()).throw(process_timeout.ResultUnavailableError("oom")),
    )
    with caplog.at_level(logging.WARNING, logger=floss_mod.__name__):
        assert floss_mod.Floss(str(f1), "pe").run() == {}
    assert any("FLOSS -> analysis process terminated unexpectedly" in r.message for r in caplog.records)

    # 3. Per-task SHA256 dedup (same SHA256+package cached; different package runs again) + budget exhaustion
    process_timeout.reset_task_budgets()
    calls = []
    clock = [10.0]
    monkeypatch.setattr(floss_mod.time, "monotonic", lambda: clock[0])

    def fake_run_floss(fn, timeout, file_path, package, *rest):
        calls.append((file_path, package, timeout))
        clock[0] += 12.0
        return {"stack_strings": [f"str_{package}"]}

    monkeypatch.setattr(floss_mod, "run_with_timeout", fake_run_floss)

    assert floss_mod.Floss(str(f1), "pe").run() == {"stack_strings": ["str_pe"]}
    assert floss_mod.Floss(str(f2), "pe").run() == {"stack_strings": ["str_pe"]}
    assert len(calls) == 1

    # Different package runs with remaining 8s budget, pushing spent to 24s (>20s)
    assert floss_mod.Floss(str(f2), "shellcode").run() == {"stack_strings": ["str_shellcode"]}
    assert len(calls) == 2

    # Third distinct file hits budget exhaustion
    with caplog.at_level(logging.WARNING, logger=floss_mod.__name__):
        assert floss_mod.Floss(str(f3), "pe").run() == {}
    assert len(calls) == 2

    # On-demand bypasses exhausted budget and cache
    assert floss_mod.Floss(str(f1), "pe", on_demand=True).run() == {"stack_strings": ["str_pe"]}
    assert calls[-1] == (str(f1), "pe", 150.0)
    process_timeout.reset_task_budgets()


def test_flare_capa_preflight_skips_spawn_for_unsupported_and_packed_files(tmp_path, monkeypatch):
    process_timeout.reset_task_budgets()
    try:
        sample = tmp_path / "packed.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 64)
        _enable_capa_config(monkeypatch, timeout=10, task_timeout=60, skip_packed=True)
        calls, _ = _setup_fake_capa_execution(monkeypatch, detected_format="pe", has_limitation=True)
        monkeypatch.setattr(capa_mod, "_CAPA_MODULES_LOADED", True)

        standalone_flags = []

        def fake_has_static_limitation(r, caps, is_standalone=True):
            standalone_flags.append(is_standalone)
            return True

        monkeypatch.setattr(capa_mod.capa.capabilities.common, "has_static_limitation", fake_has_static_limitation)

        spawn_calls = []
        monkeypatch.setattr(capa_mod, "run_with_timeout", lambda *a, **k: spawn_calls.append(a) or {"ok": True})

        # 1. Packed PE is short-circuited in parent without spawning a child or consuming budget.
        assert capa_mod.flare_capa_details(str(sample), "static") == {}
        assert spawn_calls == []
        assert standalone_flags == [False]
        assert process_timeout._TASK_BUDGET_SPENT.get("flare_capa", 0.0) == 0.0

        # 2. Non-static format is short-circuited in parent without spawning a child.
        process_timeout.reset_task_budgets()
        non_static = tmp_path / "archive.zip"
        non_static.write_bytes(b"PK\x03\x04")
        monkeypatch.setattr(sys.modules["capa.helpers"], "get_auto_format", lambda _p: "vmray")
        assert capa_mod.flare_capa_details(str(non_static), "static") == {}
        assert spawn_calls == []

        # 3. UnsupportedFormatError is short-circuited in parent without spawning a child.
        process_timeout.reset_task_budgets()
        corrupt = tmp_path / "corrupt.bin"
        corrupt.write_bytes(b"garbage")

        def _raise_unsupported(_p):
            raise capa_mod.UnsupportedFormatError("bad")

        monkeypatch.setattr(sys.modules["capa.helpers"], "get_auto_format", _raise_unsupported)
        assert capa_mod.flare_capa_details(str(corrupt), "static") == {}
        assert spawn_calls == []
    finally:
        process_timeout.reset_task_budgets()


def test_flare_capa_on_demand_behavior_loads_rules_even_with_malcat_capa(tmp_path, monkeypatch):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    monkeypatch.setattr(capa_mod, "HAVE_FLARE_CAPA", False)
    monkeypatch.setattr(capa_mod, "HAVE_MALCAT_CAPA", True)
    monkeypatch.setattr(capa_mod, "rules", False)

    loaded = []

    def fake_ensure(force=False):
        loaded.append(force)
        capa_mod.rules = object()
        return True

    monkeypatch.setattr(capa_mod, "_ensure_capa_loaded", fake_ensure)
    monkeypatch.setattr(capa_mod, "_run_capa_report", lambda fp, res, disable_progress=True: {"CAPABILITY": {"ns": ["beh"]}})

    out = capa_mod.flare_capa_details(str(sample), "behavior", on_demand=True, backend="cape", results={"behavior": {}})
    assert loaded == [True]
    assert out == {"CAPABILITY": {"ns": ["beh"]}}


def test_floss_skips_spawn_for_unsupported_non_shellcode_files(tmp_path, monkeypatch):
    process_timeout.reset_task_budgets()
    try:
        sample = tmp_path / "plain.txt"
        sample.write_bytes(b"not a pe file")
        _enable_floss_config(monkeypatch, timeout=10, task_timeout=60)
        monkeypatch.setattr(floss_mod, "fm", SimpleNamespace(is_supported_file_type=lambda _p: False), raising=False)

        spawn_calls = []
        monkeypatch.setattr(floss_mod, "run_with_timeout", lambda *a, **k: spawn_calls.append(a) or {"stack_strings": ["sc"]})

        # Non-PE with non-shellcode package skips run_with_timeout completely.
        assert floss_mod.Floss(str(sample), "pe").run() == {}
        assert spawn_calls == []
        assert process_timeout._TASK_BUDGET_SPENT.get("floss", 0.0) == 0.0

        # Shellcode packages still proceed to run_with_timeout.
        assert floss_mod.Floss(str(sample), "shellcode").run() == {"stack_strings": ["sc"]}
        assert floss_mod.Floss(str(sample), "shellcode_x64").run() == {"stack_strings": ["sc"]}
        assert len(spawn_calls) == 2
    finally:
        process_timeout.reset_task_budgets()
