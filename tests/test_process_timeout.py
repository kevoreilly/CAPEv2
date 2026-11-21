# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import operator
import os
import signal
import subprocess
import sys
import threading
import time
import warnings

import psutil
import pytest

from lib.cuckoo.common import process_timeout


def test_budget_helpers_and_result_cache_isolation():
    process_timeout.reset_task_budgets()
    try:
        assert process_timeout.resolve_call_timeout("capa", None, None) == 0.0
        assert process_timeout.resolve_call_timeout("capa", 0, 0) == 0.0
        assert process_timeout.resolve_call_timeout("capa", 60, 0) == 60.0
        assert process_timeout.resolve_call_timeout("capa", 0, 180) == 180.0
        assert process_timeout.resolve_call_timeout("capa", 60, 180) == 60.0

        process_timeout.record_task_budget_elapsed("capa", 150.0)
        assert process_timeout.resolve_call_timeout("capa", 60, 180) == pytest.approx(30.0)

        process_timeout.record_task_budget_elapsed("capa", 35.0)
        assert process_timeout.resolve_call_timeout("capa", 60, 180) == -1.0

        assert process_timeout.mark_budget_warned("capa") is True
        assert process_timeout.mark_budget_warned("capa") is False

        hit, val = process_timeout.get_cached_task_result("flare_capa", "deadbeef")
        assert hit is False and val is None

        original = {"CAPABILITY": {"ns": ["a"]}}
        process_timeout.set_cached_task_result("flare_capa", "deadbeef", original)
        original["CAPABILITY"]["ns"].append("mutated_after_set")

        hit, cached = process_timeout.get_cached_task_result("flare_capa", "deadbeef")
        assert hit is True
        assert cached == {"CAPABILITY": {"ns": ["a"]}}
        cached["CAPABILITY"]["ns"].append("mutated_after_get")

        hit2, cached2 = process_timeout.get_cached_task_result("flare_capa", "deadbeef")
        assert hit2 is True
        assert cached2 == {"CAPABILITY": {"ns": ["a"]}}
    finally:
        process_timeout.reset_task_budgets()

    assert process_timeout.mark_budget_warned("capa") is True
    assert process_timeout.resolve_call_timeout("capa", 60, 180) == 60.0
    assert process_timeout.get_cached_task_result("flare_capa", "deadbeef") == (False, None)
    process_timeout.reset_task_budgets()


@pytest.mark.parametrize("bad_timeout", [0, 0.0, None, -5])
def test_run_with_timeout_synchronous_fallback(bad_timeout):
    assert process_timeout.run_with_timeout(os.getpid, bad_timeout) == os.getpid()


def _make_large_payload(count: int) -> dict[str, list[str]]:
    return {"items": [f"entry-{idx:06d}-" + ("x" * 64) for idx in range(count)]}


@pytest.mark.parametrize("start_method", ["fork", "spawn"])
def test_run_with_timeout_returns_value_and_propagates_exception(start_method):
    if start_method == "fork" and not hasattr(os, "fork"):
        pytest.skip("fork not available on this platform")

    assert process_timeout.run_with_timeout(operator.add, 10, 19, 23, start_method=start_method) == 42

    large = process_timeout.run_with_timeout(_make_large_payload, 10, 8000, start_method=start_method)
    assert len(large["items"]) == 8000

    with pytest.raises(ValueError):
        process_timeout.run_with_timeout(int, 10, "not_an_int", start_method=start_method)


@pytest.mark.parametrize("start_method", ["fork", "spawn"])
def test_run_with_timeout_kills_timed_out_child_without_leaking_pid(start_method):
    if start_method == "fork" and not hasattr(os, "fork"):
        pytest.skip("fork not available on this platform")

    before_pids = {p.pid for p in psutil.Process(os.getpid()).children(recursive=True)}

    with pytest.raises(TimeoutError):
        process_timeout.run_with_timeout(time.sleep, 0.25, 30, start_method=start_method)

    # Give the OS a brief moment in case async reap finished just after wait()
    deadline = time.monotonic() + 2.0
    leaked = set()
    while time.monotonic() < deadline:
        after_pids = {p.pid for p in psutil.Process(os.getpid()).children(recursive=True)}
        leaked = after_pids - before_pids
        if not leaked:
            break
        time.sleep(0.05)

    assert leaked == set()
    assert len(process_timeout._ACTIVE_TIMEOUT_PROCS) == 0


@pytest.mark.parametrize("start_method", ["fork", "spawn"])
def test_run_with_timeout_raises_result_unavailable_on_child_crash(start_method):
    if start_method == "fork" and not hasattr(os, "fork"):
        pytest.skip("fork not available on this platform")

    with pytest.raises(process_timeout.ResultUnavailableError):
        process_timeout.run_with_timeout(os._exit, 10, 137, start_method=start_method)


def test_multithreaded_run_with_timeout_uses_spawn_without_deprecation_warning():
    stop_evt = threading.Event()
    bg_thread = threading.Thread(target=stop_evt.wait, daemon=True)
    bg_thread.start()
    try:
        assert process_timeout._is_single_threaded() is False
        assert process_timeout._select_mp_context().get_start_method() == "spawn"
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            assert process_timeout.run_with_timeout(operator.add, 10, 20, 22) == 42
    finally:
        stop_evt.set()
        bg_thread.join(timeout=2)


def test_active_pebble_pool_selects_spawn_without_deprecation_warning():
    if not hasattr(os, "fork"):
        pytest.skip("fork not available on this platform")

    # Run inside a fresh child interpreter because earlier tests in a full pytest
    # session (e.g. pymongo, gevent, OpenBLAS, or daemon join helpers) leave
    # background threads running in the pytest runner process.
    script = (
        "import multiprocessing, operator, warnings, pebble\n"
        "from lib.cuckoo.common import pebble_utils, process_timeout\n"
        "assert process_timeout._is_single_threaded() is True\n"
        "assert process_timeout._select_mp_context().get_start_method() == 'fork'\n"
        "pool = pebble.ProcessPool(max_workers=1, context=multiprocessing.get_context('fork'))\n"
        "try:\n"
        "    assert pool.schedule(operator.add, args=(1, 2)).result(timeout=15) == 3\n"
        "    assert process_timeout._is_single_threaded() is False\n"
        "    assert process_timeout._select_mp_context().get_start_method() == 'spawn'\n"
        "    with warnings.catch_warnings():\n"
        "        warnings.simplefilter('error', DeprecationWarning)\n"
        "        assert process_timeout.run_with_timeout(operator.add, 10, 4, 5) == 9\n"
        "finally:\n"
        "    pebble_utils.teardown_pool(pool, join_timeout=5, stop_join_timeout=2)\n"
    )
    res = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, f"stdout={res.stdout}\nstderr={res.stderr}"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux-only")
def test_parent_sigkill_kills_child_and_preserves_pgid(tmp_path):
    info_file = tmp_path / "child_info.txt"
    script = (
        "import os, time\n"
        "from lib.cuckoo.common.process_timeout import run_with_timeout\n"
        f"info_path = {str(info_file)!r}\n"
        "def child_fn():\n"
        "    with open(info_path, 'w') as fh:\n"
        "        fh.write(f'{os.getpid()} {os.getpgid(0)}\\n')\n"
        "    time.sleep(30)\n"
        "run_with_timeout(child_fn, 30, start_method='fork')\n"
    )
    parent_proc = subprocess.Popen([sys.executable, "-c", script])
    child_pid = None
    try:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not info_file.exists():
            time.sleep(0.05)
        assert info_file.exists(), "child did not write pid/pgid in time"
        content = info_file.read_text(encoding="utf-8").strip()
        while not content and time.monotonic() < deadline:
            time.sleep(0.05)
            content = info_file.read_text(encoding="utf-8").strip()

        child_pid_str, child_pgid_str = content.split()
        child_pid = int(child_pid_str)
        child_pgid = int(child_pgid_str)

        assert child_pgid == os.getpgid(parent_proc.pid)

        os.kill(parent_proc.pid, signal.SIGKILL)
        parent_proc.wait(timeout=5)

        kill_deadline = time.monotonic() + 5.0
        dead = False
        while time.monotonic() < kill_deadline:
            try:
                p = psutil.Process(child_pid)
                if p.status() == psutil.STATUS_ZOMBIE:
                    dead = True
                    break
            except psutil.NoSuchProcess:
                dead = True
                break
            time.sleep(0.05)
        assert dead, f"child {child_pid} survived parent SIGKILL"
    finally:
        if parent_proc.poll() is None:
            parent_proc.kill()
            parent_proc.wait(timeout=5)
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
