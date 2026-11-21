# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Bounded-execution helpers for heavy static analyzers (CAPA, FLOSS, etc.).

Runs target callables in a short-lived isolated child process so callers can
enforce hard wall-clock timeouts without interrupting in-process C/Python state,
and tracks per-task cumulative budgets and SHA256-keyed result memoization.
"""

from contextlib import suppress
import copy
import ctypes
import logging
import multiprocessing
import multiprocessing.connection
import os
import pickle
import signal
import sys
import threading
import time
from typing import Any

log = logging.getLogger(__name__)

_PR_SET_PDEATHSIG = 1
_LIBC = None

_TASK_BUDGET_SPENT: dict[str, float] = {}
_TASK_BUDGET_WARNED: set[str] = set()
_TASK_RESULT_CACHE: dict[tuple[str, str], Any] = {}

_ACTIVE_TIMEOUT_PROCS: set[Any] = set()
_ACTIVE_TIMEOUT_LOCK = threading.Lock()
_FINALIZER_PID: int | None = None


class ResultUnavailableError(Exception):
    """Raised when an isolated child exits or crashes before returning a result."""


def _reset_after_fork() -> None:
    """Reset inherited active-process tracking and locks in forked children."""
    global _ACTIVE_TIMEOUT_LOCK, _FINALIZER_PID
    _ACTIVE_TIMEOUT_LOCK = threading.Lock()
    _ACTIVE_TIMEOUT_PROCS.clear()
    _FINALIZER_PID = None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)


def reset_task_budgets() -> None:
    """Clear per-task cumulative budget counters, warning flags, and result cache."""
    _TASK_BUDGET_SPENT.clear()
    _TASK_BUDGET_WARNED.clear()
    _TASK_RESULT_CACHE.clear()


def mark_budget_warned(budget_name: str) -> bool:
    """Return True on the first budget-exhaustion warning for ``budget_name`` per task."""
    if budget_name in _TASK_BUDGET_WARNED:
        return False
    _TASK_BUDGET_WARNED.add(budget_name)
    return True


def resolve_call_timeout(
    budget_name: str,
    per_call_timeout: float | int | None,
    task_timeout: float | int | None,
) -> float:
    """Compute effective timeout for the next call under an optional per-task budget.

    Returns ``0.0`` when unbounded (timeouts disabled) and ``-1.0`` when a
    configured ``task_timeout`` budget has already been exhausted.
    """
    per_call = max(0.0, float(per_call_timeout or 0))
    task_cap = max(0.0, float(task_timeout or 0))

    remaining = 0.0
    if task_cap > 0:
        remaining = task_cap - _TASK_BUDGET_SPENT.get(budget_name, 0.0)
        if remaining <= 0:
            return -1.0

    if per_call > 0 and task_cap > 0:
        return min(per_call, remaining)
    if per_call > 0:
        return per_call
    if task_cap > 0:
        return remaining
    return 0.0


def record_task_budget_elapsed(budget_name: str, elapsed: float) -> None:
    """Add ``elapsed`` seconds to the cumulative wall-clock budget for ``budget_name``."""
    _TASK_BUDGET_SPENT[budget_name] = _TASK_BUDGET_SPENT.get(budget_name, 0.0) + max(0.0, float(elapsed))


def get_cached_task_result(namespace: str, key: str) -> tuple[bool, Any]:
    """Return ``(True, deepcopy(value))`` on per-task cache hit, else ``(False, None)``."""
    cache_key = (namespace, key)
    if cache_key in _TASK_RESULT_CACHE:
        return True, copy.deepcopy(_TASK_RESULT_CACHE[cache_key])
    return False, None


def set_cached_task_result(namespace: str, key: str, value: Any) -> None:
    """Store a deep copy of ``value`` in the per-task result cache."""
    _TASK_RESULT_CACHE[(namespace, key)] = copy.deepcopy(value)


def _is_single_threaded() -> bool:
    """Return True only when the current process has a single Python and OS thread."""
    if threading.active_count() != 1:
        return False
    if sys.platform.startswith("linux"):
        try:
            return len(os.listdir("/proc/self/task")) == 1
        except OSError:
            pass
    return True


def _select_mp_context(start_method: str | None = None):
    """Select ``fork`` when single-threaded on POSIX, otherwise ``spawn``."""
    if start_method:
        return multiprocessing.get_context(start_method)
    if os.name == "nt" or not hasattr(os, "fork"):
        return multiprocessing.get_context("spawn")
    if _is_single_threaded():
        return multiprocessing.get_context("fork")
    return multiprocessing.get_context("spawn")


def _get_libc():
    global _LIBC
    if _LIBC is None and sys.platform.startswith("linux"):
        try:
            libc = ctypes.CDLL(None)
            libc.prctl.argtypes = [
                ctypes.c_int,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
            ]
            libc.prctl.restype = ctypes.c_int
            _LIBC = libc
        except Exception:
            _LIBC = False
    return _LIBC or None


def _arm_parent_death_signal(expected_ppid: int) -> None:
    """Ensure the child dies with SIGKILL if its parent disappears unexpectedly.

    Does NOT call ``os.setsid()`` so supervisor process-group kills (``PreforkEngine``)
    still sweep the child together with its parent.
    """
    if sys.platform.startswith("linux"):
        libc = _get_libc()
        if libc is not None:
            with suppress(Exception):
                libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
    if os.getppid() != expected_ppid:
        os._exit(1)


def _stop_active_timeout_procs() -> None:
    """Kill active timeout children before multiprocessing joins non-daemon procs on SIGTERM."""
    global _FINALIZER_PID
    _FINALIZER_PID = None
    with _ACTIVE_TIMEOUT_LOCK:
        procs = list(_ACTIVE_TIMEOUT_PROCS)
        _ACTIVE_TIMEOUT_PROCS.clear()
    for proc in procs:
        try:
            if proc.exitcode is None:
                proc.kill()
        except Exception:
            pass


def _register_timeout_proc(proc) -> None:
    """Track ``proc`` and install a high-priority exit finalizer for Pebble SIGTERM teardown."""
    global _FINALIZER_PID
    with _ACTIVE_TIMEOUT_LOCK:
        _ACTIVE_TIMEOUT_PROCS.add(proc)
        current_pid = os.getpid()
        if _FINALIZER_PID != current_pid:
            try:
                from multiprocessing.util import Finalize

                Finalize(None, _stop_active_timeout_procs, exitpriority=100)
                _FINALIZER_PID = current_pid
            except Exception:
                pass


def _unregister_timeout_proc(proc) -> None:
    with _ACTIVE_TIMEOUT_LOCK:
        _ACTIVE_TIMEOUT_PROCS.discard(proc)


def _child_entry(expected_ppid: int, writer, fn, args, kwargs) -> None:
    """Top-level entry point executed inside the isolated child process."""
    _arm_parent_death_signal(expected_ppid)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    try:
        result = fn(*args, **kwargs)
        writer.send(("ok", result))
    except BaseException as exc:
        try:
            writer.send(("raise", exc))
        except Exception:
            with suppress(Exception):
                writer.send(("raise", RuntimeError(f"{type(exc).__name__}: {exc}")))
    finally:
        with suppress(OSError):
            writer.close()
        os._exit(0)


def _terminate_and_reap(proc, join_timeout: float = 2.0) -> None:
    """Kill an unfinished child and reap it within ``join_timeout`` without blocking on D-state."""
    if proc is None:
        return
    try:
        if proc.exitcode is None:
            with suppress(OSError):
                proc.kill()
        proc.join(timeout=join_timeout)
        if proc.is_alive():
            threading.Thread(target=proc.join, name="timeout-proc-reap", daemon=True).start()
    except Exception:
        pass


def run_with_timeout(fn, timeout, *args, start_method: str | None = None, **kwargs):
    """Execute ``fn(*args, **kwargs)`` in an isolated child bounded by ``timeout`` seconds.

    When ``timeout`` is ``None`` or ``<= 0``, executes ``fn`` synchronously in-process.
    Raises ``TimeoutError`` if ``timeout`` elapses or ``ResultUnavailableError`` if the
    child terminates before sending a response frame.
    """
    timeout_val = float(timeout or 0)
    if timeout_val <= 0:
        return fn(*args, **kwargs)

    ctx = _select_mp_context(start_method)
    reader, writer = ctx.Pipe(duplex=False)
    proc = ctx.Process(
        target=_child_entry,
        args=(os.getpid(), writer, fn, args, kwargs),
        daemon=True,
    )
    started = False
    try:
        _register_timeout_proc(proc)
        try:
            proc.start()
            started = True
        except OSError as err:
            _unregister_timeout_proc(proc)
            with suppress(OSError):
                reader.close()
            with suppress(OSError):
                writer.close()
            log.warning("Failed to start isolated timeout process (%s); falling back to in-process execution", err)
            return fn(*args, **kwargs)

        with suppress(OSError):
            writer.close()

        deadline = time.monotonic() + timeout_val
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"process timed out after {timeout}s")
            if multiprocessing.connection.wait([reader], remaining):
                break

        try:
            status, value = reader.recv()
        except (EOFError, OSError, pickle.UnpicklingError) as err:
            raise ResultUnavailableError("child process terminated before delivering a result") from err

        if status == "raise":
            raise value
        return value
    finally:
        _unregister_timeout_proc(proc)
        with suppress(OSError):
            reader.close()
        with suppress(OSError):
            writer.close()
        if started:
            _terminate_and_reap(proc)
