"""Periodic Windows guest telemetry, independent of API hooks."""

import ctypes
import json
import logging
import math
import os
import tempfile
import time
from ctypes import wintypes
from datetime import datetime, timezone
from threading import Event, Lock, Thread

from lib.common.abstracts import Auxiliary
from lib.common.defines import MEMORYSTATUSEX
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)
UPLOAD_PATH = "aux/periodic_metrics.jsonl"


class ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


def filetime_ticks(value):
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


class WindowsMetrics:
    """Use typed Win32 calls so process handles work on both x86 and x64."""

    def __init__(self):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        ft = ctypes.POINTER(wintypes.FILETIME)
        self.kernel.GetSystemTimes.argtypes = [ft, ft, ft]
        self.kernel.GetSystemTimes.restype = wintypes.BOOL
        self.kernel.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
        self.kernel.GlobalMemoryStatusEx.restype = wintypes.BOOL
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, ft, ft, ft, ft]
        self.kernel.GetProcessTimes.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD]
        self.psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

    @staticmethod
    def checked(result):
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())

    def system_times(self):
        idle, kernel, user = (wintypes.FILETIME() for _ in range(3))
        self.checked(self.kernel.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)))
        return tuple(filetime_ticks(t) for t in (idle, kernel, user))

    def memory(self):
        value = MEMORYSTATUSEX()
        value.dwLength = ctypes.sizeof(value)
        self.checked(self.kernel.GlobalMemoryStatusEx(ctypes.byref(value)))
        return {
            "memory_load_percent": value.dwMemoryLoad,
            "total_physical_bytes": value.ullTotalPhys,
            "available_physical_bytes": value.ullAvailPhys,
        }

    def process(self, pid):
        # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (needed by GetProcessMemoryInfo).
        handle = self.kernel.OpenProcess(0x0400 | 0x0010, False, pid)
        self.checked(handle)
        try:
            created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
            self.checked(self.kernel.GetProcessTimes(handle, *(ctypes.byref(t) for t in (created, exited, kernel, user))))
            result = {
                "creation_time_100ns": filetime_ticks(created),
                "cpu_time_100ns": filetime_ticks(kernel) + filetime_ticks(user),
            }
            memory = ProcessMemoryCounters()
            memory.cb = ctypes.sizeof(memory)
            if self.psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb):
                result.update(
                    working_set_bytes=memory.WorkingSetSize,
                    peak_working_set_bytes=memory.PeakWorkingSetSize,
                    private_usage_bytes=memory.PrivateUsage,
                    pagefile_usage_bytes=memory.PagefileUsage,
                    peak_pagefile_usage_bytes=memory.PeakPagefileUsage,
                )
            else:
                result["memory_error"] = ctypes.get_last_error()
            return result
        finally:
            self.kernel.CloseHandle(handle)


class PeriodicMetrics(Auxiliary, Thread):
    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.enabled = getattr(config, "periodic_metrics", False)
        raw_interval = self.options.get("periodic_metrics_interval", getattr(config, "periodic_metrics_interval", 1))
        try:
            self.interval = float(raw_interval)
            if not math.isfinite(self.interval) or not 0.1 <= self.interval <= 60:
                raise ValueError("interval must be between 0.1 and 60 seconds")
        except (TypeError, ValueError):
            log.warning("Invalid periodic_metrics_interval %r; using 1 second", raw_interval)
            self.interval = 1.0
        self._stopped = Event()
        self._pid_lock = Lock()
        self._pids = set()
        self._previous_system = None
        self._previous_processes = {}
        self._path = None
        self._finished = False

    def add_pid(self, pid):
        with self._pid_lock:
            self._pids.add(int(pid))

    def del_pid(self, pid):
        with self._pid_lock:
            self._pids.discard(int(pid))

    def stop(self):
        self._stopped.set()

    def sample(self, provider, started_ns):
        now_ns = time.perf_counter_ns()
        row = {
            "schema_version": 1,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "monotonic_ns": now_ns,
            "elapsed_seconds": (now_ns - started_ns) / 1e9,
            "interval_seconds": self.interval,
            "system": {"cpu_percent": None},
            "processes": [],
            "errors": [],
        }
        try:
            current = provider.system_times()
            if self._previous_system is not None:
                idle, kernel, user = (a - b for a, b in zip(current, self._previous_system))
                total = kernel + user  # Windows kernel time includes idle time.
                if min(idle, kernel, user) >= 0 and total > 0 and idle <= total:
                    row["system"]["cpu_percent"] = 100 * (total - idle) / total
            self._previous_system = current
        except OSError as exc:
            self._previous_system = None
            row["errors"].append({"metric": "system_cpu", "error": str(exc)})
        try:
            row["system"].update(provider.memory())
        except OSError as exc:
            row["errors"].append({"metric": "system_memory", "error": str(exc)})
        with self._pid_lock:
            pids = sorted(self._pids)
        previous = self._previous_processes
        self._previous_processes = {}
        for pid in pids:
            item = {"pid": pid, "cpu_percent": None}
            try:
                metrics = provider.process(pid)
                measured_ns = time.perf_counter_ns()
                item.update(metrics)
                old = previous.get(pid)
                if old and old[0] == metrics["creation_time_100ns"]:
                    delta = metrics["cpu_time_100ns"] - old[1]
                    duration = measured_ns - old[2]
                    if delta >= 0 and duration > 0:
                        item["cpu_percent"] = 100 * delta * 100 / duration
                self._previous_processes[pid] = (metrics["creation_time_100ns"], metrics["cpu_time_100ns"], measured_ns)
            except OSError as exc:
                item["error"] = str(exc)
            row["processes"].append(item)
        return row

    def run(self):
        if not self.enabled or self._stopped.is_set():
            return
        try:
            provider = WindowsMetrics()
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", prefix="cape_metrics_", suffix=".jsonl", delete=False
            ) as output:
                self._path = output.name
                started_ns = time.perf_counter_ns()
                deadline = time.perf_counter()
                while not self._stopped.is_set():
                    output.write(json.dumps(self.sample(provider, started_ns), allow_nan=False) + "\n")
                    output.flush()
                    deadline += self.interval
                    now = time.perf_counter()
                    if deadline <= now:
                        # Skip missed slots rather than producing a burst of samples.
                        deadline += (math.floor((now - deadline) / self.interval) + 1) * self.interval
                    self._stopped.wait(max(0, deadline - time.perf_counter()))
        except Exception:
            log.exception("Periodic guest metrics collection failed")

    def finish(self):
        # Analyzer calls stop(), joins this thread, then calls finish().
        if self._finished or self._path is None:
            return
        if self.is_alive():
            log.warning("Periodic metrics collector is still running; retaining %s", self._path)
            return
        upload_to_host(self._path, UPLOAD_PATH)
        self._finished = True
        os.unlink(self._path)
