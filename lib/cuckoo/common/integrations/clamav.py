# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress

from cachetools import TTLCache

from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)

HAVE_CLAMAV = False
CLAMAV_ENABLED = Config("processing").detections.clamav

if CLAMAV_ENABLED:
    with suppress(ImportError):
        import pyclamd

        HAVE_CLAMAV = True


# Module-level cache for per-task `prefetch_clamav` results. Keyed by
# absolute file path. Each value is the same list of match-strings that
# `get_clamav` would otherwise compute. Populated by `prefetch_clamav`
# and consumed transparently by `get_clamav`. Cleared at task boundary
# via `clear_clamav_cache` to avoid leaking results across analyses on
# long-lived worker process.
# We use a TTLCache as a safety measure against unbounded growth in
# long-lived workers, though `clear_clamav_cache` remains the primary
# mechanism for lifecycle management.
_CACHE_LOCK = threading.Lock()
_CLAMAV_CACHE = TTLCache(maxsize=1024, ttl=3600)



def _scan_one(file_path):
    """Return the list of ClamAV match-strings for `file_path`, or [] on
    error / empty file / clamav not present. Issues a single
    ALLMATCHSCAN over its own clamd socket so it's safe to call from
    multiple threads concurrently — clamd is multi-threaded server-side
    and serves each socket independently."""
    matches = []
    if not HAVE_CLAMAV:
        return matches
    try:
        if os.path.getsize(file_path) <= 0:
            return matches
    except OSError:
        return matches
    try:
        cd = pyclamd.ClamdUnixSocket()
        results = cd.allmatchscan(file_path)
        if results and file_path in results:
            for entry in results[file_path]:
                if entry[0] == "FOUND" and entry[1] not in matches:
                    matches.append(entry[1])
    except ConnectionError:
        log.warning("failed to connect to clamd socket")
    except Exception as e:
        log.warning("failed to scan file with clamav %s: %s", file_path, e)
    return matches


def prefetch_clamav(file_paths, max_workers=8):
    """Pre-scan a batch of files in parallel and populate the per-task
    cache. Subsequent `get_clamav(path)` calls for any of these paths
    return instantly from cache instead of opening a socket.

    The bottleneck on heavy CAPE tasks is the sequential single-thread
    `allmatchscan` over 10-20 dropped/extracted files (each ~3-9s of
    socket-recv latency). clamd is multi-threaded server-side, so
    fanning out N parallel ALLMATCHSCAN sockets cuts wall-clock to
    roughly `slowest_file_scan_seconds` instead of `sum_of_all_scans`.

    Workers default to 8 — beyond that you start saturating clamd's
    thread pool (default `MaxThreads = 12` in clamd.conf) and gain
    little. No-ops if ClamAV is not configured.
    """
    if not HAVE_CLAMAV or not file_paths:
        return
    # Filter to paths we don't already have cached and that exist.
    pending = []
    with _CACHE_LOCK:
        for p in file_paths:
            if p in _CLAMAV_CACHE:
                continue
            try:
                if not os.path.isfile(p) or os.path.getsize(p) <= 0:
                    _CLAMAV_CACHE[p] = []
                    continue
            except OSError:
                continue
            pending.append(p)
    if not pending:
        return
    workers = max(1, min(max_workers, len(pending)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_map = {ex.submit(_scan_one, p): p for p in pending}
        for fut in as_completed(future_map):
            p = future_map[fut]
            try:
                result = fut.result()
            except Exception as e:
                log.warning("clamav prefetch failed for %s: %s", p, e)
                result = []
            with _CACHE_LOCK:
                _CLAMAV_CACHE[p] = result


def clear_clamav_cache():
    """Drop the per-task prefetch cache. Call at task boundaries to
    avoid leaking match results across analyses on a long-lived
    worker process."""
    with _CACHE_LOCK:
        _CLAMAV_CACHE.clear()


def get_clamav(file_path):
    """Get ClamAV signatures matches.
    Enable in: processing -> [CAPE] -> clamav

    Requires pyclamd module. Additionally if running with apparmor, an exception must be made.
    apt-get install clamav clamav-daemon clamav-freshclam clamav-unofficial-sigs -y
    poetry run pip install -U pyclamd
    systemctl enable clamav-daemon
    systemctl start clamav-daemon
    usermod -a -G cape clamav
    echo "/opt/CAPEv2/storage/** r," | sudo tee -a /etc/apparmor.d/local/usr.sbin.clamd

    Returns the cached matches when `prefetch_clamav` has been called
    for this path in the current task; otherwise issues a single
    sequential scan (preserving the legacy behaviour for any caller
    that bypasses the prefetch path).

    @return: matched ClamAV signatures.
    """
    if not HAVE_CLAMAV:
        return []
    with _CACHE_LOCK:
        cached = _CLAMAV_CACHE.get(file_path)
        if cached is not None:
            return list(cached)
    matches = _scan_one(file_path)
    # Memoise even single-shot scans so repeated lookups for the same
    # path within a task don't pay the network cost twice.
    with _CACHE_LOCK:
        _CLAMAV_CACHE[file_path] = matches
    return matches
