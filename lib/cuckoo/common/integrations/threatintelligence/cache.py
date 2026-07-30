# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2024 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Best-effort, on-disk TTL cache for threat-intel lookups.

Suppresses duplicate API calls for the same key ACROSS analyses (within an
analysis the processing module already dedupes), keeping usage inside
provider fair-use limits. Any cache error degrades to a live lookup, never
to a processing failure. One small JSON file per (kind, provider, key).
"""

import hashlib
import json
import logging
import os
import time

log = logging.getLogger(__name__)


def _default_cache_dir():
    try:
        from lib.cuckoo.common.constants import CUCKOO_ROOT
        return os.path.join(CUCKOO_ROOT, "storage", "threatintel_cache")
    except Exception:
        import tempfile
        return os.path.join(tempfile.gettempdir(), "cape_threatintel_cache")


class IntelCache:
    def __init__(self, enabled=True, ttl=86400, cache_dir=None):
        self.enabled = bool(enabled)
        self.ttl = int(ttl or 0)
        self.cache_dir = cache_dir or _default_cache_dir()
        if self.enabled:
            try:
                os.makedirs(self.cache_dir, exist_ok=True)
            except OSError as err:
                log.debug("Threat-intel cache disabled (mkdir failed): %s", err)
                self.enabled = False

    def _path(self, kind, provider, key):
        digest = hashlib.sha256(f"{kind}|{provider}|{key}".encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{digest}.json")

    def get(self, kind, provider, key):
        if not self.enabled:
            return None
        try:
            with open(self._path(kind, provider, key), "r", encoding="utf-8") as fh:
                entry = json.load(fh)
        except (OSError, ValueError):
            return None
        if self.ttl and (time.time() - entry.get("ts", 0)) > self.ttl:
            return None
        return entry.get("value")

    def set(self, kind, provider, key, value):
        if not self.enabled:
            return
        path = self._path(kind, provider, key)
        try:
            tmp = f"{path}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"ts": time.time(), "value": value}, fh)
            os.replace(tmp, path)
        except OSError as err:
            log.debug("Threat-intel cache write failed: %s", err)
