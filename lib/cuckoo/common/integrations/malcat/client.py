# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Client for the Malcat bridge (the sidecar service that wraps Malcat's python
module and exposes selected features over an authenticated HTTP(S) API).

Malcat's python module must run in Malcat's own venv (its own pinned Python and
requirements), so CAPE never imports it directly. Instead the bridge runs
alongside Malcat and CAPE talks to it over the network - exactly like MCRIT.
This keeps CAPE's venv clean and lets Malcat live locally, on another host, or
in a container, decoupled from CAPE.

One request analyses one artifact and returns whichever features were asked
for, so a single call can pull kesakode + anomalies + capa together. Different
CAPE subsystems (code-similarity/kesakode, the Malcat anomalies module, the
optional Malcat CAPA route) decide independently whether they want a given
artifact; the caller unions their wishes into one feature list per artifact so
the file is analysed once.

requests.Session is not thread-safe, so - like mcrit_engine - each thread gets
its own Session via threading.local(). Malcat's analyse() is not known to be
safe for concurrent calls either, but that is enforced on the bridge side (it
serialises analyses); from CAPE's perspective this client is just HTTP.
"""

import logging
import threading

log = logging.getLogger(__name__)

# Features the bridge understands. Kept in sync with the bridge's ALL_FEATURES.
KNOWN_FEATURES = frozenset({"kesakode", "capa", "anomalies", "yara", "constants", "info"})


class MalcatBridgeError(Exception):
    """Raised for transport/HTTP errors talking to the bridge."""


class MalcatClient:
    """Thin, thread-safe HTTP client for the Malcat bridge.

    Construct once from the [malcat] / [similarity] config values and share
    across threads; each thread lazily gets its own requests.Session.
    """

    def __init__(self, host, api_key=None, ssl_verify=True, timeout=120):
        self.host = (host or "http://127.0.0.1:8090").rstrip("/")
        self.api_key = api_key or ""
        self.ssl_verify = ssl_verify
        self.timeout = int(timeout or 120)
        self._thread_local = threading.local()

    # -- session ----------------------------------------------------------
    @property
    def _session(self):
        """Per-thread requests.Session (thread-safe, keep-alive preserved)."""
        session = getattr(self._thread_local, "session", None)
        if session is None:
            import requests

            session = requests.Session()
            if self.api_key:
                session.headers.update({"X-API-Key": self.api_key})
            self._thread_local.session = session
        return session

    # -- endpoints --------------------------------------------------------
    def health(self):
        """GET /health (no auth). Returns the parsed dict or raises."""
        try:
            resp = self._session.get(
                f"{self.host}/health", timeout=min(self.timeout, 15), verify=self.ssl_verify
            )
        except Exception as err:
            raise MalcatBridgeError(f"bridge unreachable at {self.host}: {err}")
        if resp.status_code != 200:
            raise MalcatBridgeError(f"bridge /health returned HTTP {resp.status_code}")
        try:
            return resp.json()
        except ValueError as err:
            raise MalcatBridgeError(f"bridge /health gave non-JSON: {err}")

    def available(self):
        """True if the bridge answers /health and reports Malcat activated."""
        try:
            import requests  # noqa: F401  (ensure dependency present)
        except ImportError:
            log.warning("Malcat client: 'requests' unavailable (unexpected in CAPE venv).")
            return False
        try:
            info = self.health()
        except MalcatBridgeError as err:
            log.warning("Malcat bridge not available: %s", err)
            return False
        if not info.get("activated"):
            log.warning("Malcat bridge reachable but Malcat is not activated (%s).", self.host)
            # Still return True: online kesakode needs a license, not local activation,
            # and the bridge will report a per-feature error if it truly can't serve.
        return True

    def analyze(self, data, features, kesakode_mode="online", filetype_force=None, quota_reserve=0):
        """POST /v1/analyze with raw file bytes and a feature list.

        data            raw artifact bytes
        features        iterable of feature names (subset of KNOWN_FEATURES)
        kesakode_mode   online | offline | auto
        filetype_force  optional 'PE'/'ELF' hint for mangled dumps
        quota_reserve   stop online kesakode lookups when the bridge's live
                        quota is at/below this many tokens (0 = no floor)

        Returns the parsed JSON dict from the bridge. Raises MalcatBridgeError
        on transport/HTTP failure. Per-feature problems are reported inside the
        JSON (result['errors'] / features[x]['error']) rather than raised.
        """
        feats = [f for f in features if f in KNOWN_FEATURES]
        if not feats:
            raise MalcatBridgeError("no known features requested")
        params = {"features": ",".join(sorted(set(feats))), "kesakode_mode": kesakode_mode}
        if filetype_force:
            params["filetype_force"] = filetype_force
        if quota_reserve:
            params["quota_reserve"] = int(quota_reserve)
        try:
            resp = self._session.post(
                f"{self.host}/v1/analyze",
                params=params,
                data=data,
                headers={"Content-Type": "application/octet-stream"},
                timeout=self.timeout,
                verify=self.ssl_verify,
            )
        except Exception as err:
            raise MalcatBridgeError(f"bridge analyze failed: {err}")
        if resp.status_code == 401:
            raise MalcatBridgeError("bridge rejected API key (401)")
        if resp.status_code >= 400:
            detail = ""
            try:
                detail = resp.json()
            except ValueError:
                detail = resp.text[:200]
            raise MalcatBridgeError(f"bridge returned HTTP {resp.status_code}: {detail}")
        try:
            return resp.json()
        except ValueError as err:
            raise MalcatBridgeError(f"bridge gave non-JSON response: {err}")
