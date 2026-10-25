# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Malcat processing module: static intel from the Malcat bridge (anomalies for
now; extendable to other Malcat features later).

Runs after the extraction modules, gathers the configured artifact types
(payloads / procdump / dropped / submitted), and for each supported file calls
the Malcat bridge with the requested features. Results are annotated back onto
each artifact's report dict under the ``malcat`` key, so the web UI renders an
expandable "Malcat" panel on the file-info card (exactly like the PE/MSI
expanders) with no change to views.py - because _file_info.html renders the
payload/dropped/procdump/target dict directly as its ``file`` variable.

Config: conf/integrations.conf [malcat]; module on/off in conf/processing.conf
[malcat]. This is the NON-similarity Malcat integration; Kesakode code
similarity lives with the similarity engines and is configured in [similarity].

Concurrency: one bridge call per artifact, sequentially. Malcat analyses are
serialised on the bridge side anyway, and take ~2s, so we keep this simple
(no shared cross-module analysis cache yet - a known refinement for later).
"""

import logging
import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.integrations.similarity.base import (
    FMT_UNKNOWN,
    detect_format,
    _as_bool,
)

log = logging.getLogger(__name__)


class MalcatStatic(Processing):
    """Attach Malcat static intel (anomalies) to analysed artifacts."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = "malcat"

    def run(self):
        try:
            options = dict(Config("integrations").get("malcat"))
        except Exception as err:
            log.warning("Malcat: no [malcat] config section (%s); skipping.", err)
            return {}

        # Which Malcat features this module pulls. Anomalies for now; the list
        # is here so adding features later is a one-line change.
        features = []
        if _as_bool(options.get("anomalies", True)):
            features.append("anomalies")
        if not features:
            return {}

        sources = {
            "payload": _as_bool(options.get("malcat_payloads", True)),
            "procdump": _as_bool(options.get("malcat_procdump", True)),
            "dropped": _as_bool(options.get("malcat_dropped", False)),
            "submitted": _as_bool(options.get("malcat_submittedfile", False)),
        }

        candidates = []
        if sources["payload"]:
            candidates.extend(self._gather("payload"))
        if sources["procdump"]:
            candidates.extend(self._gather("procdump"))
        if sources["dropped"]:
            candidates.extend(self._gather("dropped"))
        if sources["submitted"]:
            candidates.extend(self._gather_submitted())

        # Only supported executable formats (skip shellcode blobs etc.).
        candidates = [c for c in candidates if c["format"] != FMT_UNKNOWN]
        if not candidates:
            return {}

        # De-dup by sha256 (same artifact may appear in >1 list).
        seen = set()
        unique = []
        for c in candidates:
            if c["sha256"] in seen:
                continue
            seen.add(c["sha256"])
            unique.append(c)

        client = self._make_client(options)
        if client is None or not client.available():
            log.warning("Malcat bridge unavailable; skipping anomalies.")
            return {}

        from lib.cuckoo.common.integrations.malcat.client import MalcatBridgeError
        from lib.cuckoo.common.integrations.malcat.convert import normalize_anomalies

        kesakode_mode = (options.get("kesakode_mode") or "online").strip().lower()
        analysed = 0
        for cand in unique:
            try:
                with open(cand["path"], "rb") as fh:
                    data = fh.read()
            except OSError as err:
                log.debug("Malcat: cannot read %s: %s", cand["path"], err)
                continue
            if not data:
                continue
            try:
                payload = client.analyze(data=data, features=features, kesakode_mode=kesakode_mode)
            except MalcatBridgeError as err:
                log.warning("Malcat bridge error for %s: %s", cand["filename"], err)
                continue
            except Exception as err:
                log.exception("Malcat analysis failed for %s: %s", cand["filename"], err)
                continue

            feats = payload.get("features") or {}
            block = {}
            if "anomalies" in features:
                anomalies = normalize_anomalies(feats.get("anomalies") or [])
                if anomalies:
                    block["anomalies"] = anomalies
            if block and isinstance(cand.get("artifact"), dict):
                # Annotate the artifact dict in place -> file.malcat in the UI.
                cand["artifact"]["malcat"] = block
                analysed += 1

        log.info("Malcat: annotated %d artifact(s) with static intel.", analysed)
        # Nothing to store at top level; annotations live on the artifacts.
        return {}

    # -- client -----------------------------------------------------------
    def _make_client(self, options):
        try:
            from lib.cuckoo.common.integrations.malcat.client import MalcatClient
        except Exception as err:
            log.warning("Malcat: cannot import client: %s", err)
            return None
        # When the [malcat] connection keys are blank, fall back to the
        # [similarity] kesakode_* bridge settings. kesakode_host/apikey/ssl live
        # in the [similarity] section, so we must read THAT section for the
        # fallback - reading only [malcat] would miss them and default to
        # http://127.0.0.1:8090 (wrong scheme against an https bridge).
        try:
            scfg = dict(Config("integrations").get("similarity"))
        except Exception:
            scfg = {}
        host = options.get("malcat_host") or scfg.get("kesakode_host") or "http://127.0.0.1:8090"
        api_key = options.get("malcat_apikey") or scfg.get("kesakode_apikey") or ""
        # Use malcat_ssl_verify only if explicitly set; otherwise inherit
        # kesakode_ssl_verify.
        raw_ssl = options.get("malcat_ssl_verify", "")
        if str(raw_ssl).strip() == "":
            ssl_verify = _as_bool(scfg.get("kesakode_ssl_verify", True))
        else:
            ssl_verify = _as_bool(raw_ssl)
        return MalcatClient(
            host=host,
            api_key=api_key,
            ssl_verify=ssl_verify,
            timeout=int(options.get("timeout", 120) or 120),
        )

    # -- artifact gathering (mirrors the similarity module) ---------------
    def _gather(self, source):
        rows = []
        if source == "payload":
            cape = self.results.get("CAPE", {})
            items = cape.get("payloads", []) if isinstance(cape, dict) else (cape if isinstance(cape, list) else [])
        else:
            items = self.results.get(source) or []
        for it in items:
            if isinstance(it, dict) and it.get("path") and it.get("sha256"):
                rows.append(self._mk(it, source))
        return rows

    def _gather_submitted(self):
        target = self.results.get("target", {})
        f = target.get("file") if isinstance(target, dict) else None
        if isinstance(f, dict) and f.get("path") and f.get("sha256"):
            return [self._mk(f, "submitted")]
        return []

    def _mk(self, info, source):
        return {
            "path": info["path"],
            "sha256": info["sha256"],
            "filename": info.get("name") or os.path.basename(info["path"]),
            "source": source,
            "format": detect_format(info.get("type")),
            "artifact": info,
        }
