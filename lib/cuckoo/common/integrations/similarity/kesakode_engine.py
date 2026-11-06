# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Kesakode code-similarity engine (via the Malcat bridge).

Malcat's Kesakode identifies a sample's malware family by hashing its
functions, strings and constants and matching them against Kesakode's database.
It returns a per-family verdict (family -> score 0..100), NOT a link to a
specific matched corpus sample. So unlike MCRIT (which gives sample-to-sample
matches with a sample sha256), Kesakode gives family LABELS: each MatchRecord
carries a family and score, and sample_sha256 stays None. Keep that distinction
in mind for clustering - Kesakode labels, MCRIT links.

This engine imports nothing from Malcat. It talks to the Malcat bridge over
HTTP (see lib/cuckoo/common/integrations/malcat/client.py), exactly like
mcrit_engine talks to an MCRIT server. Config lives in the [similarity] section
of integrations.conf (alongside mcrit), per the "keep code similarity together"
convention.

Online vs offline: `kesakode_mode` selects online (consumes Kesakode quota,
returns goodware too), offline (local DB, no quota - requires the OEM headless
build), or auto (offline first, escalate to online on a miss). We start with
online; offline flips on once the OEM build is in place. The engine tags each
match's engine name as "kesakode-online" / "kesakode-offline" so provenance is
visible in the report and clustering.
"""

import logging

from lib.cuckoo.common.integrations.similarity.base import (
    FMT_ELF,
    FMT_PE,
    EngineResult,
    MatchRecord,
    SimilarityEngine,
    _as_bool,
)

log = logging.getLogger(__name__)


class KesakodeEngine(SimilarityEngine):
    name = "kesakode"
    # Kesakode works on unpacked native code (PE/ELF). CAPE targets Windows and
    # Linux, so PE and ELF; Mach-O omitted like mcrit. Unpacked-shellcode blobs
    # that aren't a recognised executable become FMT_UNKNOWN and are skipped by
    # the base class's accepts_format() gate - matching MCRIT's behaviour.
    supported_formats = {FMT_PE, FMT_ELF}

    def __init__(self, options):
        super().__init__(options)

        # Optional per-engine format narrowing (kesakode_formats = pe,elf).
        raw_formats = (self.options.get("kesakode_formats") or "").strip()
        if raw_formats:
            parsed = {tok.strip().lower() for tok in raw_formats.split(",") if tok.strip()}
            parsed &= {FMT_PE, FMT_ELF}
            if parsed:
                self.supported_formats = parsed

        # online | offline | auto
        self.mode = (self.options.get("kesakode_mode") or "online").strip().lower()
        if self.mode not in ("online", "offline", "auto"):
            self.mode = "online"

        # The framework tags every match with engine.name (shown as the code-
        # similarity engine label). Per product decision this is always
        # "malcat kesakode" regardless of online/offline mode - a single,
        # user-facing label. (Online/offline provenance can be surfaced via a
        # separate field later if clustering needs it.)
        self.name = "malcat kesakode"

        # Bridge connection (kept in [similarity] with the other kesakode keys).
        self.host = (self.options.get("kesakode_host") or "http://127.0.0.1:8090").rstrip("/")
        self.api_key = self.options.get("kesakode_apikey") or ""
        self.ssl_verify = _as_bool(self.options.get("kesakode_ssl_verify", True))

        # On-demand (online only): when set, the online lookup is deferred to a
        # per-file button in the report (see web on_demand view), so processing
        # does not auto-spend tokens. Offline always looks up.
        self.on_demand = _as_bool(self.options.get("kesakode_on_demand", False))
        # Quota floor passed to the bridge, which enforces it against live quota.
        try:
            self.quota_reserve = int(self.options.get("kesakode_quota_reserve", 10) or 0)
        except (TypeError, ValueError):
            self.quota_reserve = 10

        self._client = None
        self._available = False

    # -- lifecycle --------------------------------------------------------
    def available(self) -> bool:
        try:
            from lib.cuckoo.common.integrations.malcat.client import MalcatClient
        except Exception as err:
            log.warning("Kesakode engine: cannot import Malcat client: %s", err)
            return False
        self._client = MalcatClient(
            host=self.host,
            api_key=self.api_key,
            ssl_verify=self.ssl_verify,
            timeout=self.timeout,
        )
        if not self._client.available():
            log.warning("Kesakode engine enabled but Malcat bridge unavailable at %s.", self.host)
            return False
        self._available = True
        return True

    def analyze(self, file_path, sha256, filename, source,
                is_dump=False, base_addr=None, bitness=None) -> EngineResult:
        if not self._available or self._client is None:
            return EngineResult(status="disabled")
        try:
            with open(file_path, "rb") as fh:
                binary = fh.read()
        except OSError as err:
            return EngineResult(status="error", error=f"unreadable: {err}")
        if not binary:
            return EngineResult(status="skipped", error="empty file")

        from lib.cuckoo.common.integrations.malcat.client import MalcatBridgeError

        # On-demand online: don't spend a token during processing. Offline still
        # runs (no quota cost). For online/auto with on_demand, defer to the
        # report button, which re-submits this artifact for the online lookup.
        effective_mode = self.mode
        if self.on_demand and self.mode == "online":
            return EngineResult(status="on_demand")
        if self.on_demand and self.mode == "auto":
            effective_mode = "offline"  # offline stage only; online via button

        try:
            payload = self._client.analyze(
                data=binary,
                features=["kesakode"],
                kesakode_mode=effective_mode,
                quota_reserve=self.quota_reserve,
            )
        except MalcatBridgeError as err:
            log.warning("Kesakode bridge error for %s: %s", filename, err)
            return EngineResult(status="error", error=str(err))
        except Exception as err:
            log.exception("Kesakode analysis failed for %s", filename)
            return EngineResult(status="error", error=str(err))

        kesakode = (payload.get("features") or {}).get("kesakode") or {}
        if kesakode.get("error"):
            return EngineResult(status="error", error=str(kesakode["error"]))

        out = EngineResult(status="ok")
        out.matches = self._select_matches(self._parse_verdict(kesakode))
        if not out.matches:
            out.status = "no_match"
        return out

    # -- mapping ----------------------------------------------------------
    def _parse_verdict(self, kesakode) -> list:
        """Turn Kesakode's {family: score} verdict into MatchRecords.

        Kesakode gives family labels, not corpus-sample links, so sample_sha256
        stays None. The engine name records which DB produced the label so the
        report and clustering can tell online from offline.
        """
        verdict = kesakode.get("verdict") or {}

        records = []
        for family, score in verdict.items():
            if not family:
                continue
            try:
                similarity = float(score)
            except (TypeError, ValueError):
                continue
            # Kesakode gives family labels, not corpus-sample links, so
            # sample_sha256 stays None. Provenance (online/offline) is carried by
            # this engine's name, which the processing layer stamps onto every
            # match in by_sha256 / results.
            records.append(
                MatchRecord(
                    family=str(family),
                    similarity=similarity,
                    sample_sha256=None,
                )
            )
        return records
