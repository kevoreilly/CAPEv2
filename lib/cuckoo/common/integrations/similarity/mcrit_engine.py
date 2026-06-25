# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""MCRIT similarity engine — direct REST API client.

Uses only ``requests`` (already in CAPE). The ``mcrit`` and ``smda`` Python
packages are NOT required and must NOT be installed (smda conflicts with
CAPE's venv). MCRIT is PE-only, so this engine declares supported_formats
accordingly; non-PE artifacts are filtered out by the dispatcher.

REST contract (MCRIT 1.4.x), all responses {"status":"successful","data":...}:
  GET  /version
  POST /query/binary               body=bytes  params=minhash_score=N   -> job_id
  POST /query/binary/mapped/<va>   body=bytes  params=minhash_score=N   -> job_id
  GET  /jobs/<job_id>              -> job dict (.result set when done)
  GET  /results/<result_id>        -> matching result dict
  GET  /samples/sha256/<sha256>    -> sample entry or 404
  POST /samples/binary?...         body=bytes  -> job_id (persist mode)
"""

import logging
import threading
import time
from typing import List

from lib.cuckoo.common.integrations.similarity.base import (
    FMT_ELF, FMT_MACHO, FMT_PE, EngineResult, MatchRecord, SimilarityEngine, _as_bool,
)

log = logging.getLogger(__name__)


class McritEngine(SimilarityEngine):
    name = "mcrit"
    # MCRIT disassembles via SMDA, which now supports PE, ELF and Mach-O
    # (x86/x64/aarch64). Formats are config-driven via mcrit_formats so an
    # operator on an older SMDA can narrow it; default covers all three.
    supported_formats = {FMT_PE, FMT_ELF, FMT_MACHO}

    def __init__(self, options):
        super().__init__(options)
        # Allow operators to restrict/extend the formats sent to MCRIT.
        fmts = (self.options.get("mcrit_formats") or "pe,elf,macho")
        parsed = {f.strip().lower() for f in str(fmts).split(",") if f.strip()}
        if parsed:
            self.supported_formats = parsed
        self.host = (self.options.get("mcrit_host") or "http://127.0.0.1:8000").rstrip("/")
        self.apitoken = self.options.get("mcrit_apitoken") or None
        self.username = self.options.get("mcrit_username") or "cape"
        self.persist_samples = _as_bool(self.options.get("persist_samples", False))
        self.poll_interval = int(self.options.get("mcrit_poll_interval", 3) or 3)
        self.minhash_threshold = int(self.minimum_similarity) if self.minimum_similarity else None
        # When set, score matches by their NON-library weighted similarity so
        # matches that are mostly shared library/runtime code (Go, OpenSSL, CRT,
        # etc.) fall below the threshold and drop out — leaving malware-code
        # matches. Pure-library matches are discarded outright.
        self.ignore_library_matches = _as_bool(self.options.get("ignore_library_matches", True))
        # requests.Session is NOT thread-safe. With concurrent_submissions the
        # ThreadPoolExecutor calls analyze() from multiple threads, so each
        # thread gets its own Session via threading.local() (still keeping
        # HTTP keep-alive per thread). _available records that the server
        # answered a probe successfully during available().
        self._thread_local = threading.local()
        self._available = False

    @property
    def _session(self):
        """Per-thread requests.Session (thread-safe, keep-alive preserved)."""
        session = getattr(self._thread_local, "session", None)
        if session is None:
            import requests
            session = requests.Session()
            session.headers.update(self._auth_headers())
            self._thread_local.session = session
        return session

    def available(self) -> bool:
        try:
            import requests  # noqa: F401  (ensure dependency present)
        except ImportError:
            log.warning("MCRIT engine: 'requests' unavailable (unexpected in CAPE venv).")
            return False
        try:
            resp = self._session.get(f"{self.host}/version", timeout=10)
            if self._unwrap(resp) is None:
                log.warning("MCRIT at %s gave an unexpected /version response.", self.host)
                return False
            self._available = True
            return True
        except Exception as err:
            log.warning("MCRIT server unreachable at %s: %s", self.host, err)
            return False

    def analyze(self, file_path, sha256, filename, source,
                is_dump=False, base_addr=None, bitness=None) -> EngineResult:
        if not self._available:
            return EngineResult(status="disabled")
        try:
            with open(file_path, "rb") as fh:
                binary = fh.read()
        except OSError as err:
            return EngineResult(status="error", error=f"unreadable: {err}")
        if not binary:
            return EngineResult(status="skipped", error="empty file")

        try:
            if self.persist_samples:
                result = self._persist_and_match(binary, sha256, filename, is_dump, base_addr, bitness)
            else:
                result = self._transient_match(binary, is_dump, base_addr)
        except TimeoutError as err:
            return EngineResult(status="timeout", error=str(err))
        except Exception as err:
            log.exception("MCRIT analysis failed for %s", filename)
            return EngineResult(status="error", error=str(err))

        if result is None:
            return EngineResult(status="error", error="no result returned from MCRIT")

        out = EngineResult(status="ok")
        out.matches = self._select_matches(self._parse_matches(result))
        if not out.matches:
            out.status = "no_match"
        return out

    # -- match strategies -------------------------------------------------

    def _transient_match(self, binary, is_dump, base_addr):
        params = self._match_params()
        if is_dump and base_addr is not None:
            url = f"{self.host}/query/binary/mapped/{base_addr:#x}"
        else:
            url = f"{self.host}/query/binary"
        job_id = self._unwrap(self._session.post(url, data=binary, params=params, timeout=30))
        if not job_id:
            raise RuntimeError(f"MCRIT returned no job_id for {url}")
        return self._await_result(job_id)

    def _persist_and_match(self, binary, sha256, filename, is_dump, base_addr, bitness):
        sample_id = self._get_sample_id_by_sha256(sha256)
        if sample_id is None:
            job_id = self._submit_binary(binary, filename, is_dump, base_addr, bitness)
            if job_id:
                self._await_result(job_id)
            sample_id = self._get_sample_id_by_sha256(sha256)
            if sample_id is None:
                raise RuntimeError("sample submitted but sha256 not found in MCRIT")
        job_id = self._unwrap(self._session.get(
            f"{self.host}/matches/sample/{sample_id}", params=self._match_params(), timeout=30))
        if not job_id:
            raise RuntimeError("MCRIT returned no match job_id")
        return self._await_result(job_id)

    # -- HTTP helpers -----------------------------------------------------

    def _auth_headers(self):
        h = {}
        if self.apitoken:
            h["apitoken"] = self.apitoken
        if self.username:
            h["username"] = self.username
        return h

    def _match_params(self):
        return {"minhash_score": self.minhash_threshold} if self.minhash_threshold is not None else {}

    @staticmethod
    def _unwrap(response):
        try:
            if response.status_code not in (200, 202):
                return None
            j = response.json()
            if isinstance(j, dict) and j.get("status") == "successful":
                return j.get("data")
        except Exception:
            pass
        return None

    def _get_sample_id_by_sha256(self, sha256):
        try:
            data = self._unwrap(self._session.get(f"{self.host}/samples/sha256/{sha256}", timeout=15))
            if isinstance(data, dict):
                return data.get("sample_id")
        except Exception:
            pass
        return None

    def _submit_binary(self, binary, filename, is_dump, base_addr, bitness):
        fields = [f"filename={filename}"]
        if is_dump:
            fields.append("is_dump=1")
        if base_addr is not None:
            fields.append(f"base_addr={base_addr:#x}")
        if bitness in (32, 64):
            fields.append(f"bitness={bitness}")
        qs = "?" + "&".join(fields)
        return self._unwrap(self._session.post(f"{self.host}/samples/binary{qs}", data=binary, timeout=30))

    # -- job polling (threaded deadline) ----------------------------------

    def _await_result(self, job_id):
        container = {}

        def _poll():
            try:
                container["result"] = self._poll_job(job_id)
            except Exception as err:
                container["error"] = err

        t = threading.Thread(target=_poll, daemon=True)
        t.start()
        t.join(self.timeout)
        if t.is_alive():
            raise TimeoutError(f"MCRIT job {job_id} exceeded {self.timeout}s deadline")
        if "error" in container:
            raise container["error"]
        return container.get("result")

    def _poll_job(self, job_id):
        while True:
            job = self._unwrap(self._session.get(f"{self.host}/jobs/{job_id}", timeout=15))
            if not isinstance(job, dict):
                raise RuntimeError(f"unexpected job response for {job_id}")
            if job.get("terminated"):
                raise RuntimeError(f"MCRIT job {job_id} terminated")
            if job.get("attempts_left") == 0:
                raise RuntimeError(f"MCRIT job {job_id} failed (attempts exhausted)")
            result_id = job.get("result")
            if result_id:
                return self._unwrap(self._session.get(f"{self.host}/results/{result_id}", timeout=30))
            time.sleep(self.poll_interval)

    # -- result parsing ---------------------------------------------------

    def _parse_matches(self, result_dict) -> List[MatchRecord]:
        records: List[MatchRecord] = []
        if not isinstance(result_dict, dict):
            return records
        for s in (result_dict.get("matches") or {}).get("samples") or []:
            matched = s.get("matched") or {}
            percent = matched.get("percent") or {}
            functions = matched.get("functions") or {}
            combined = functions.get("combined") or 0
            library = functions.get("library") or 0

            if self.ignore_library_matches:
                # Drop matches whose matched functions are entirely library code.
                if combined > 0 and library >= combined:
                    continue
                # Score on the non-library weighted similarity so library-heavy
                # matches sink below the threshold. Fall back gracefully.
                similarity = percent.get("nonlib_score_weighted")
                if similarity is None:
                    similarity = percent.get("score_weighted") or percent.get("unweighted") or 0.0
            else:
                similarity = percent.get("score_weighted") or percent.get("unweighted") or 0.0

            records.append(MatchRecord(
                family=s.get("family") or None,
                similarity=float(similarity),
                sample_sha256=s.get("sha256"),
                sample_id=s.get("sample_id"),
                matched_functions=combined,
                total_functions=s.get("num_functions"),
                version=s.get("version") or None,
            ))
        return records
