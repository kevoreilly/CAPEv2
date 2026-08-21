# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Code-similarity processing module.

Runs after CAPE extraction + YARA detection (order=20). Collects artifacts
(submitted file, CAPE payloads, process dumps, dropped files) that did not
already resolve to a known family, filters them to the formats each engine
supports (per engine; MCRIT does PE/ELF/Mach-O), submits them, and
writes results to results["similarity"].

Output shape:
    results["similarity"] = {
        "enabled_engines": ["mcrit"],
        "results": {"mcrit": [ {file, sha256, source, status, matches:[...]}, ... ]},
        "by_sha256": {"<sha256>": [ {engine, ...match...}, ... ]},  # for per-file UI
    }

Optionally promotes a high-confidence top family match into CAPE's own
detections list so similarity acts as a classification engine.
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.integrations.similarity.base import detect_format
from lib.cuckoo.common.integrations.similarity.registry import get_enabled_engines

log = logging.getLogger(__name__)


class Similarity(Processing):
    """Submit unidentified artifacts to code-similarity engines."""

    order = 20

    def run(self):
        self.key = "similarity"

        try:
            options = dict(Config("integrations").get("similarity") or {})
        except Exception as err:
            log.warning("Could not read [similarity] from integrations.conf: %s", err)
            return {}

        engines = get_enabled_engines(options)
        if not engines:
            return {}

        only_unidentified = _as_bool(options.get("only_unidentified", True))
        sources_enabled = {
            "payload": _as_bool(options.get("similarity_payloads", True)),
            "procdump": _as_bool(options.get("similarity_procdump", True)),
            "dropped": _as_bool(options.get("similarity_dropped", True)),
            "submitted": _as_bool(options.get("similarity_submittedfile", False)),
        }
        concurrent = _as_bool(options.get("concurrent_submissions", False))
        max_workers = int(options.get("max_workers", 4) or 4)

        update_malfamily = _as_bool(options.get("update_malfamily", False))
        malfamily_min_sim = float(options.get("malfamily_minimum_similarity", 80) or 80)
        malfamily_mode = (options.get("malfamily_mode", "top") or "top").strip().lower()
        if malfamily_mode not in ("top", "all"):
            malfamily_mode = "top"

        candidates = []
        if sources_enabled["payload"]:
            candidates.extend(self._gather_payloads(only_unidentified))
        if sources_enabled["procdump"]:
            candidates.extend(self._gather_procdumps())
        if sources_enabled["dropped"]:
            candidates.extend(self._gather_dropped())
        if sources_enabled["submitted"]:
            candidates.extend(self._gather_submitted(only_unidentified))

        # Deduplicate by sha256, keep only files that still exist.
        seen, unique = set(), []
        for cand in candidates:
            if cand["sha256"] not in seen and os.path.exists(cand["path"]):
                seen.add(cand["sha256"])
                unique.append(cand)

        if not unique:
            log.info("Similarity: no candidates to submit (only_unidentified=%s). "
                     "Set only_unidentified=no to include already-identified artifacts.",
                     only_unidentified)
            return {}

        # Build (engine, idx, candidate) tasks, skipping format mismatches so
        # e.g. an ELF is never sent to MCRIT (PE-only).
        tasks = []
        for engine in engines:
            for idx, cand in enumerate(unique):
                if engine.accepts_format(cand["format"]):
                    tasks.append((engine, idx, cand))
                else:
                    log.debug("Similarity: %s skips %s (format=%s not supported)",
                              engine.name, cand["filename"], cand["format"])

        if not tasks:
            log.info("Similarity: no artifacts match the enabled engines' supported formats.")
            return {}

        log.info("Similarity: submitting %d task(s) to engine(s): %s",
                 len(tasks), ", ".join(e.name for e in engines))

        rows_by_engine = {engine.name: [None] * len(unique) for engine in engines}

        if concurrent and len(tasks) > 1 and max_workers > 1:
            workers = min(max_workers, len(tasks))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="similarity") as pool:
                futures = [pool.submit(self._analyze_one, eng, cand) for eng, _i, cand in tasks]
                for (eng, idx, _c), future in zip(tasks, futures):
                    rows_by_engine[eng.name][idx] = future.result()
        else:
            for eng, idx, cand in tasks:
                rows_by_engine[eng.name][idx] = self._analyze_one(eng, cand)

        output = {"enabled_engines": [e.name for e in engines], "results": {}, "by_sha256": {}}
        for engine_name, rows in rows_by_engine.items():
            kept = [r for r in rows if r is not None]
            if kept:
                output["results"][engine_name] = kept

        if not output["results"]:
            return {}

        # Per-file index for the web UI: sha256 -> list of match dicts (with engine tag).
        for engine_name, rows in output["results"].items():
            for row in rows:
                if not row.get("matches"):
                    continue
                bucket = output["by_sha256"].setdefault(row["sha256"], [])
                for match in row["matches"]:
                    entry = dict(match)
                    entry["engine"] = engine_name
                    bucket.append(entry)

        # Annotate each source artifact dict in-place with its matches. Because
        # _file_info.html renders the payload/dropped/procdump/target dict
        # directly (as its ``file`` variable), this makes matches appear in
        # every view — the overview page and the AJAX-loaded Payloads/Dropped/
        # Procdump tabs — without any change to web/analysis/views.py.
        for cand in unique:
            matches = output["by_sha256"].get(cand["sha256"])
            if matches and isinstance(cand.get("artifact"), dict):
                cand["artifact"]["code_similarity_matches"] = matches

        if update_malfamily:
            self._apply_family_classifications(output, malfamily_min_sim, malfamily_mode)

        return output

    # -- per-task analysis ------------------------------------------------

    def _analyze_one(self, engine, cand):
        try:
            result = engine.analyze(
                file_path=cand["path"], sha256=cand["sha256"],
                filename=cand["filename"], source=cand["source"],
                is_dump=cand["is_dump"], base_addr=cand["base_addr"],
                bitness=cand.get("bitness"),
            )
        except Exception as err:
            log.exception("Similarity engine '%s' crashed on %s", engine.name, cand["filename"])
            return {"file": cand["filename"], "sha256": cand["sha256"], "source": cand["source"],
                    "status": "error", "error": str(err), "matches": []}
        row = {"file": cand["filename"], "sha256": cand["sha256"], "source": cand["source"]}
        row.update(result.to_dict())
        # Keep every real submission attempt visible; drop only skipped.
        return row if result.status != "skipped" else None

    # -- candidate collection ---------------------------------------------

    def _gather_payloads(self, only_unidentified):
        rows = []
        cape = self.results.get("CAPE", {})
        payloads = cape.get("payloads", []) if isinstance(cape, dict) else (cape if isinstance(cape, list) else [])
        for p in payloads:
            if not isinstance(p, dict):
                continue
            if not p.get("path") or not p.get("sha256"):
                continue
            if only_unidentified and self._payload_identified(p):
                continue
            rows.append(self._mk(p, p["path"], "payload", is_dump=False))
        return rows

    def _gather_procdumps(self):
        rows = []
        for d in (self.results.get("procdump") or []):
            if isinstance(d, dict) and d.get("path") and d.get("sha256"):
                rows.append(self._mk(d, d["path"], "procdump", is_dump=True, base_addr=self._dump_base(d)))
        return rows

    def _gather_dropped(self):
        rows = []
        for d in (self.results.get("dropped") or []):
            if isinstance(d, dict) and d.get("path") and d.get("sha256"):
                rows.append(self._mk(d, d["path"], "dropped", is_dump=False))
        return rows

    def _gather_submitted(self, only_unidentified):
        target = self.results.get("target", {})
        f = target.get("file") if isinstance(target, dict) else None
        if not isinstance(f, dict) or not f.get("path") or not f.get("sha256"):
            return []
        if only_unidentified and self._analysis_has_family():
            return []
        return [self._mk(f, f["path"], "submitted", is_dump=False)]

    def _mk(self, info, path, source, is_dump=False, base_addr=None):
        """Build a candidate dict, deriving its format from CAPE's 'type' field.

        ``artifact`` keeps a reference to the original report dict (payload /
        dropped / procdump / target file) so matches can be annotated back onto
        it for per-file rendering in the web UI.
        """
        return {
            "path": path,
            "sha256": info["sha256"],
            "filename": info.get("name") or os.path.basename(path),
            "source": source,
            "is_dump": is_dump,
            "base_addr": base_addr,
            "format": detect_format(info.get("type")),
            "artifact": info,
        }

    # -- family classification --------------------------------------------

    def _apply_family_classifications(self, output, min_sim, mode="top"):
        """Promote family hits (>= min_sim) into results["detections"].

        mode="top": only the single highest-similarity family per artifact is
                    promoted (conservative; default).
        mode="all": every family whose match clears min_sim is promoted.

        Only artifacts with no existing family detection are considered, and
        each unique family is added at most once per analysis so the same
        family is never appended repeatedly across multiple matching payloads.
        """
        try:
            from lib.cuckoo.common.utils import add_family_detection
        except ImportError:
            log.warning("Similarity: add_family_detection unavailable; update_malfamily skipped.")
            return

        already_present = self._existing_detection_families()
        added = set()
        mode = (mode or "top").strip().lower()

        # Collect candidate (family, similarity, engine, sha256) tuples.
        promotions = []  # list of dicts
        per_artifact_best = {}  # sha256 -> best tuple

        for engine_name, rows in output.get("results", {}).items():
            for row in rows:
                sha256 = row.get("sha256", "")
                if not row.get("matches") or self._sha_already_identified(sha256):
                    continue
                for m in row["matches"]:
                    fam, sim = m.get("family"), float(m.get("similarity") or 0)
                    if not fam or sim < min_sim:
                        continue
                    entry = {"family": fam, "similarity": sim, "engine": engine_name, "sha256": sha256}
                    if mode == "all":
                        promotions.append(entry)
                    cur = per_artifact_best.get(sha256)
                    if cur is None or sim > cur["similarity"]:
                        per_artifact_best[sha256] = entry

        if mode != "all":
            promotions = list(per_artifact_best.values())

        # Highest-similarity first so the dedup keeps the strongest evidence.
        promotions.sort(key=lambda e: e["similarity"], reverse=True)

        for e in promotions:
            key = e["family"].lower()
            if key in already_present or key in added:
                continue  # never double-add the same family
            log.info("Similarity: classifying %s as '%s' (%.1f%%, via %s)",
                     e["sha256"][:12], e["family"], e["similarity"], e["engine"])
            add_family_detection(self.results, e["family"], f"Similarity/{e['engine']}", e["sha256"])
            added.add(key)

    def _existing_detection_families(self):
        return {(b.get("family") or "").lower() for b in (self.results.get("detections") or [])}

    def _sha_already_identified(self, sha256):
        for block in (self.results.get("detections") or []):
            for detail in (block.get("details") or []):
                if sha256 in detail.values():
                    return True
        return False

    # -- "already identified?" helpers ------------------------------------

    def _payload_identified(self, payload):
        if payload.get("cape_yara") or payload.get("detections") or payload.get("detection"):
            return True
        cape_type = (payload.get("cape_type") or "").lower()
        return bool(cape_type and "unknown" not in cape_type and "extraction" not in cape_type)

    def _analysis_has_family(self):
        return bool(self.results.get("malfamily") or self.results.get("malfamily_tag") or self.results.get("detections"))

    @staticmethod
    def _dump_base(dump):
        space = dump.get("address_space")
        if isinstance(space, list) and space:
            start = space[0].get("start")
            try:
                return int(start, 16) if isinstance(start, str) else int(start)
            except (TypeError, ValueError):
                pass
        base = dump.get("imagebase") or dump.get("base")
        try:
            return int(base, 16) if isinstance(base, str) else int(base)
        except (TypeError, ValueError):
            return None


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "yes", "true", "on", "y")
