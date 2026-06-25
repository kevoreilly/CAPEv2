# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Code-similarity engine framework — base abstractions.

Zero external dependencies (stdlib + whatever CAPE already ships). New
engines subclass SimilarityEngine, declare the file formats they accept,
implement available()/analyze(), and register in registry.py.
"""

import logging
from typing import Dict, List, Optional, Set

log = logging.getLogger(__name__)

# Canonical file-format tokens used across the framework.
FMT_PE = "pe"
FMT_ELF = "elf"
FMT_MACHO = "macho"
FMT_UNKNOWN = "unknown"


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "yes", "true", "on", "y")


def detect_format(type_string: Optional[str], magic: Optional[bytes] = None) -> str:
    """Map CAPE's libmagic 'type' string (or raw magic) to a format token.

    Prefers CAPE's reported type (already computed during processing);
    falls back to magic-byte sniffing when the type string is absent.
    """
    t = (type_string or "").lower()
    if "pe32" in t or "ms-dos" in t or "ms windows" in t or "for ms windows" in t:
        return FMT_PE
    if "elf" in t:
        return FMT_ELF
    if "mach-o" in t or "mach o" in t:
        return FMT_MACHO
    if magic:
        if magic[:2] == b"MZ":
            return FMT_PE
        if magic[:4] == b"\x7fELF":
            return FMT_ELF
        if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                         b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            return FMT_MACHO
    return FMT_UNKNOWN


class MatchRecord:
    """Single normalized similarity hit, engine-agnostic."""

    def __init__(
        self,
        family: Optional[str],
        similarity: float,
        sample_sha256: Optional[str] = None,
        sample_id=None,
        matched_functions: Optional[int] = None,
        total_functions: Optional[int] = None,
        version: Optional[str] = None,
        is_low_confidence: bool = False,
    ):
        self.family = family or None
        self.similarity = round(float(similarity), 2)
        self.sample_sha256 = sample_sha256
        self.sample_id = sample_id
        self.matched_functions = matched_functions
        self.total_functions = total_functions
        self.version = version
        self.is_low_confidence = is_low_confidence

    @property
    def has_family(self) -> bool:
        return bool(self.family)

    def to_dict(self) -> Dict:
        return {
            "family": self.family,
            "similarity": self.similarity,
            "sample_sha256": self.sample_sha256,
            "sample_id": self.sample_id,
            "matched_functions": self.matched_functions,
            "total_functions": self.total_functions,
            "version": self.version,
            "low_confidence": self.is_low_confidence,
        }


class EngineResult:
    """Per-file result from one engine for one artifact."""

    def __init__(self, status: str = "ok", error: Optional[str] = None):
        # status: ok | no_match | skipped | timeout | error | disabled
        self.status = status
        self.error = error
        self.matches: List[MatchRecord] = []

    def to_dict(self) -> Dict:
        out = {"status": self.status, "matches": [m.to_dict() for m in self.matches]}
        if self.error:
            out["error"] = self.error
        return out


class SimilarityEngine:
    """Base class for a code-similarity backend.

    Subclasses set ``supported_formats`` to the set of file formats they
    can analyze, and implement available()/analyze(). External packages
    must only be imported lazily (inside available()) so a missing optional
    dependency cannot crash CAPE's plugin loader.
    """

    name = "base"
    # Formats this engine accepts. Override per engine.
    #   MCRIT -> {FMT_PE}            (PE only)
    #   a multi-format engine -> {FMT_PE, FMT_ELF, FMT_MACHO}
    supported_formats: Set[str] = {FMT_PE}

    def __init__(self, options: Dict):
        self.options = options or {}
        self.minimum_similarity = float(self.options.get("minimum_similarity", 50) or 0)
        self.match_families = _as_bool(self.options.get("match_families", True))
        self.match_nofamily = _as_bool(self.options.get("match_nofamily", True))
        self.best_match = _as_bool(self.options.get("best_match", False))
        self.max_results = int(self.options.get("max_results", 3) or 3)
        self.timeout = int(self.options.get("timeout", 120) or 120)
        excluded = self.options.get("exclude_families", "") or ""
        self.exclude_families = [e.strip().lower() for e in excluded.split(",") if e.strip()]

    def accepts_format(self, file_format: str) -> bool:
        return file_format in self.supported_formats

    def available(self) -> bool:
        return True

    def analyze(
        self,
        file_path: str,
        sha256: str,
        filename: str,
        source: str,
        is_dump: bool = False,
        base_addr: Optional[int] = None,
        bitness: Optional[int] = None,
    ) -> EngineResult:
        raise NotImplementedError

    def _is_excluded_family(self, family: Optional[str]) -> bool:
        if not family or not self.exclude_families:
            return False
        return any(token in family.lower() for token in self.exclude_families)

    def _select_matches(self, candidates: List[MatchRecord]) -> List[MatchRecord]:
        """Apply shared family/threshold/best-match selection, then cap to max_results."""
        candidates = [c for c in candidates if not self._is_excluded_family(c.family)]

        kept: List[MatchRecord] = []
        for cand in candidates:
            if cand.has_family and not self.match_families:
                continue
            if not cand.has_family and not self.match_nofamily:
                continue
            if cand.similarity >= self.minimum_similarity:
                kept.append(cand)

        if kept:
            kept.sort(key=lambda m: m.similarity, reverse=True)
            return kept[: self.max_results] if self.max_results > 0 else kept

        # Nothing cleared the threshold: optionally surface the single best hit.
        if self.best_match and candidates:
            eligible = [
                c for c in candidates
                if (c.has_family and self.match_families) or (not c.has_family and self.match_nofamily)
            ]
            if eligible:
                best = max(eligible, key=lambda m: m.similarity)
                best.is_low_confidence = True
                return [best]

        return []
