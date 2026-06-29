# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2024 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Malpedia family-enrichment provider — direct REST client.

Uses only ``requests`` (already in CAPE). No third-party Malpedia client.

API (https://malpedia.caad.fkie.fraunhofer.de/usage/api), all GET, the
endpoints we use are public (no auth); an optional APIToken raises rate
limits and is sent as ``Authorization: apitoken <TOKEN>``:

    GET /api/find/family/<needle>     -> resolve a name/alias to family id(s)
    GET /api/get/family/<family_id>   -> family metadata
        {common_name, description, alt_names[], attribution[], urls[], updated}

ThreatFox already hands us canonical ids (win.cobalt_strike), so those skip
resolution; CAPE's own YARA/detection family names are resolved via
find/family. Focus is malware families.
"""

import logging
import re
from typing import List, Optional
from urllib.parse import quote

from lib.cuckoo.common.integrations.threatintelligence.base import (
    FamilyCard, FamilyProvider, looks_like_malpedia_id, malpedia_details_url,
    reference_label, squash_name,
)

log = logging.getLogger(__name__)

DEFAULT_HOST = "https://malpedia.caad.fkie.fraunhofer.de/api"

# Malpedia platform prefixes — used to harvest ids from loosely-typed
# find/family responses without over-matching arbitrary "a.b" strings.
_PLATFORMS = ("win", "elf", "apk", "osx", "jar", "js", "py", "vbs", "ps1",
              "swf", "sh", "asp", "php", "pl", "rb", "go", "symbian", "ios")


class MalpediaProvider(FamilyProvider):
    name = "malpedia"

    def __init__(self, options):
        super().__init__(options)
        self.host = (self.options.get("malpedia_host") or DEFAULT_HOST).strip().rstrip("/")
        self.apitoken = (self.options.get("malpedia_api") or "").strip() or None
        self.max_references = int(self.options.get("malpedia_max_references", 4) or 0)
        self._session = None

    def available(self) -> bool:
        try:
            import requests  # noqa: F401
        except ImportError:
            log.warning("Malpedia: 'requests' unavailable (unexpected in CAPE venv).")
            return False
        return True

    def _get_session(self):
        if self._session is None:
            import requests
            s = requests.Session()
            s.headers.update({"Accept": "application/json"})
            if self.apitoken:
                s.headers.update({"Authorization": f"apitoken {self.apitoken}"})
            self._session = s
        return self._session

    # -- HTTP -------------------------------------------------------------

    def _get(self, path):
        import requests
        url = f"{self.host}/{path.lstrip('/')}"
        try:
            resp = self._get_session().get(url, timeout=self.timeout)
        except requests.exceptions.Timeout as err:
            raise TimeoutError(f"Malpedia request exceeded {self.timeout}s") from err
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            log.warning("Malpedia HTTP %s for %s", resp.status_code, path)
            return None
        try:
            return resp.json()
        except ValueError:
            log.warning("Malpedia returned non-JSON for %s", path)
            return None

    def _get_raw(self, path):
        """GET returning the raw response text (used for the .bib endpoint)."""
        import requests
        url = f"{self.host}/{path.lstrip('/')}"
        try:
            resp = self._get_session().get(url, timeout=self.timeout)
        except requests.exceptions.Timeout as err:
            raise TimeoutError(f"Malpedia request exceeded {self.timeout}s") from err
        if resp.status_code != 200:
            return None
        return resp.text

    # -- resolution -------------------------------------------------------

    def resolve(self, query: str) -> Optional[str]:
        if looks_like_malpedia_id(query):
            return query.strip().lower()
        try:
            data = self._get(f"find/family/{quote(query.strip(), safe='')}")
        except Exception as err:
            log.warning("Malpedia resolve failed for %r: %s", query, err)
            return None
        candidates = self._harvest_ids(data)
        return self._best_candidate(query, candidates)

    @classmethod
    def _harvest_ids(cls, obj) -> List[str]:
        """Recursively collect Malpedia family ids from a loosely-typed blob."""
        found = []

        def visit(node):
            if isinstance(node, str):
                s = node.strip().lower()
                if "." in s and s.split(".", 1)[0] in _PLATFORMS and looks_like_malpedia_id(s):
                    found.append(s)
            elif isinstance(node, dict):
                for k, v in node.items():
                    visit(k)
                    visit(v)
            elif isinstance(node, (list, tuple, set)):
                for v in node:
                    visit(v)

        visit(obj)
        # preserve order, de-dup
        seen, out = set(), []
        for f in found:
            if f not in seen:
                seen.add(f)
                out.append(f)
        return out

    @staticmethod
    def _best_candidate(query, candidates) -> Optional[str]:
        if not candidates:
            return None
        want = squash_name(query)
        # 1) exact match on the family part (after the platform dot)
        for cid in candidates:
            if squash_name(cid.split(".", 1)[-1]) == want:
                return cid
        # 2) exact match on the whole id squashed
        for cid in candidates:
            if squash_name(cid) == want:
                return cid
        # 3) family part contains the query (or vice-versa)
        for cid in candidates:
            fam = squash_name(cid.split(".", 1)[-1])
            if want and (want in fam or fam in want):
                return cid
        # 4) give up on ambiguity rather than guess wrong
        return None

    # -- fetch ------------------------------------------------------------

    def fetch(self, family_id, provenance=None) -> Optional[FamilyCard]:
        family_id = family_id.strip().lower()
        try:
            data = self._get(f"get/family/{quote(family_id, safe='.')}")
        except Exception as err:
            log.warning("Malpedia fetch failed for %s: %s", family_id, err)
            return None
        if not isinstance(data, dict):
            return None

        references = self._select_references(data.get("urls") or [], family_id)
        attribution = self._parse_attribution(data.get("attribution") or [])
        common = data.get("common_name") or family_id.split(".", 1)[-1]

        return FamilyCard(
            source=self.name,
            family_id=family_id,
            common_name=common,
            aliases=[a for a in (data.get("alt_names") or []) if a],
            description=(data.get("description") or "").strip(),
            references=references,
            attribution=attribution,
            updated=data.get("updated"),
            url=malpedia_details_url(family_id),
            provenance=provenance,
        )

    def _select_references(self, urls, family_id) -> List[dict]:
        """Order references by real publication date (most recent first).

        Malpedia's get/family ``urls`` is a flat list with NO dates and is
        not chronologically ordered, so we cannot infer recency from it.
        The per-family BibTeX endpoint (get/bib/family/<id>) does carry a
        date/year per reference, so we use it to sort. If the bib is
        unavailable, we fall back to the native list order (best effort) and
        omit the recency claim by leaving dates blank.
        """
        urls = [u for u in urls if isinstance(u, str) and u.strip()]
        dates = {}
        try:
            raw = self._get_raw(f"get/bib/family/{quote(family_id, safe='.')}")
            if raw:
                dates = _parse_bib_dates(raw)
        except Exception as err:
            log.debug("Malpedia bib lookup failed for %s: %s", family_id, err)

        if dates:
            dated = sorted((u for u in urls if u in dates), key=lambda u: dates[u], reverse=True)
            undated = [u for u in urls if u not in dates]
            ordered = dated + undated
        else:
            # No dates available: keep Malpedia's native order rather than
            # pretending to know recency.
            ordered = urls

        if self.max_references and self.max_references > 0:
            ordered = ordered[: self.max_references]
        return [{"url": u, "label": reference_label(u), "date": dates.get(u)} for u in ordered]

    @staticmethod
    def _parse_attribution(attribution) -> List[str]:
        names = []
        for item in attribution:
            if isinstance(item, dict):
                for key in ("value", "common_name", "name", "actor"):
                    if item.get(key):
                        names.append(str(item[key]))
                        break
            elif isinstance(item, str) and item.strip():
                names.append(item.strip())
        # de-dup, keep order
        seen, out = set(), []
        for n in names:
            if n.lower() not in seen:
                seen.add(n.lower())
                out.append(n)
        return out


# BibTeX field extractors (tolerant of {..} or "..", any whitespace/case).
_BIB_URL = re.compile(r'\burl\s*=\s*[{"]([^}"]+)[}"]', re.I)
_BIB_DATE = re.compile(r'\bdate\s*=\s*[{"]([^}"]+)[}"]', re.I)
_BIB_YEAR = re.compile(r'\byear\s*=\s*[{"]?\s*(\d{4})', re.I)


def _parse_bib_dates(text: str) -> dict:
    """Map reference URL -> date string from a Malpedia family .bib file.

    Returns ISO-ish date strings ("2022-05-01") or bare years ("2022"),
    which sort lexicographically in chronological order. Best-effort: any
    entry without both a url and a date is skipped.
    """
    out = {}
    for entry in re.split(r'\n@', text or ""):
        m_url = _BIB_URL.search(entry)
        if not m_url:
            continue
        url = m_url.group(1).strip()
        m_date = _BIB_DATE.search(entry)
        date = m_date.group(1).strip() if m_date else None
        if not date:
            m_year = _BIB_YEAR.search(entry)
            date = m_year.group(1) if m_year else None
        if url and date:
            prev = out.get(url)
            if prev is None or date > prev:
                out[url] = date
    return out
