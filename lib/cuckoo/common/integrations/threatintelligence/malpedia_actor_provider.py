# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2024 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Malpedia threat-actor provider — REFERENCE IMPLEMENTATION, OFF by default.

Implements the actor-enrichment path so the report-page actor card is ready
for real providers. Malpedia's actor data is sourced from community / MISP
curation, so its family<->actor links and attribution-confidence are often
only moderate. Attributing a sample to a named actor is a strong claim, so
this provider stays disabled unless explicitly enabled for a specific,
understood scenario; a dedicated high-confidence actor provider is the
intended driver of actor cards.

API (all GET, public; optional Authorization: apitoken <TOKEN>):
    GET /api/find/actor/<needle>   -> resolve a name/synonym to actor id(s)
    GET /api/get/actor/<actor_id>  -> actor meta
        {value/common_name, description, meta:{synonyms, country, refs,
         attribution-confidence, ...}, families:[...]}
"""

import logging
from typing import List, Optional
from urllib.parse import quote

from lib.cuckoo.common.integrations.threatintelligence.base import (
    ActorCard, ActorProvider, malpedia_actor_url, reference_label, squash_name,
)

log = logging.getLogger(__name__)

DEFAULT_HOST = "https://malpedia.caad.fkie.fraunhofer.de/api"


class MalpediaActorProvider(ActorProvider):
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
            log.warning("Malpedia actor: 'requests' unavailable (unexpected in CAPE venv).")
            return False
        return True

    def _get_session(self):
        if not hasattr(self, "_thread_local"):
            import threading
            self._thread_local = threading.local()
        session = getattr(self._thread_local, "session", None)
        if session is None:
            import requests
            session = requests.Session()
            session.headers.update({"Accept": "application/json"})
            if self.apitoken:
                session.headers.update({"Authorization": f"apitoken {self.apitoken}"})
            self._thread_local.session = session
        return session

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
            log.warning("Malpedia actor HTTP %s for %s", resp.status_code, path)
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    # -- resolution -------------------------------------------------------

    def resolve(self, query: str) -> Optional[str]:
        try:
            data = self._get(f"find/actor/{quote(query.strip(), safe='')}")
        except Exception as err:
            log.warning("Malpedia actor resolve failed for %r: %s", query, err)
            return None
        candidates = self._harvest_actor_ids(data)
        return self._best_candidate(query, candidates)

    @staticmethod
    def _harvest_actor_ids(obj) -> List[str]:
        """Collect actor-id-like strings from a loosely-typed find/actor blob iteratively."""
        found = []
        stack = [obj]
        while stack:
            node = stack.pop()
            if isinstance(node, str):
                s = node.strip().lower()
                # Actor ids are slugs (apt28, sofacy, lazarus_group); accept
                # short slug-ish tokens, exclude obvious sentences/urls.
                if s and " " not in s and "/" not in s and "." not in s and len(s) <= 64:
                    found.append(s)
            elif isinstance(node, dict):
                # push in reverse so pop() visits in document order
                for k, v in reversed(list(node.items())):
                    stack.append(v)
                    stack.append(k)
            elif isinstance(node, (list, tuple, set)):
                stack.extend(reversed(list(node)))
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
        for cid in candidates:
            if squash_name(cid) == want:
                return cid
        for cid in candidates:
            cs = squash_name(cid)
            if want and (want in cs or cs in want):
                return cid
        return None

    # -- fetch ------------------------------------------------------------

    def fetch(self, actor_id, provenance=None) -> Optional[ActorCard]:
        actor_id = actor_id.strip().lower()
        try:
            data = self._get(f"get/actor/{quote(actor_id, safe='')}")
        except Exception as err:
            log.warning("Malpedia actor fetch failed for %s: %s", actor_id, err)
            return None
        if not isinstance(data, dict):
            return None

        meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
        common = data.get("value") or data.get("common_name") or actor_id
        aliases = [a for a in (meta.get("synonyms") or data.get("synonyms") or []) if a]
        refs = self._select_references(meta.get("refs") or data.get("refs") or data.get("urls") or [])
        families = self._actor_families(data)
        confidence = _to_int(meta.get("attribution-confidence"))

        return ActorCard(
            source=self.name,
            actor_id=actor_id,
            common_name=common,
            aliases=aliases,
            description=(data.get("description") or meta.get("description") or "").strip(),
            country=meta.get("country"),
            references=refs,
            families=families,
            attribution_confidence=confidence,
            url=malpedia_actor_url(actor_id),
            provenance=provenance,
        )

    def _select_references(self, urls) -> List[dict]:
        urls = [u for u in urls if isinstance(u, str) and u.strip()]
        if self.max_references and self.max_references > 0:
            urls = urls[: self.max_references]
        return [{"url": u, "label": reference_label(u)} for u in urls]

    @staticmethod
    def _actor_families(data) -> List[str]:
        fams = data.get("families")
        out = []
        if isinstance(fams, dict):
            out = list(fams.keys())
        elif isinstance(fams, list):
            for f in fams:
                if isinstance(f, str):
                    out.append(f)
                elif isinstance(f, dict):
                    out.append(f.get("common_name") or f.get("family_id") or f.get("id") or "")
        return [f for f in out if f]


def _to_int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
