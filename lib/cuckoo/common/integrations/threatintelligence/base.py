# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2024 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Threat-intelligence framework — base abstractions.

Two provider kinds share one registry and config section:

* IndicatorProvider — resolves a network indicator (ip / domain / sha256)
  to threat context. ThreatFox is the first. Produces IntelMatch records
  that become the red tags rendered against hosts/domains on the network
  page (``threat_type:malware_printable``).

* FamilyProvider — resolves a malware FAMILY (a name or a Malpedia id) to a
  descriptive card. Malpedia is the first. Produces FamilyCard records that
  populate the collapsible "Threat Intelligence" section on the report page.

The two are connected: families discovered by an IndicatorProvider hit
(e.g. ThreatFox returns ``win.cobalt_strike``) are fed to the family
providers, so an infrastructure match also yields a malware card.

Zero external dependencies (stdlib + whatever CAPE already ships); any
optional package is imported lazily inside available()/lookup().
"""

import logging
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# Indicator-type tokens.
IND_IP = "ip"
IND_DOMAIN = "domain"
IND_HASH = "hash"
IND_URL = "url"

# Malpedia family ids look like ``platform.family_name`` (win.emotet,
# elf.mirai, apk.flubot, osx.x, js.x, py.x, jar.x, ...).
_MALPEDIA_ID_RE = re.compile(r"^[a-z0-9]{2,12}\.[a-z0-9_]+$")
_MALPEDIA_DETAILS = "https://malpedia.caad.fkie.fraunhofer.de/details/"


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "yes", "true", "on", "y")


def normalize_domain(domain: Optional[str]) -> str:
    if not domain:
        return ""
    return domain.strip().rstrip(".").lower()


def ioc_host_part(ioc: Optional[str]) -> str:
    """Reduce a ThreatFox IOC string to its bare host (ip or domain)."""
    if not ioc:
        return ""
    s = ioc.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    if s.count(":") == 1:
        head, _, tail = s.rpartition(":")
        if tail.isdigit():
            s = head
    return s.strip().lower()


def looks_like_malpedia_id(value: Optional[str]) -> bool:
    return bool(value and _MALPEDIA_ID_RE.match(value.strip().lower()))


def url_match_key(url: Optional[str]) -> str:
    """Normalize a URL for exact, path-sensitive comparison.

    Scheme is intentionally ignored: CAPE's HTTP parser labels every
    reconstructed URL "http://" even when the real traffic was TLS, while
    ThreatFox may store the same dead-drop-resolver URL as "https://". We
    compare host (lower, minus default port) + path (minus trailing slash)
    + query, so a URL IOC only matches the EXACT resource the sample
    requested -- not merely its host.
    """
    if not url:
        return ""
    s = url.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    # split off fragment
    s = s.split("#", 1)[0]
    if "/" in s:
        netloc, _, rest = s.partition("/")
        path_q = "/" + rest
    else:
        netloc, path_q = s, "/"
    netloc = netloc.lower()
    # strip default ports
    if netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif netloc.endswith(":443"):
        netloc = netloc[:-4]
    # normalize a bare trailing slash so "/path" and "/path/" match, but keep
    # the root "/" meaningful
    path, sep, query = path_q.partition("?")
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return netloc + path + (sep + query if sep else "")


def malpedia_details_url(family_id: str) -> str:
    return _MALPEDIA_DETAILS + family_id.strip().lower()


_MALPEDIA_ACTOR = "https://malpedia.caad.fkie.fraunhofer.de/actor/"


def malpedia_actor_url(actor_id: str) -> str:
    return _MALPEDIA_ACTOR + actor_id.strip().lower()


def squash_name(name: Optional[str]) -> str:
    """Lower-case and strip to alphanumerics for fuzzy name comparison.

    "Cobalt Strike" -> "cobaltstrike", "CASTLESTEALER" -> "castlestealer",
    "win.castle_stealer" -> "wincastlestealer".
    """
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


# ============================================================
# Indicator side
# ============================================================
class IntelMatch:
    """A single normalized indicator hit (ThreatFox-style fields + badge)."""

    def __init__(self, source, indicator, indicator_type, ioc=None,
                 threat_type=None, threat_type_desc=None, ioc_type=None,
                 ioc_type_desc=None, malware=None, malware_printable=None,
                 malware_alias=None, malware_malpedia=None, confidence_level=None,
                 first_seen=None, last_seen=None, reference=None, reporter=None,
                 tags=None, tag_category=None, tag_value=None,
                 ioc_id=None, indicator_url=None):
        self.source = source
        self.indicator = indicator
        self.indicator_type = indicator_type
        self.ioc = ioc
        self.ioc_id = ioc_id
        # indicator_url: a direct link to THIS indicator hit on the provider
        # (e.g. the ThreatFox IOC page), as opposed to family/sample links.
        self.indicator_url = indicator_url
        self.threat_type = threat_type
        self.threat_type_desc = threat_type_desc
        self.ioc_type = ioc_type
        self.ioc_type_desc = ioc_type_desc
        self.malware = malware
        self.malware_printable = malware_printable
        self.malware_alias = malware_alias
        self.malware_malpedia = malware_malpedia
        self.confidence_level = confidence_level
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.reference = reference
        self.reporter = reporter
        self.tags = tags or []
        self.tag_category = tag_category or (threat_type or "")
        self.tag_value = tag_value if tag_value is not None else (malware_printable or "")

    @property
    def tag(self) -> str:
        cat = (self.tag_category or "").strip().lower()
        val = (self.tag_value or "").strip().lower()
        if cat and val:
            return f"{cat}:{val}"
        return cat or val

    @property
    def tooltip(self) -> str:
        bits = [self.source]
        if self.confidence_level is not None:
            bits.append(f"confidence {self.confidence_level}%")
        if self.ioc:
            bits.append(f"ioc {self.ioc}")
        if self.malware_printable:
            bits.append(self.malware_printable)
        if self.first_seen:
            bits.append(f"first seen {self.first_seen}")
        return " | ".join(bits)

    def dedup_key(self) -> str:
        return f"{self.source}|{self.tag}"

    def to_dict(self) -> Dict:
        return {
            "source": self.source, "indicator": self.indicator,
            "indicator_type": self.indicator_type, "ioc": self.ioc,
            "ioc_id": self.ioc_id, "indicator_url": self.indicator_url,
            "threat_type": self.threat_type, "threat_type_desc": self.threat_type_desc,
            "ioc_type": self.ioc_type, "ioc_type_desc": self.ioc_type_desc,
            "malware": self.malware, "malware_printable": self.malware_printable,
            "malware_alias": self.malware_alias, "malware_malpedia": self.malware_malpedia,
            "confidence_level": self.confidence_level, "first_seen": self.first_seen,
            "last_seen": self.last_seen, "reference": self.reference,
            "reporter": self.reporter, "tags": self.tags,
            "tag": self.tag, "tooltip": self.tooltip,
        }


class ProviderResult:
    """Per-indicator result from one indicator provider."""

    def __init__(self, status: str = "ok", error: Optional[str] = None):
        self.status = status  # ok | no_match | skipped | timeout | error | disabled
        self.error = error
        self.matches: List[IntelMatch] = []


class IndicatorProvider:
    """Base class for an indicator-lookup backend (e.g. ThreatFox)."""

    name = "base"
    supported_indicators: Set[str] = set()

    def __init__(self, options: Dict):
        self.options = options or {}
        self.timeout = int(self.options.get("timeout", 20) or 20)
        self.minimum_confidence = int(self.options.get("minimum_confidence", 0) or 0)
        self.max_results = int(self.options.get("max_results", 5) or 0)

    def accepts_indicator(self, indicator_type: str) -> bool:
        return indicator_type in self.supported_indicators

    def available(self) -> bool:
        return True

    def lookup(self, indicator: str, indicator_type: str, ports=None) -> ProviderResult:
        raise NotImplementedError

    def _select(self, matches: List[IntelMatch]) -> List[IntelMatch]:
        kept = [m for m in matches
                if (m.confidence_level is None or m.confidence_level >= self.minimum_confidence)]
        best: Dict[str, IntelMatch] = {}
        for m in kept:
            key = m.dedup_key()
            cur = best.get(key)
            if cur is None or (m.confidence_level or 0) > (cur.confidence_level or 0):
                best[key] = m
        ordered = sorted(best.values(), key=lambda m: (m.confidence_level or 0), reverse=True)
        if self.max_results and self.max_results > 0:
            ordered = ordered[: self.max_results]
        return ordered


# ============================================================
# Family side
# ============================================================
class FamilyCard:
    """A descriptive malware-family card for the report-page section."""

    def __init__(self, source, family_id=None, common_name=None, aliases=None,
                 description=None, references=None, attribution=None, updated=None,
                 url=None, provenance=None):
        self.source = source
        self.family_id = family_id
        self.common_name = common_name or (family_id.split(".", 1)[-1] if family_id else None)
        self.aliases = aliases or []
        self.description = description or ""
        # references: list of {"url":..., "label":...}
        self.references = references or []
        self.attribution = attribution or []   # associated actor names (groups later)
        self.updated = updated
        self.url = url or (malpedia_details_url(family_id) if family_id else None)
        # provenance: how this family surfaced (detection / malfamily / threatfox)
        self.provenance = set(provenance or ())

    def to_dict(self) -> Dict:
        return {
            "source": self.source,
            "family_id": self.family_id,
            "common_name": self.common_name,
            "aliases": self.aliases,
            "description": self.description,
            "references": self.references,
            "attribution": self.attribution,
            "updated": self.updated,
            "url": self.url,
            "provenance": sorted(self.provenance),
        }


class FamilyProvider:
    """Base class for a family-enrichment backend (e.g. Malpedia)."""

    name = "base"

    def __init__(self, options: Dict):
        self.options = options or {}
        self.timeout = int(self.options.get("timeout", 20) or 20)

    def available(self) -> bool:
        return True

    def resolve(self, query: str) -> Optional[str]:
        """Resolve a free-text family name to this provider's canonical id."""
        raise NotImplementedError

    def fetch(self, family_id: str, provenance=None) -> Optional[FamilyCard]:
        """Fetch a card for a canonical family id."""
        raise NotImplementedError

    def enrich(self, query: str, is_id: bool = False, provenance=None) -> Optional[FamilyCard]:
        """Resolve (unless already an id) then fetch a card."""
        family_id = query if is_id else self.resolve(query)
        if not family_id:
            return None
        return self.fetch(family_id, provenance=provenance)


def reference_label(url: str) -> str:
    """Human-friendly label for a reference link (its registrable host)."""
    try:
        host = urlparse(url).netloc or url
    except Exception:
        host = url
    return host[4:] if host.startswith("www.") else host


# ============================================================
# Threat-actor side  (SCAFFOLDING — wired but disabled by default)
# ============================================================
# Actor attribution must be HIGH CONFIDENCE. Showing a threat actor against a
# sample is a strong claim, so this path is intended for an authoritative,
# high-confidence actor provider and is gated off by default. A Malpedia actor
# provider exists as a reference implementation but its links derive from
# community/MISP curation (attribution-confidence is often moderate), so it too
# is disabled unless explicitly enabled for a specific, understood scenario.
class ActorCard:
    """A descriptive threat-actor card for the report-page section."""

    def __init__(self, source, actor_id=None, common_name=None, aliases=None,
                 description=None, country=None, references=None, families=None,
                 attribution_confidence=None, url=None, provenance=None):
        self.source = source
        self.actor_id = actor_id
        self.common_name = common_name or actor_id
        self.aliases = aliases or []
        self.description = description or ""
        self.country = country
        # references: list of {"url":..., "label":...}
        self.references = references or []
        # families: associated malware family names/ids
        self.families = families or []
        # attribution_confidence: provider-supplied 0-100 (or None)
        self.attribution_confidence = attribution_confidence
        self.url = url
        # provenance: how the actor surfaced (e.g. family attribution, a
        # high-confidence provider attribution, ...)
        self.provenance = set(provenance or ())

    def to_dict(self) -> Dict:
        return {
            "source": self.source,
            "actor_id": self.actor_id,
            "common_name": self.common_name,
            "aliases": self.aliases,
            "description": self.description,
            "country": self.country,
            "references": self.references,
            "families": self.families,
            "attribution_confidence": self.attribution_confidence,
            "url": self.url,
            "provenance": sorted(self.provenance),
        }


class ActorProvider:
    """Base class for a threat-actor enrichment backend.

    Mirrors FamilyProvider so actor engines slot into the same registry /
    processing / template pattern as malware-family engines.
    """

    name = "base"

    def __init__(self, options: Dict):
        self.options = options or {}
        self.timeout = int(self.options.get("timeout", 20) or 20)

    def available(self) -> bool:
        return True

    def resolve(self, query: str) -> Optional[str]:
        """Resolve a free-text actor name to this provider's canonical id."""
        raise NotImplementedError

    def fetch(self, actor_id: str, provenance=None) -> Optional[ActorCard]:
        """Fetch a card for a canonical actor id."""
        raise NotImplementedError

    def enrich(self, query: str, is_id: bool = False, provenance=None) -> Optional[ActorCard]:
        actor_id = query if is_id else self.resolve(query)
        if not actor_id:
            return None
        return self.fetch(actor_id, provenance=provenance)
