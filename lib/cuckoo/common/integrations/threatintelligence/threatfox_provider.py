# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2024 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""ThreatFox (abuse.ch) indicator provider — direct REST client.

Uses only ``requests`` (already in CAPE); no third-party ThreatFox client.

API (https://threatfox.abuse.ch/api/), single endpoint, POST JSON:
    POST https://threatfox-api.abuse.ch/api/v1/
    headers: Auth-Key: <key>            # REQUIRED since 2024
    body:    {"query":"search_ioc","search_term":"<indicator>","exact_match":bool}
    body:    {"query":"search_hash","hash":"<md5|sha256>"}
Responses: {"query_status":"ok"|"no_result"|..., "data":[ {ioc fields} ]}

Each ThreatFox row carries ``malware`` (a Malpedia family id, e.g.
win.cobalt_strike) — the processing module feeds those ids straight to the
family providers, so an infrastructure hit also yields a malware card.
"""

import logging
from typing import List, Optional

from lib.cuckoo.common.integrations.threatintelligence.base import (
    IND_DOMAIN, IND_HASH, IND_IP, IND_URL,
    IntelMatch, IndicatorProvider, ProviderResult,
    _as_bool, ioc_host_part, normalize_domain, url_match_key,
)

log = logging.getLogger(__name__)

DEFAULT_HOST = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxProvider(IndicatorProvider):
    name = "threatfox"
    supported_indicators = {IND_IP, IND_DOMAIN, IND_URL, IND_HASH}

    def __init__(self, options):
        super().__init__(options)
        self.host = (self.options.get("threatfox_host") or DEFAULT_HOST).strip()
        self.apikey = (self.options.get("threatfox_api") or "").strip() or None
        self.exact_match = _as_bool(self.options.get("threatfox_exact_match", False))
        self.match_ports_only = _as_bool(self.options.get("match_ports_only", False))
        # When True, an IOC only matches an indicator of the SAME type. When
        # False (default), url IOCs also match a contacted domain/IP by host,
        # except on dead-drop-resolver hosts (auto-detected below).
        self.strict_type_match = _as_bool(self.options.get("strict_ioc_type_match", False))
        # Rate-limit / transient-error resilience: retry on HTTP 429 / 5xx /
        # timeout with exponential backoff (honours Retry-After when present).
        self.retries = int(self.options.get("threatfox_retries", 3) or 0)
        self.backoff = float(self.options.get("threatfox_backoff", 0.5) or 0.0)
        self._session = None

    def available(self) -> bool:
        try:
            import requests  # noqa: F401
        except ImportError:
            log.warning("ThreatFox: 'requests' unavailable (unexpected in CAPE venv).")
            return False
        if not self.apikey:
            log.warning(
                "ThreatFox enabled but threatfox_api (Auth-Key) is empty. abuse.ch "
                "rejects unauthenticated requests; get a free key at "
                "https://auth.abuse.ch/ . Provider skipped."
            )
            return False
        return True

    def _get_session(self):
        if self._session is None:
            import requests
            s = requests.Session()
            s.headers.update({"Auth-Key": self.apikey, "Accept": "application/json"})
            self._session = s
        return self._session

    def lookup(self, indicator, indicator_type, ports=None) -> ProviderResult:
        if not self.apikey:
            return ProviderResult(status="disabled")
        try:
            if indicator_type == IND_HASH:
                payload = {"query": "search_hash", "hash": indicator}
            else:
                payload = {"query": "search_ioc", "search_term": indicator,
                           "exact_match": bool(self.exact_match)}
            data = self._post(payload)
        except TimeoutError as err:
            return ProviderResult(status="timeout", error=str(err))
        except Exception as err:
            log.warning("ThreatFox lookup failed for %s: %s", indicator, err)
            return ProviderResult(status="error", error=str(err))

        if data is None:
            return ProviderResult(status="error", error="no/invalid response")

        out = ProviderResult(status="ok")
        parsed = self._parse(data, indicator, indicator_type, ports)
        parsed = self._suppress_dead_drop(parsed, indicator, indicator_type)
        out.matches = self._select(parsed)
        if not out.matches:
            out.status = "no_match"
        return out

    def _post(self, payload):
        import random
        import time

        import requests

        attempt = 0
        while True:
            try:
                resp = self._get_session().post(self.host, json=payload, timeout=self.timeout)
            except requests.exceptions.Timeout as err:
                if attempt < self.retries:
                    self._sleep_backoff(attempt)
                    attempt += 1
                    continue
                raise TimeoutError(f"ThreatFox request exceeded {self.timeout}s") from err
            except requests.exceptions.RequestException as err:
                if attempt < self.retries:
                    self._sleep_backoff(attempt)
                    attempt += 1
                    continue
                raise

            # Rate limited / transient server error: back off and retry so a
            # burst of lookups doesn't silently drop enrichment for some hosts.
            if resp.status_code == 429 or 500 <= resp.status_code < 600:
                if attempt < self.retries:
                    delay = self._retry_after(resp)
                    if delay is None:
                        delay = self.backoff * (2 ** attempt) + random.uniform(0, 0.25)
                    log.info("ThreatFox HTTP %s; retrying in %.1fs (%d/%d)",
                             resp.status_code, delay, attempt + 1, self.retries)
                    time.sleep(delay)
                    attempt += 1
                    continue
                log.warning("ThreatFox HTTP %s after %d retries for query=%s",
                            resp.status_code, self.retries, payload.get("query"))
                return None

            if resp.status_code != 200:
                log.warning("ThreatFox HTTP %s for query=%s", resp.status_code, payload.get("query"))
                return None

            try:
                body = resp.json()
            except ValueError:
                log.warning("ThreatFox returned non-JSON response.")
                return None
            status = (body or {}).get("query_status")
            if status == "ok":
                data = body.get("data")
                return data if isinstance(data, list) else []
            if status in ("no_result", "no_results"):
                return []
            if status in ("illegal_auth_key", "unauthorized", "missing_auth_key"):
                log.warning("ThreatFox auth rejected (query_status=%s); check threatfox_api.", status)
                return None
            log.debug("ThreatFox query_status=%s (treated as no match)", status)
            return []

    def _sleep_backoff(self, attempt):
        import random
        import time
        time.sleep(self.backoff * (2 ** attempt) + random.uniform(0, 0.25))

    @staticmethod
    def _retry_after(resp):
        val = resp.headers.get("Retry-After")
        if not val:
            return None
        try:
            return float(val)
        except (TypeError, ValueError):
            return None

    def _parse(self, data, indicator, indicator_type, ports) -> List[IntelMatch]:
        matches: List[IntelMatch] = []
        want_ports = self._normalize_ports(ports) if self.match_ports_only else None
        for row in data:
            if not isinstance(row, dict):
                continue
            ioc = row.get("ioc") or ""
            ioc_type = row.get("ioc_type") or ""
            if not self._ioc_matches(ioc, ioc_type, indicator, indicator_type):
                continue
            if want_ports is not None and not self._port_matches(ioc, want_ports):
                continue
            ioc_id = row.get("id")
            indicator_url = f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id else None
            matches.append(IntelMatch(
                source=self.name, indicator=indicator, indicator_type=indicator_type,
                ioc=ioc, ioc_id=ioc_id, indicator_url=indicator_url,
                threat_type=row.get("threat_type"),
                threat_type_desc=row.get("threat_type_desc"),
                ioc_type=row.get("ioc_type"), ioc_type_desc=row.get("ioc_type_desc"),
                malware=row.get("malware"), malware_printable=row.get("malware_printable"),
                malware_alias=row.get("malware_alias"), malware_malpedia=row.get("malware_malpedia"),
                confidence_level=_to_int(row.get("confidence_level")),
                first_seen=row.get("first_seen"), last_seen=row.get("last_seen"),
                reference=row.get("reference"), reporter=row.get("reporter"),
                tags=row.get("tags") or [],
            ))
        return matches

    # IOC matching. By default an IOC matches an indicator of its own type,
    # AND a `url` IOC also matches a contacted domain/IP by HOST -- so a
    # dedicated malicious domain stored on ThreatFox as a url (e.g. a Lumma C2
    # like https://curtainjors.fun/api) still tags the domain. The
    # dead-drop-resolver false positive (a legitimate shared host like
    # steamcommunity.com carrying url IOCs for many families) is handled
    # separately by _suppress_dead_drop, which keys off family multiplicity
    # rather than bluntly dropping all url IOCs. Set strict_ioc_type_match to
    # require same-type matching only.
    _IP_IOC_TYPES = {"ip:port", "ip"}
    _HASH_IOC_TYPES = {"md5_hash", "sha256_hash", "sha1_hash", "sha384_hash", "sha512_hash"}

    def _ioc_matches(self, ioc, ioc_type, indicator, indicator_type) -> bool:
        ioc_type = (ioc_type or "").strip().lower()

        if indicator_type == IND_HASH:
            return (not ioc_type) or ioc_type in self._HASH_IOC_TYPES

        if indicator_type == IND_URL:
            if ioc_type and ioc_type != "url":
                return False
            return url_match_key(ioc) == url_match_key(indicator)

        if indicator_type == IND_DOMAIN:
            host_ok = ioc_host_part(ioc) == normalize_domain(indicator)
            if ioc_type == "domain" or not ioc_type:
                return host_ok
            if ioc_type == "url" and not self.strict_type_match:
                return host_ok  # host-level url match; dead-drop guarded later
            return False

        if indicator_type == IND_IP:
            host_ok = ioc_host_part(ioc) == indicator.strip().lower()
            if ioc_type in self._IP_IOC_TYPES or not ioc_type:
                return host_ok
            if ioc_type == "url" and not self.strict_type_match:
                return host_ok
            return False

        return False

    def _suppress_dead_drop(self, matches, indicator, indicator_type):
        """Drop host-level url matches on dead-drop-resolver hosts.

        A url IOC matched a domain/IP by host (not exact path). If such url
        IOCs on this single host span MORE THAN ONE malware family, the host
        is almost certainly a legitimate shared service abused as a dead drop
        resolver (steamcommunity.com, t.me, pastebin, ...), so those host-level
        url matches are false positives and are removed. A single-family host
        (a dedicated malicious domain) is kept. Same-type matches (domain/ip
        IOCs) are always kept.
        """
        if indicator_type not in (IND_DOMAIN, IND_IP):
            return matches
        url_hits = [m for m in matches if (m.ioc_type or "").strip().lower() == "url"]
        if not url_hits:
            return matches
        families = {(m.malware or m.malware_printable or "").lower() for m in url_hits}
        families.discard("")
        if len(families) > 1:
            log.info("ThreatFox: %s looks like a dead-drop resolver (url IOCs for %d "
                     "families); dropping host-level url matches.", indicator, len(families))
            return [m for m in matches if (m.ioc_type or "").strip().lower() != "url"]
        return matches

    @staticmethod
    def _normalize_ports(ports):
        out = set()
        for p in ports or []:
            try:
                out.add(int(p))
            except (TypeError, ValueError):
                continue
        return out

    @staticmethod
    def _port_matches(ioc, want_ports) -> bool:
        host = ioc.split("://", 1)[-1].split("/", 1)[0]
        if host.count(":") == 1:
            _, _, tail = host.rpartition(":")
            if tail.isdigit():
                return int(tail) in want_ports
        return True


def _to_int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
