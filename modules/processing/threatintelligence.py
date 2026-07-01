# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2024 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Threat-intelligence processing module.

Runs late (order=22) so network analysis and family detections are already
populated. Two phases:

1. Indicator phase (ThreatFox, ...): looks up contacted host IPs / domains
   (and optionally the sample sha256) per the global indicator toggles,
   annotates network hosts/domains in-place with red tags, and harvests the
   Malpedia family ids that those infrastructure hits reference.

2. Family phase (Malpedia, ...): takes the malware families surfaced by
   CAPE's own detections / malfamily AND by the indicator hits, fetches a
   descriptive card for each (name, aliases, description, recent reference
   reports), and writes them for the collapsible "Threat Intelligence"
   report-page section.

Output (results["threatintelligence"]):
    {
      "providers": {"indicator": ["threatfox"], "family": ["malpedia"]},
      "indicators": {"by_indicator": {...}, "count": N},
      "families": [ {family_id, common_name, aliases, description,
                     references:[{url,label}], attribution, url,
                     provenance:[...]}, ... ],
      "stats": {...},
    }
"""

import logging
from concurrent.futures import ThreadPoolExecutor

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.integrations.threatintelligence.base import (
    IND_DOMAIN, IND_HASH, IND_IP, IND_URL, _as_bool, looks_like_malpedia_id,
    normalize_domain, squash_name,
)
from lib.cuckoo.common.integrations.threatintelligence.cache import IntelCache
from lib.cuckoo.common.integrations.threatintelligence.registry import (
    get_enabled_actor_providers, get_enabled_family_providers, get_enabled_indicator_providers,
)

log = logging.getLogger(__name__)


def _looks_like_ip(value):
    """Cheap check: is this host an IP literal (so it's not a domain)?"""
    if not value:
        return False
    v = str(value).strip().strip("[]")
    if ":" in v and "." not in v:
        return True  # IPv6
    parts = v.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


class ThreatIntelligence(Processing):
    """Enrich an analysis with external threat intelligence."""

    order = 22

    def run(self):
        self.key = "threatintelligence"

        try:
            options = dict(Config("integrations").get("threatintelligence") or {})
        except Exception as err:
            log.warning("Could not read [threatintelligence] from integrations.conf: %s", err)
            return {}

        indicator_providers = get_enabled_indicator_providers(options)
        family_providers = get_enabled_family_providers(options)
        # Threat-actor engines are additionally gated by a master "threat
        # actors" toggle (default off) because actor attribution is a strong,
        # high-confidence-only claim.
        actor_enabled = _as_bool(options.get("threat actors", False))
        actor_providers = get_enabled_actor_providers(options) if actor_enabled else []
        if not indicator_providers and not family_providers and not actor_providers:
            return {}

        self.cache = IntelCache(
            enabled=_as_bool(options.get("cache", True)),
            ttl=int(options.get("cache_ttl", 86400) or 0),
        )
        self.concurrent = _as_bool(options.get("concurrent_lookups", True))
        self.max_workers = int(options.get("max_workers", 4) or 4)
        self.max_results = int(options.get("max_results", 5) or 0)
        # Safety valve for shared/abused infrastructure: if one indicator
        # matches more than this many distinct families it is treated as an
        # ambiguous shared host and its tags are suppressed. 0 = no limit.
        self.max_families_per_indicator = int(options.get("max_families_per_indicator", 5) or 0)

        # Global indicator-type toggles (his requested layout).
        lookups = {
            IND_IP: _as_bool(options.get("ip addresses", True)),
            IND_DOMAIN: _as_bool(options.get("domains", True)),
            IND_URL: _as_bool(options.get("urls", False)),
            IND_HASH: _as_bool(options.get("sha256", False)),
        }

        by_indicator, discovered_families = {}, []
        if indicator_providers:
            by_indicator, discovered_families = self._indicator_phase(
                indicator_providers, lookups)

        # Optionally promote indicator hits to CAPE detections. This APPENDS a
        # detection entry (via add_family_detection) and never sets the
        # headline malfamily, so ThreatFox infrastructure attribution does not
        # override CAPE's own classification. Off by default; C2-only by
        # default when enabled.
        promoted = []
        if by_indicator and _as_bool(options.get("promote_to_detection", False)):
            promoted = self._promote_detections(by_indicator, options)

        families = []
        if family_providers:
            from_threatfox = _as_bool(options.get("malpedia_from_threatfox", True))
            hints = self._gather_family_hints(discovered_families if from_threatfox else [])
            families = self._family_phase(family_providers, hints)

        # Actor phase (gated): only when master toggle on AND an actor engine
        # is enabled. Hints are the actors that the matched families are
        # attributed to (and, in future, explicit high-confidence provider
        # attributions). Off by default.
        actors = []
        if actor_providers:
            actor_hints = self._gather_actor_hints(families, options)
            actors = self._actor_phase(actor_providers, actor_hints)

        if not by_indicator and not families and not actors:
            return {}

        return {
            "providers": {
                "indicator": [p.name for p in indicator_providers],
                "family": [p.name for p in family_providers],
                "actor": [p.name for p in actor_providers],
            },
            "indicators": {"by_indicator": by_indicator, "count": len(by_indicator)},
            "families": families,
            "actors": actors,
            "promoted_detections": promoted,
            "stats": {
                "indicators_with_intel": len(by_indicator),
                "families": len(families),
                "actors": len(actors),
            },
        }

    # ================================================================
    # Indicator phase
    # ================================================================
    def _indicator_phase(self, providers, lookups):
        network = self.results.get("network") or {}
        if not isinstance(network, dict):
            network = {}

        ip_ports, domains, urls = {}, set(), set()
        if lookups[IND_IP]:
            for host in network.get("hosts") or []:
                if isinstance(host, dict) and host.get("ip"):
                    ip = str(host["ip"]).strip()
                    ip_ports.setdefault(ip, set()).update(host.get("ports") or [])
            # Accurate ip:port construction: ports actually contacted in the
            # capture (TCP/UDP destinations). These drive precise ip:port
            # matching when match_ports_only is enabled.
            for proto in ("tcp", "udp"):
                for conn in network.get(proto) or []:
                    if isinstance(conn, dict) and conn.get("dst") and conn.get("dport"):
                        ip_ports.setdefault(str(conn["dst"]).strip(), set()).add(conn["dport"])
        if lookups[IND_DOMAIN]:
            # Gather domains from EVERY network surface so nothing contacted is
            # skipped: resolved domains, DNS requests + answers, HTTP Host
            # headers, reverse-resolved host names, and TLS SNI.
            for d in network.get("domains") or []:
                if isinstance(d, dict) and d.get("domain"):
                    domains.add(normalize_domain(d["domain"]))
            for req in network.get("dns") or []:
                if isinstance(req, dict):
                    if req.get("request"):
                        domains.add(normalize_domain(req["request"]))
                    for ans in req.get("answers") or []:
                        data = ans.get("data") if isinstance(ans, dict) else None
                        if data and (ans.get("type") in ("CNAME", "NS", "PTR")):
                            domains.add(normalize_domain(data))
            for h in network.get("http") or []:
                if isinstance(h, dict) and h.get("host") and not _looks_like_ip(h["host"]):
                    domains.add(normalize_domain(h["host"]))
            for host in network.get("hosts") or []:
                if isinstance(host, dict) and host.get("hostname"):
                    domains.add(normalize_domain(host["hostname"]))
            for tls in network.get("tls") or []:
                if isinstance(tls, dict) and tls.get("sni"):
                    domains.add(normalize_domain(tls["sni"]))
        if lookups[IND_URL]:
            # Full URLs reconstructed from HTTP traffic (network.http already
            # builds scheme://host[:port]/path in the "uri" field).
            for h in network.get("http") or []:
                if isinstance(h, dict) and h.get("uri"):
                    urls.add(str(h["uri"]).strip())
        domains.discard("")
        urls.discard("")

        indicators = [(ip, IND_IP, sorted(ports)) for ip, ports in ip_ports.items()]
        indicators += [(dom, IND_DOMAIN, None) for dom in domains]
        indicators += [(url, IND_URL, None) for url in urls]
        if lookups[IND_HASH]:
            sha = self._sample_sha256()
            if sha:
                indicators.append((sha, IND_HASH, None))

        if not indicators:
            return {}, []

        tasks = [(p, ind, it, pt) for p in providers for (ind, it, pt) in indicators
                 if p.accepts_indicator(it)]
        if not tasks:
            return {}, []

        log.info("ThreatIntelligence: %d indicator lookup(s) via %s",
                 len(tasks), ", ".join(p.name for p in providers))
        results_list = self._run_tasks(tasks, self._lookup_indicator)

        by_indicator = {}
        for (_p, indicator, _it, _pt), match_dicts in zip(tasks, results_list):
            if match_dicts:
                by_indicator.setdefault(indicator, []).extend(match_dicts)
        for indicator, items in list(by_indicator.items()):
            # Suppress shared/abused-infrastructure over-matches (a single
            # indicator attributed to many families) as likely false tags.
            families = {it.get("malware") or it.get("tag") for it in items}
            if self.max_families_per_indicator and len(families) > self.max_families_per_indicator:
                log.info("ThreatIntelligence: suppressing %s -> %d families "
                         "(likely shared/abused host, not asserting tags)",
                         indicator, len(families))
                del by_indicator[indicator]
                continue
            by_indicator[indicator] = self._dedup_cap(items, self.max_results)

        # Annotate network dicts in-place for the web UI red tags.
        self._annotate_hosts(network, by_indicator)
        self._annotate_domains(network, by_indicator)
        self._annotate_urls(network, by_indicator)

        # Harvest discovered families (Malpedia ids) from the hits, carrying the
        # indicator type so provenance can record WHERE it was seen
        # (threatfox_domain, threatfox_ip_address, ...).
        discovered = []
        for items in by_indicator.values():
            for it in items:
                fam_id = it.get("malware")
                if fam_id:
                    discovered.append((fam_id, it.get("malware_printable"),
                                       it.get("source"), it.get("indicator_type")))
        return by_indicator, discovered

    def _lookup_indicator(self, task):
        provider, indicator, indicator_type, ports = task
        ck = f"{indicator_type}:{indicator}"
        cached = self.cache.get("indicator", provider.name, ck)
        if cached is not None:
            return cached
        try:
            result = provider.lookup(indicator, indicator_type, ports=ports)
            if not result:
                return []
            match_dicts = [m.to_dict() for m in result.matches]
            if result.status in ("ok", "no_match"):
                self.cache.set("indicator", provider.name, ck, match_dicts)
            return match_dicts
        except Exception:
            log.exception("ThreatIntelligence: %s crashed on %s", provider.name, indicator)
            return []

    @staticmethod
    def _dedup_cap(items, max_results):
        best = {}
        for it in items:
            key = f"{it.get('source')}|{it.get('tag')}"
            cur = best.get(key)
            if cur is None or (it.get("confidence_level") or 0) > (cur.get("confidence_level") or 0):
                best[key] = it
        ordered = sorted(best.values(), key=lambda d: (d.get("confidence_level") or 0), reverse=True)
        return ordered[:max_results] if max_results and max_results > 0 else ordered

    def _annotate_hosts(self, network, by_indicator):
        for host in network.get("hosts") or []:
            if isinstance(host, dict):
                hits = by_indicator.get(str(host.get("ip") or "").strip())
                if hits:
                    host["threatintel"] = hits

    def _annotate_domains(self, network, by_indicator):
        for req in network.get("dns") or []:
            if isinstance(req, dict):
                hits = by_indicator.get(normalize_domain(req.get("request")))
                if hits:
                    req["threatintel"] = hits
        for d in network.get("domains") or []:
            if isinstance(d, dict):
                hits = by_indicator.get(normalize_domain(d.get("domain")))
                if hits:
                    d["threatintel"] = hits

    def _annotate_urls(self, network, by_indicator):
        for h in network.get("http") or []:
            if isinstance(h, dict):
                hits = by_indicator.get(str(h.get("uri") or "").strip())
                if hits:
                    h["threatintel"] = hits

    def _sample_sha256(self):
        target = self.results.get("target") or {}
        f = target.get("file") if isinstance(target, dict) else None
        if isinstance(f, dict):
            return f.get("sha256")
        return None

    # ================================================================
    # Family phase
    # ================================================================
    def _gather_family_hints(self, discovered_families):
        """Build de-duplicated family hints from detections + indicator hits.

        Each hint: {"query","is_id","provenance":set}. Dedup key is the
        Malpedia id (when known) or the squashed family name.
        """
        hints = {}

        def hint_key(query, is_id):
            # Key on the squashed family-part so a free-text detection name
            # ("CastleStealer") and a canonical id ("win.castle_stealer")
            # collapse to ONE hint -> one Malpedia lookup. The platform is
            # dropped because names carry none; same-family-part across
            # platforms (rare) intentionally merges.
            base_part = query.split(".", 1)[-1] if is_id else query
            return squash_name(base_part)

        def add(query, is_id, source):
            if not query:
                return
            key = hint_key(query, is_id)
            if not key:
                return
            entry = hints.get(key)
            if entry is None:
                hints[key] = {"query": query.strip(), "is_id": is_id, "provenance": {source}}
            else:
                entry["provenance"].add(source)
                # Prefer a canonical id over a free-text name for the same family.
                if is_id and not entry["is_id"]:
                    entry["query"], entry["is_id"] = query.strip(), True

        # CAPE detections (list of blocks, or a bare string).
        detections = self.results.get("detections")
        if isinstance(detections, str):
            add(detections, False, "cape_detection")
        elif isinstance(detections, list):
            for block in detections:
                if isinstance(block, dict) and block.get("family"):
                    add(block["family"], False, "cape_detection")
                elif isinstance(block, str):
                    add(block, False, "cape_detection")

        # Top-level malfamily hints.
        for key in ("malfamily", "malfamily_tag"):
            val = self.results.get(key)
            if isinstance(val, str) and val:
                add(val, False, "cape_detection")

        # Families surfaced by indicator hits, tagged with WHERE seen, e.g.
        # threatfox_domain / threatfox_ip_address / threatfox_url.
        for fam_id, printable, source, indicator_type in discovered_families:
            prov = self._indicator_provenance(source or "threatfox", indicator_type)
            if looks_like_malpedia_id(fam_id):
                add(fam_id, True, prov)
            elif printable:
                add(printable, False, prov)

        return list(hints.values())

    @staticmethod
    def _indicator_provenance(source, indicator_type):
        label = {IND_IP: "ip_address", IND_DOMAIN: "domain",
                 IND_URL: "url", IND_HASH: "sha256"}.get(indicator_type)
        return f"{source}_{label}" if label else source

    # ThreatFox threat_types considered "C2" (command-and-control). Only these
    # promote when promote_c2_only is set.
    _C2_THREAT_TYPES = {"botnet_cc"}

    def _promote_detections(self, by_indicator, options):
        """Append CAPE detections for indicator hits (never sets malfamily).

        With promote_c2_only (default), only C2 (botnet_cc) hits promote;
        other threat types still enrich the TI card but are not promoted. The
        family is added via add_family_detection, which appends to
        results["detections"] without touching the headline malfamily.
        """
        try:
            from lib.cuckoo.common.utils import add_family_detection
        except Exception:
            log.warning("ThreatIntelligence: add_family_detection unavailable; cannot promote.")
            return []

        c2_only = _as_bool(options.get("promote_c2_only", True))
        min_conf = int(options.get("promote_minimum_confidence", 100) or 0)

        promoted, seen = [], set()
        for indicator, items in by_indicator.items():
            for it in items:
                threat_type = (it.get("threat_type") or "").strip().lower()
                if c2_only and threat_type not in self._C2_THREAT_TYPES:
                    continue
                conf = it.get("confidence_level")
                if min_conf and (conf is None or conf < min_conf):
                    continue
                family = it.get("malware_printable") or it.get("malware")
                if not family:
                    continue
                key = (family, indicator)
                if key in seen:
                    continue
                seen.add(key)
                add_family_detection(
                    self.results, family, "ThreatIntelligence",
                    f"ThreatFox {threat_type or 'indicator'}: {indicator}")
                promoted.append({"family": family, "indicator": indicator,
                                 "threat_type": threat_type, "confidence_level": conf})
        if promoted:
            log.info("ThreatIntelligence: promoted %d indicator hit(s) to detections.", len(promoted))
        return promoted

    def _family_phase(self, providers, hints):
        if not hints:
            return []
        tasks = [(p, h) for p in providers for h in hints]
        log.info("ThreatIntelligence: %d family lookup(s) via %s",
                 len(tasks), ", ".join(p.name for p in providers))
        results_list = self._run_tasks(tasks, self._lookup_family)

        # Keep one card per (family, source) so multiple intel sources for the
        # SAME family (from multiple family providers) coexist and render in one
        # family block. Sorted so same family_id is adjacent for the template's
        # {% regroup %} (then ordered by source within a family).
        cards = {}
        for (_p, hint), card in zip(tasks, results_list):
            if not card:
                continue
            fam_id = card.get("family_id") or card.get("common_name")
            source = card.get("source") or "?"
            key = (fam_id, source)
            prov = set(card.get("provenance") or []) | set(hint["provenance"])
            existing = cards.get(key)
            if existing is None:
                card["provenance"] = sorted(prov)
                cards[key] = card
            else:
                existing["provenance"] = sorted(set(existing["provenance"]) | prov)
        return sorted(
            cards.values(),
            key=lambda c: ((c.get("common_name") or "").lower(), c.get("family_id") or "", c.get("source") or ""),
        )

    def _lookup_family(self, task):
        provider, hint = task
        key = ("id:" + hint["query"].lower()) if hint["is_id"] else ("name:" + squash_name(hint["query"]))
        cached = self.cache.get("family", provider.name, key)
        if cached is not None:
            return cached or None  # {} is a cached miss
        try:
            card = provider.enrich(hint["query"], is_id=hint["is_id"], provenance=hint["provenance"])
            value = card.to_dict() if card else {}
            self.cache.set("family", provider.name, key, value)
            return value or None
        except Exception:
            log.exception("ThreatIntelligence: family provider %s crashed on %s",
                          provider.name, hint["query"])
            return None

    # ================================================================
    # Actor phase  (gated; see run())
    # ================================================================
    def _gather_actor_hints(self, families, options):
        """Build de-duplicated actor hints.

        For now, hints are the actors that the matched malware families are
        attributed to (Malpedia family ``attribution``). This is community-
        sourced, so it is opt-in via ``actor_attribution_from_families`` and
        only ever runs inside the master ``threat actors`` gate. When a
        high-confidence actor provider is registered, its explicit actor
        attributions become additional, preferred hints here.
        """
        hints = {}

        def add(name, source, provenance):
            if not name:
                return
            key = squash_name(name)
            if not key:
                return
            entry = hints.get(key)
            if entry is None:
                hints[key] = {"query": name.strip(), "is_id": False, "provenance": set(provenance or ()) | {source}}
            else:
                entry["provenance"].update(provenance or ())
                entry["provenance"].add(source)

        if _as_bool(options.get("actor_attribution_from_families", True)):
            for fam in families:
                for actor in fam.get("attribution") or []:
                    add(actor, f"family:{fam.get('source')}", fam.get("provenance"))

        return list(hints.values())

    def _actor_phase(self, providers, hints):
        if not hints:
            return []
        tasks = [(p, h) for p in providers for h in hints]
        log.info("ThreatIntelligence: %d actor lookup(s) via %s",
                 len(tasks), ", ".join(p.name for p in providers))
        results_list = self._run_tasks(tasks, self._lookup_actor)

        cards = {}
        for (_p, hint), card in zip(tasks, results_list):
            if not card:
                continue
            actor_id = card.get("actor_id") or card.get("common_name")
            source = card.get("source") or "?"
            key = (actor_id, source)
            prov = set(card.get("provenance") or []) | set(hint["provenance"])
            existing = cards.get(key)
            if existing is None:
                card["provenance"] = sorted(prov)
                cards[key] = card
            else:
                existing["provenance"] = sorted(set(existing["provenance"]) | prov)
        return sorted(
            cards.values(),
            key=lambda c: ((c.get("common_name") or "").lower(), c.get("actor_id") or "", c.get("source") or ""),
        )

    def _lookup_actor(self, task):
        provider, hint = task
        key = ("id:" + hint["query"].lower()) if hint["is_id"] else ("name:" + squash_name(hint["query"]))
        cached = self.cache.get("actor", provider.name, key)
        if cached is not None:
            return cached or None
        try:
            card = provider.enrich(hint["query"], is_id=hint["is_id"], provenance=hint["provenance"])
            value = card.to_dict() if card else {}
            self.cache.set("actor", provider.name, key, value)
            return value or None
        except Exception:
            log.exception("ThreatIntelligence: actor provider %s crashed on %s",
                          provider.name, hint["query"])
            return None

    # ================================================================
    # Shared task runner
    # ================================================================
    def _run_tasks(self, tasks, fn):
        if self.concurrent and len(tasks) > 1 and self.max_workers > 1:
            workers = min(self.max_workers, len(tasks))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="threatintel") as pool:
                return list(pool.map(fn, tasks))
        return [fn(t) for t in tasks]
