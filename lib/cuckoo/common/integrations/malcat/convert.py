# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Converters that turn the Malcat bridge's feature output into the shapes
CAPE already renders, so Malcat data drops into the existing UI unchanged.

- capa_to_flare_shape(): converts the bridge's `capa` list into the exact dict
  FLARE capa produces ({CAPABILITY, ATTCK, MBC}), so setting file["flare_capa"]
  to it makes the existing "View CAPA" template render Malcat's results with no
  template change. Malcat's CAPA is faster than FLARE's but may populate fewer
  rows; that's fine - we simply emit fewer.

- normalize_anomalies(): light passthrough/cleanup of the bridge's anomalies
  list (label/category/locations with function+offset) for the Malcat panel.
"""


def _term_id(term):
    """Bridge capa attack/mbc terms are dicts (id/technique/tactic/...) or
    strings. Return an id-ish string for grouping/labels."""
    if isinstance(term, dict):
        return term.get("id") or term.get("technique") or term.get("behavior") or term.get("name") or ""
    return str(term or "")


def _term_label(term):
    """Human label for an attack/mbc term, close to FLARE's 'Technique [ID]'."""
    if isinstance(term, dict):
        name = term.get("technique") or term.get("behavior") or term.get("name") or ""
        sub = term.get("subtechnique") or term.get("method") or ""
        tid = term.get("id") or ""
        if name and tid:
            return f"{name}::{sub} [{tid}]" if sub else f"{name} [{tid}]"
        return name or tid or str(term)
    return str(term)


def _term_group(term, kind):
    """Grouping key: FLARE groups ATT&CK by tactic and MBC by objective."""
    if isinstance(term, dict):
        if kind == "attack":
            return (term.get("tactic") or "UNKNOWN").upper()
        return (term.get("objective") or "UNKNOWN").upper()
    return "UNKNOWN"


def capa_to_flare_shape(capa_list):
    """Convert the bridge's capa feature (a list of capability dicts) into
    FLARE's render dictionary: {CAPABILITY: {ns: [names]}, ATTCK: {tactic:
    [rows]}, MBC: {objective: [rows]}}.

    Each bridge capa entry looks like:
        {"name": str, "namespace": str,
         "attack": [term, ...], "mbc": [term, ...]}
    where term is a dict (id/technique/tactic/...) or a string.
    """
    result = {"CAPABILITY": {}, "ATTCK": {}, "MBC": {}}
    if not capa_list:
        return result

    attck = {}   # tactic -> set of rows
    mbc = {}     # objective -> set of rows

    for cap in capa_list:
        if not isinstance(cap, dict):
            continue
        name = cap.get("name") or "unknown"
        namespace = cap.get("namespace") or "unknown"
        result["CAPABILITY"].setdefault(namespace, [])
        if name not in result["CAPABILITY"][namespace]:
            result["CAPABILITY"][namespace].append(name)

        for term in cap.get("attack") or []:
            group = _term_group(term, "attack")
            attck.setdefault(group, set()).add(_term_label(term))
        for term in cap.get("mbc") or []:
            group = _term_group(term, "mbc")
            mbc.setdefault(group, set()).add(_term_label(term))

    result["ATTCK"] = {k: sorted(v) for k, v in sorted(attck.items())}
    result["MBC"] = {k: sorted(v) for k, v in sorted(mbc.items())}
    return result


def kesakode_to_similarity_rows(kesakode, minimum_similarity=0.0, max_results=0):
    """Turn a bridge kesakode feature dict into the same match-row shape the
    similarity processing module stores in ``code_similarity_matches`` on an
    artifact, so an on-demand lookup renders in the existing Code Similarity row.

    Rows: {family, similarity, sample_sha256(None), engine, low_confidence}.
    Sorted by similarity desc; filtered by minimum_similarity; capped at
    max_results (0 = no cap).
    """
    verdict = (kesakode or {}).get("verdict") or {}
    rows = []
    for family, score in verdict.items():
        if not family:
            continue
        try:
            sim = float(score)
        except (TypeError, ValueError):
            continue
        if minimum_similarity and sim < float(minimum_similarity):
            continue
        rows.append({
            "family": str(family),
            "similarity": sim,
            "sample_sha256": None,
            "engine": "malcat kesakode",
            "low_confidence": False,
        })
    rows.sort(key=lambda r: r["similarity"], reverse=True)
    if max_results and max_results > 0:
        rows = rows[:max_results]
    return rows


def normalize_anomalies(anomalies_list):
    """Return a clean list of anomaly dicts for the Malcat panel. The bridge
    already emits {label, category, locations:[{address, size, function?,
    function_offset?}]}; we pass through defensively."""
    out = []
    for a in anomalies_list or []:
        if not isinstance(a, dict):
            continue
        locs = []
        for loc in a.get("locations") or []:
            if not isinstance(loc, dict):
                continue
            entry = {"address": loc.get("address"), "size": loc.get("size")}
            if loc.get("function"):
                entry["function"] = loc["function"]
            if loc.get("function_offset"):
                entry["function_offset"] = loc["function_offset"]
            locs.append(entry)
        out.append({
            "label": a.get("label") or "Unknown",
            "category": a.get("category") or "unknown",
            "locations": locs,
        })
    return out
