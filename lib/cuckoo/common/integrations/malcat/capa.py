# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Malcat CAPA via the Malcat bridge.

Drop-in alternative to FLARE capa: malcat_capa_details() has the same call shape
as capa.flare_capa_details() and returns the SAME render dictionary
({CAPABILITY, ATTCK, MBC}), so callers store it under the existing "flare_capa"
key and the existing "View CAPA" template renders it unchanged. Malcat's CAPA is
significantly faster than FLARE's; it may populate fewer rows in some sections.

Enabled by [flare_capa] malcat_capa = yes in integrations.conf (needs the Malcat
bridge, configured under [malcat]). Any failure returns {} so CAPA never breaks
processing - identical to FLARE's own failure behaviour.
"""

import hashlib
import logging
import threading
from collections import OrderedDict

log = logging.getLogger(__name__)

_client = None
_CACHE_LOCK = threading.Lock()
_CAPA_PREFETCH_CACHE: "OrderedDict[str, dict]" = OrderedDict()
_MAX_PREFETCH_ENTRIES = 32


def _cache_put_capa(sha256: str, shaped: dict) -> None:
    with _CACHE_LOCK:
        _CAPA_PREFETCH_CACHE[sha256] = shaped
        _CAPA_PREFETCH_CACHE.move_to_end(sha256)
        while len(_CAPA_PREFETCH_CACHE) > _MAX_PREFETCH_ENTRIES:
            _CAPA_PREFETCH_CACHE.popitem(last=False)


def _should_prefetch_capa(integ, cat_norm: str, _as_bool) -> bool:
    """Return True if [flare_capa] will request malcat_capa for this category
    later in CAPE.process_file, so malcat_details can piggyback 'capa' onto the
    same bridge call and avoid a second upload + full re-analysis."""
    try:
        fcfg = dict(integ.get("flare_capa"))
    except Exception:
        return False
    if not _as_bool(fcfg.get("enabled", False)) or not _as_bool(fcfg.get("malcat_capa", False)):
        return False
    if _as_bool(fcfg.get("on_demand", False)):
        return False
    capa_cat = "cape" if cat_norm in ("cape", "payload") else ("procdump" if cat_norm == "procdump" else "static")
    return _as_bool(fcfg.get(capa_cat, False))


def _get_client():
    """Build (once) a MalcatClient from the [malcat] config, falling back to the
    [similarity] kesakode_* bridge settings when [malcat] leaves them blank."""
    global _client
    if _client is not None:
        return _client
    try:
        from lib.cuckoo.common.config import Config
        from lib.cuckoo.common.integrations.malcat.client import MalcatClient
        from lib.cuckoo.common.integrations.similarity.base import _as_bool

        integ = Config("integrations")
        mcfg = dict(integ.get("malcat"))
        try:
            scfg = dict(integ.get("similarity"))
        except Exception:
            scfg = {}

        host = mcfg.get("malcat_host") or scfg.get("kesakode_host") or "http://127.0.0.1:8090"
        api_key = mcfg.get("malcat_apikey") or scfg.get("kesakode_apikey") or ""
        ssl_verify = _as_bool(
            mcfg.get("malcat_ssl_verify", scfg.get("kesakode_ssl_verify", True))
        )
        timeout = int(mcfg.get("timeout", 120) or 120)
        _client = MalcatClient(host=host, api_key=api_key, ssl_verify=ssl_verify, timeout=timeout)
    except Exception as err:
        log.warning("Malcat CAPA: could not build bridge client: %s", err)
        _client = None
    return _client


def malcat_capa_details(file_path, category=False, on_demand=False, results=None, **kwargs):
    """Return FLARE-shaped capa dict for file_path via the Malcat bridge, or {}.

    Signature is intentionally compatible with capa.flare_capa_details so it can
    be swapped in at the same call sites. `category`/`on_demand`/`results` are
    accepted and ignored (the bridge analyses whatever file it is given).
    """
    try:
        with open(file_path, "rb") as fh:
            data = fh.read()
    except OSError as err:
        log.debug("Malcat CAPA: cannot read %s: %s", file_path, err)
        return {}
    if not data:
        return {}

    sha256 = hashlib.sha256(data).hexdigest()
    with _CACHE_LOCK:
        prefetched = _CAPA_PREFETCH_CACHE.pop(sha256, None)
    if prefetched is not None:
        return prefetched if prefetched.get("CAPABILITY") else {}

    client = _get_client()
    if client is None:
        return {}

    try:
        from lib.cuckoo.common.integrations.malcat.convert import capa_to_flare_shape

        payload = client.analyze(data=data, features=["capa"])
    except Exception as err:
        # MalcatBridgeError or anything else -> behave like FLARE on failure.
        log.warning("Malcat CAPA failed for %s: %s", file_path, err)
        return {}

    capa_list = (payload.get("features") or {}).get("capa") or []
    if not capa_list:
        return {}
    shaped = capa_to_flare_shape(capa_list)
    # Only return non-empty if we actually have capabilities.
    if shaped.get("CAPABILITY"):
        return shaped
    return {}


_CATEGORY_TO_SOURCE_KEY = {
    "cape": "malcat_payloads",
    "payload": "malcat_payloads",
    "procdump": "malcat_procdump",
    "dropped": "malcat_dropped",
    "package": "malcat_dropped",
    "files": "malcat_dropped",
    "static": "malcat_submittedfile",
    "file": "malcat_submittedfile",
    "submitted": "malcat_submittedfile",
}

_CATEGORY_DEFAULTS = {
    "malcat_payloads": True,
    "malcat_procdump": True,
    "malcat_dropped": False,
    "malcat_submittedfile": False,
}


def malcat_details(file_path, category="static", file_type=""):
    """Return static Malcat intel (anomalies) for ``file_path`` when enabled in
    ``integrations.conf [malcat]`` for ``category``, or ``{}``."""
    try:
        from lib.cuckoo.common.config import Config
        from lib.cuckoo.common.integrations.malcat.convert import capa_to_flare_shape, normalize_anomalies
        from lib.cuckoo.common.integrations.similarity.base import (
            FMT_UNKNOWN,
            _as_bool,
            detect_format,
        )

        integ = Config("integrations")
        mcfg = dict(integ.get("malcat"))
    except Exception as err:
        log.debug("Malcat: could not read [malcat] config (%s); skipping.", err)
        return {}

    if not _as_bool(mcfg.get("enabled", False)):
        return {}

    cat_norm = (str(category or "static")).strip().lower()
    source_key = _CATEGORY_TO_SOURCE_KEY.get(cat_norm, "malcat_submittedfile")
    default_enabled = _CATEGORY_DEFAULTS.get(source_key, False)
    if not _as_bool(mcfg.get(source_key, mcfg.get(cat_norm, default_enabled))):
        return {}

    features = []
    if _as_bool(mcfg.get("anomalies", True)):
        features.append("anomalies")
    if not features:
        return {}

    try:
        with open(file_path, "rb") as fh:
            data = fh.read()
    except OSError as err:
        log.debug("Malcat: cannot read %s: %s", file_path, err)
        return {}
    if not data:
        return {}

    if detect_format(file_type, data[:4]) == FMT_UNKNOWN:
        return {}

    client = _get_client()
    if client is None:
        return {}

    prefetch_capa = _should_prefetch_capa(integ, cat_norm, _as_bool)
    if prefetch_capa and "capa" not in features:
        features.append("capa")

    try:
        payload = client.analyze(data=data, features=features)
    except Exception as err:
        log.warning("Malcat static analysis failed for %s: %s", file_path, err)
        return {}

    feats = payload.get("features") or {}
    if prefetch_capa:
        sha256 = hashlib.sha256(data).hexdigest()
        _cache_put_capa(sha256, capa_to_flare_shape(feats.get("capa") or []))
    block = {}
    if "anomalies" in features:
        anomalies = normalize_anomalies(feats.get("anomalies") or [])
        if anomalies:
            block["anomalies"] = anomalies
    return block

