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

import logging

log = logging.getLogger(__name__)

_client = None


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
    client = _get_client()
    if client is None:
        return {}
    try:
        with open(file_path, "rb") as fh:
            data = fh.read()
    except OSError as err:
        log.debug("Malcat CAPA: cannot read %s: %s", file_path, err)
        return {}
    if not data:
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
