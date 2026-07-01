# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2024 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Provider registry for the threat-intelligence framework.

Two kinds of provider live here:
  * indicator providers — ip/domain/sha256 -> context (ThreatFox, ...)
  * family providers    — malware family   -> card    (Malpedia, ...)

Provider modules are imported LAZILY so a missing/broken optional
dependency cannot crash CAPE's plugin loader when a provider is disabled.

Adding a provider:
  1. Implement the subclass (lazy-import deps inside available()/lookup()).
  2. Add it to _INDICATOR_MODULES or _FAMILY_MODULES below.
  3. Add "<name> = yes/no" (+ "<name>_*" settings) to the
     [threatintelligence] section of integrations.conf.
"""

import importlib
import logging
from typing import Dict, List

from lib.cuckoo.common.integrations.threatintelligence.base import (
    ActorProvider, FamilyProvider, IndicatorProvider, _as_bool,
)

log = logging.getLogger(__name__)

# Register additional indicator providers here, e.g.:
#   "<name>": "lib.cuckoo.common.integrations.threatintelligence.<module>.<Class>",
_INDICATOR_MODULES: Dict[str, str] = {
    "threatfox": "lib.cuckoo.common.integrations.threatintelligence.threatfox_provider.ThreatFoxProvider",
}

# Register additional family providers here (same dotted-path pattern).
_FAMILY_MODULES: Dict[str, str] = {
    "malpedia": "lib.cuckoo.common.integrations.threatintelligence.malpedia_provider.MalpediaProvider",
}

# Threat-actor engines. Enabled by "<name>_actors = yes" AND the master
# "threat actors = yes" gate. Actor attribution must be high confidence, so
# the Malpedia reference engine is OFF by default (community/MISP sourced).
# Register a high-confidence actor provider here using the same pattern.
_ACTOR_MODULES: Dict[str, str] = {
    "malpedia_actors": "lib.cuckoo.common.integrations.threatintelligence.malpedia_actor_provider.MalpediaActorProvider",
}


def _load(dotted: str):
    module_path, class_name = dotted.rsplit(".", 1)
    return getattr(importlib.import_module(module_path), class_name)


def _enabled(modules: Dict[str, str], options: Dict):
    out = []
    for name, dotted in modules.items():
        if not _as_bool(options.get(name, False)):
            continue
        try:
            provider = _load(dotted)(options)
        except Exception as err:
            log.warning("Threat-intel provider '%s' failed to load: %s", name, err)
            continue
        if not provider.available():
            log.warning("Threat-intel provider '%s' enabled but unavailable; skipping.", name)
            continue
        out.append(provider)
    return out


def get_enabled_indicator_providers(options: Dict) -> List[IndicatorProvider]:
    return _enabled(_INDICATOR_MODULES, options)


def get_enabled_family_providers(options: Dict) -> List[FamilyProvider]:
    return _enabled(_FAMILY_MODULES, options)


def get_enabled_actor_providers(options: Dict) -> List[ActorProvider]:
    return _enabled(_ACTOR_MODULES, options)
