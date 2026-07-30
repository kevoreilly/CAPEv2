# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Provider registry for the threat-intelligence framework.

Two kinds of provider live here:
  * indicator providers — ip/domain/sha256 -> context (ThreatFox, ...)
  * family providers    — malware family   -> card    (Malpedia, ...)

Provider modules are imported LAZILY so a missing/broken optional
dependency cannot crash CAPE's plugin loader when a provider is disabled.

Each provider owns a same-named SECTION in conf/threat_intel.conf, holding
"enabled" plus its engine-local keys; the global [threatintelligence] section
is inherited underneath it.

Adding a provider:
  1. Implement the subclass (lazy-import deps inside available()/lookup()).
  2. Add it to _INDICATOR_MODULES / _FAMILY_MODULES / _ACTOR_MODULES below.
  3. Add a "[<name>]" section (with "enabled") to conf/threat_intel.conf.
Nothing else needs to change: the section name is taken from the registry.
"""

import importlib
import logging
from typing import Dict, List

from lib.cuckoo.common.integrations.threatintelligence.base import (
    ActorProvider, FamilyProvider, IndicatorProvider,
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


def all_provider_names() -> List[str]:
    """Every registered engine name = every engine section in threat_intel.conf."""
    return list(_INDICATOR_MODULES) + list(_FAMILY_MODULES) + list(_ACTOR_MODULES)


def _enabled(modules: Dict[str, str], config):
    """Instantiate the enabled engines from `modules`.

    `config` is a TIConfig: each engine is enabled by "enabled" in its own
    section and receives globals overlaid with that section.
    """
    out = []
    for name, dotted in modules.items():
        if not config.is_enabled(name):
            continue
        try:
            provider = _load(dotted)(config.provider_options(name))
        except Exception as err:
            log.warning("Threat-intel provider '%s' failed to load: %s", name, err)
            continue
        if not provider.available():
            log.warning("Threat-intel provider '%s' enabled but unavailable; skipping.", name)
            continue
        out.append(provider)
    return out


def get_enabled_indicator_providers(config) -> List[IndicatorProvider]:
    return _enabled(_INDICATOR_MODULES, config)


def get_enabled_family_providers(config) -> List[FamilyProvider]:
    return _enabled(_FAMILY_MODULES, config)


def get_enabled_actor_providers(config) -> List[ActorProvider]:
    return _enabled(_ACTOR_MODULES, config)
