# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Loader for conf/threat_intel.conf.

The file is laid out as one global section plus one section per engine:

    [threatintelligence]   global behaviour (timeouts, cache, gates, ...)
    [threatfox]            engine, "enabled" + engine-local keys
    [malpedia]             engine, "enabled" + engine-local keys

Engine sections INHERIT the global section: an engine is handed
``globals | its own section``, so it only needs to declare what differs and
still sees shared settings such as ``timeout``. Because engine keys are
section-scoped they are unprefixed (``api_key``, not ``threatfox_api``),
which is what lets new engines be added without the flat namespace growing.

Section names come from the registry, so adding an engine is a section here
plus a line in registry.py -- nothing else needs to know about it.
"""

import logging
from typing import Dict, Iterable, Optional

log = logging.getLogger(__name__)

CONFIG_NAME = "threat_intel"
GLOBAL_SECTION = "threatintelligence"


class TIConfig:
    """Global options plus per-engine sections, with inheritance."""

    def __init__(self, global_options: Optional[Dict] = None, sections: Optional[Dict] = None):
        self.globals: Dict = dict(global_options or {})
        self.sections: Dict[str, Dict] = dict(sections or {})

    def section(self, name: str) -> Dict:
        """Raw options for one engine section (empty when absent)."""
        return dict(self.sections.get(name) or {})

    def provider_options(self, name: str) -> Dict:
        """Options handed to an engine: globals overlaid with its section."""
        merged = dict(self.globals)
        merged.update(self.section(name))
        return merged

    def is_enabled(self, name: str) -> bool:
        from lib.cuckoo.common.integrations.threatintelligence.base import _as_bool

        return _as_bool(self.section(name).get("enabled", False))


def _read_section(cfg, name: str) -> Dict:
    """Read one section, tolerating its absence.

    CAPE's Config.get() raises when a section is missing, which is expected
    here: an operator may simply not have a section for an engine they do not
    use, and that must degrade to "disabled", never to a processing failure.
    """
    try:
        return dict(cfg.get(name) or {})
    except Exception:
        return {}


def load_config(section_names: Iterable[str] = ()) -> TIConfig:
    """Load conf/threat_intel.conf into a TIConfig.

    Resolution is CAPE's standard chain for this file name:
    conf/default/threat_intel.conf.default -> conf/threat_intel.conf ->
    conf/threat_intel.conf.d/*.conf -> custom conf dir.
    """
    from lib.cuckoo.common.config import Config

    cfg = Config(CONFIG_NAME)
    globals_ = _read_section(cfg, GLOBAL_SECTION)
    sections = {name: _read_section(cfg, name) for name in section_names}
    return TIConfig(globals_, sections)
