# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Engine registry and dispatcher.

Engine modules are imported LAZILY inside get_enabled_engines() so that a
missing or broken optional dependency in any engine cannot crash CAPE's
plugin loader when the engine is disabled or its package is absent.

Adding a new engine (e.g. binlex, Malcat, Intezer):
  1. Implement a SimilarityEngine subclass in <name>_engine.py
     (lazy-import any external deps inside available()).
  2. Add an entry to _ENGINE_MODULES below.
  3. Add "<name> = yes/no" to integrations.conf [similarity] section.
  Nothing else needs changing. Engines run independently, so you can have
  one, several, or all enabled at once; matches merge per artifact and are
  tagged with the engine name.
"""

import importlib
import logging
from typing import Dict, List

from lib.cuckoo.common.integrations.similarity.base import SimilarityEngine, _as_bool

log = logging.getLogger(__name__)

# Map of config key -> dotted "module.ClassName" path.
# Only engines listed here are ever instantiated. Additional engines (binlex,
# Malcat, Intezer, ...) slot in by adding a line here plus a config toggle —
# the dispatcher, result merging and UI need no changes.
_ENGINE_MODULES: Dict[str, str] = {
    "mcrit": "lib.cuckoo.common.integrations.similarity.mcrit_engine.McritEngine",
    # "binlex": "lib.cuckoo.common.integrations.similarity.binlex_engine.BinlexEngine",
}


def _load_engine_class(dotted: str):
    module_path, class_name = dotted.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def get_enabled_engines(options: Dict) -> List[SimilarityEngine]:
    """Return initialized, available engines whose config key is 'yes'."""
    engines: List[SimilarityEngine] = []
    for engine_name, dotted_path in _ENGINE_MODULES.items():
        if not _as_bool(options.get(engine_name, False)):
            continue
        try:
            cls = _load_engine_class(dotted_path)
            engine = cls(options)
        except Exception as err:
            log.warning("Similarity engine '%s' failed to load: %s", engine_name, err)
            continue
        if not engine.available():
            log.warning("Similarity engine '%s' is enabled but unavailable; skipping.", engine_name)
            continue
        engines.append(engine)
    return engines
