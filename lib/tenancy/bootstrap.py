"""Single entry point CAPE processes use to activate `lib.tenancy`.

Core call sites (web settings, the scheduler, dist) call `bootstrap_tenancy()` instead of
each re-implementing the enablement check and error handling. Kept free of heavy imports so
a disabled deployment never imports the package.
"""

from __future__ import annotations

import logging
from typing import Any, MutableMapping, Optional

log = logging.getLogger(__name__)


def _section_enabled(cfg: Any, name: str) -> bool:
    section = getattr(cfg, name, None) or {}
    try:
        return bool(section.get("enabled", False))
    except AttributeError:
        return bool(getattr(section, "enabled", False))


def bootstrap_tenancy(cfg: Any, settings_globals: Optional[MutableMapping[str, Any]] = None) -> bool:
    """Activate tenancy hooks (and, given Django settings globals, the web integration).

    Returns True when activated. When `[multitenancy]` is enabled a failure raises: serving
    with isolation silently off is worse than not starting. Object storage alone (including the
    legacy `[central_mode]` section) keeps the log-and-continue behaviour.
    """
    multitenancy = _section_enabled(cfg, "multitenancy")
    storage = _section_enabled(cfg, "object_storage") or _section_enabled(cfg, "central_mode")
    if not (multitenancy or storage):
        return False
    try:
        if settings_globals is not None:
            import lib.tenancy

            lib.tenancy.install(settings_globals)
        else:
            from lib.tenancy.hooks import register_core_hooks

            register_core_hooks()
    except Exception as e:
        if multitenancy:
            raise RuntimeError(f"[multitenancy] is enabled but lib.tenancy failed to initialize: {e}") from e
        log.exception("Failed to initialize lib.tenancy: %s", e)
        return False
    return True
