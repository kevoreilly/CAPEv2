# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Shared helpers for normalizing, resolving, and classifying task network routes."""

from typing import Any, Optional

NO_ROUTE_VALUES = frozenset({"none", "drop", "false"})


def normalize_task_route(route: Any) -> Optional[str]:
    """Normalize a requested or stored task route.

    Unset, empty, whitespace-only, and boolean ``False`` values normalize to
    ``None`` (meaning "defer to ``routing.conf``"). Explicit strings such as
    ``"none"`` or ``"drop"`` are preserved trimmed so callers can override a
    non-empty default route in ``routing.conf``.
    """
    if route is None or route is False:
        return None
    if isinstance(route, str):
        cleaned = route.strip()
        return cleaned or None
    cleaned = str(route).strip()
    return cleaned or None


def resolve_task_route(task_route: Any, routing_conf: Any = None) -> str:
    """Return the effective route string for a task, falling back to ``routing.conf``."""
    route = normalize_task_route(task_route)
    if route is None:
        if routing_conf is None:
            from lib.cuckoo.common.config import Config

            routing_conf = Config("routing")
        routing_section = getattr(routing_conf, "routing", None)
        route = normalize_task_route(getattr(routing_section, "route", None))
    return route or "none"


def resolve_auxiliary_route(aux_route: Any, task: Any = None, routing_conf: Any = None) -> str:
    """Return the effective route for an auxiliary module.

    Prefers a non-empty runtime route propagated from ``AnalysisManager``,
    falling back to ``task.route`` and then ``routing.conf``.
    """
    raw_route = normalize_task_route(aux_route)
    if raw_route is None:
        raw_route = getattr(task, "route", None)
    return resolve_task_route(raw_route, routing_conf)


def is_no_route(route: Any) -> bool:
    """Return True when ``route`` represents no outbound network routing."""
    normalized = normalize_task_route(route)
    return normalized is None or normalized.lower() in NO_ROUTE_VALUES
