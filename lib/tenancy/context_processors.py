"""Django template context processor for `lib.tenancy`."""

from typing import Any, Dict

from lib.tenancy.middleware import default_viewer_resolver
from lib.tenancy.policy import VISIBILITIES, multitenancy_config
from lib.tenancy.resources import resolve_user_entitlements


def tenancy_context(request: Any) -> Dict[str, Any]:
    """Provide `tenancy_enabled`, `tenancy_viewer`, `tenancy_entitlements`, and `visibility_choices` to templates."""
    cfg = multitenancy_config()
    user = getattr(request, "user", None)
    viewer = getattr(request, "viewer", None)
    if viewer is None:
        viewer = default_viewer_resolver(user)
    entitlements = getattr(request, "entitlements", None)
    if entitlements is None:
        entitlements = resolve_user_entitlements(user)
    return {
        "tenancy_enabled": bool(cfg.enabled),
        "tenancy_viewer": viewer,
        "tenancy_entitlements": entitlements,
        "allow_all_vms": bool(entitlements.allow_all_vms),
        "allow_route_none": bool(entitlements.can_use_route("none")),
        "visibility_choices": list(VISIBILITIES),
    }
