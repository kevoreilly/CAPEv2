"""Import-optional facade for the lib-level MT symbols (lib.cuckoo.common.tenancy).

Delegates to the real MT module when it's importable; when it ISN'T (the MT layer is not
deployed — e.g. an upstream central-only build), returns values IDENTICAL to the MT-disabled
code path (which the real functions already implement: viewer_for -> is_local_admin=True ->
every can_* gate True; scope_match -> None). FAIL-CLOSED: catch ImportError ONLY; a runtime
error from a deployed MT layer propagates rather than silently degrading to see-all.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Viewer:
    """FALLBACK viewer, returned by viewer_for() ONLY when the MT layer is absent — see-all
    (is_local_admin=True). When MT IS deployed, viewer_for() returns the REAL
    lib.cuckoo.common.tenancy.Viewer, a DIFFERENT class. So do NOT
    `isinstance(viewer_for(u), Viewer)` against this type — it's False in production. Treat
    viewer_for()'s result structurally (.is_local_admin / .tenant_id), never by type."""
    user_id: int = 0
    tenant_id: int = 0
    is_tenant_admin: bool = False
    is_local_admin: bool = True


@dataclass(frozen=True)
class MTConfig:
    """FALLBACK config, returned by multitenancy_config() ONLY when the MT layer is absent.
    When MT is deployed the REAL lib.cuckoo.common.tenancy.MTConfig (a different class) is
    returned — don't isinstance-check against this; read .enabled / .mode structurally."""
    enabled: bool = False
    mode: str = "shared"
    default_visibility: str = ""
    local_admins_manage_all_tenants: bool = True


def multitenancy_config():
    try:
        from lib.cuckoo.common.tenancy import multitenancy_config as real
    except ImportError:
        return MTConfig()
    return real()


def viewer_for(user):
    # viewer_for lives in the web `users` MT app (needs the Django ORM), NOT the pure predicate
    # lib.cuckoo.common.tenancy -- importing it from there always ImportError'd -> the facade
    # silently degraded to see-all even when MT WAS deployed (cross-tenant leak). Resolve it from
    # users.tenancy (present => real viewer; absent/non-Django => fall back to see-all).
    try:
        from users.tenancy import viewer_for as real
    except ImportError:
        return Viewer()
    return real(user)


def scope_match(scope, viewer):
    try:
        from lib.cuckoo.common.tenancy import scope_match as real
    except ImportError:
        return None
    return real(scope, viewer)


# Visibility constants — stable contract values. Present -> the real module's values;
# absent -> the same literals so callers comparing/storing visibility still work.
try:
    from lib.cuckoo.common.tenancy import PUBLIC, PRIVATE, TENANT, VISIBILITIES  # noqa: F401
except ImportError:
    PUBLIC, TENANT, PRIVATE = "public", "tenant", "private"
    VISIBILITIES = (PUBLIC, TENANT, PRIVATE)


def default_visibility(cfg):
    """Submit-time default visibility for the configured mode (see-all path -> PUBLIC)."""
    try:
        from lib.cuckoo.common.tenancy import default_visibility as real
    except ImportError:
        if getattr(cfg, "default_visibility", "") in VISIBILITIES:
            return cfg.default_visibility
        return PUBLIC if getattr(cfg, "mode", "shared") == "shared" else TENANT
    return real(cfg)


def viewer_scope_match(viewer):
    """Mongo $match restricting a query to the viewer's entitled scopes, or None (no
    filter / see-all) when MT is disabled or the layer is absent."""
    try:
        from lib.cuckoo.common.tenancy import viewer_scope_match as real
    except ImportError:
        return None
    return real(viewer)


def viewer_scope_es_filter(viewer):
    """Elasticsearch bool-filter analogue of viewer_scope_match, or None (see-all)."""
    try:
        from lib.cuckoo.common.tenancy import viewer_scope_es_filter as real
    except ImportError:
        return None
    return real(viewer)
