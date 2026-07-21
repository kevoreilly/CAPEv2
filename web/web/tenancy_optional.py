"""Import-optional facade for the web-level MT symbols (users.tenancy + the
entitled_scope_filter/entitled_scopes defined in dashboard.views).

Same contract as the lib facade: delegate when the MT layer is importable, fall back to the
MT-disabled-equivalent value when it raises ImportError, FAIL-CLOSED on runtime errors. Re-
exports the lib-level facade symbols so a view needs a single import.
"""
from lib.cuckoo.common.tenancy_optional import (  # noqa: F401
    MTConfig,
    PRIVATE,
    PUBLIC,
    TENANT,
    VISIBILITIES,
    Viewer,
    _mt_enabled,
    default_visibility,
    scope_match,
    viewer_scope_es_filter,
    viewer_scope_match,
)


# viewer_for and multitenancy_config are delegated to users.tenancy (NOT the lib facade):
# the web layer historically imported these from users.tenancy, whose own viewer_for resolves
# multitenancy_config in the users.tenancy namespace. Routing them through the lib module would
# read a different binding (e.g. test fixtures patch users.tenancy.multitenancy_config), silently
# changing scoping. In production both bindings point at the same object; this preserves the
# web layer's exact resolution.
# FAIL-CLOSED contract for every arm below: when the users.tenancy MT layer can't be imported, tell
# 'MT genuinely absent' (single-tenant / upstream -> the MT-disabled-equivalent value: see-all) from
# 'MT enabled but its import chain broke' via _mt_enabled() (pure lib config). In the latter case NEVER
# degrade this -- the sole isolation gate -- to see-all; deny instead. (The lib facade's Viewer docstring
# records this exact ImportError-fail-open class already caused a cross-tenant see-all leak once.)
def viewer_for(user):
    try:
        from users.tenancy import viewer_for as real
    except ImportError:
        if _mt_enabled():
            return Viewer(user_id=0, tenant_id=0, is_tenant_admin=False, is_local_admin=False)
        return Viewer()
    return real(user)


def multitenancy_config():
    try:
        from users.tenancy import multitenancy_config as real
    except ImportError:
        # users.tenancy (web MT layer) absent/broken: fall back to the PURE lib config, not a hardcoded
        # MTConfig(enabled=False) -- claiming MT-off when it's actually enabled would silently see-all
        # every gate below. The lib facade reads lib.cuckoo.common.tenancy (independent import path).
        from lib.cuckoo.common.tenancy_optional import multitenancy_config as _libmt

        return _libmt()
    return real()


def can_view_task(user, task):
    try:
        from users.tenancy import can_view_task as real
    except ImportError:
        return not _mt_enabled()  # MT enabled+broken -> deny; genuinely absent -> allow (single-tenant)
    return real(user, task)


def can_toggle_task(user, task):
    try:
        from users.tenancy import can_toggle_task as real
    except ImportError:
        return not _mt_enabled()
    return real(user, task)


def can_manage_task(user, task):
    try:
        from users.tenancy import can_manage_task as real
    except ImportError:
        return not _mt_enabled()
    return real(user, task)


def can_delete_task(user, task):
    # Irreversible delete gate (stricter than can_manage_task for PUBLIC jobs). Same fail-closed
    # contract: MT genuinely absent -> allow (single-tenant shared box); MT enabled but import broken
    # -> deny (never see-all the sole isolation gate).
    try:
        from users.tenancy import can_delete_task as real
    except ImportError:
        return not _mt_enabled()
    return real(user, task)


def can_set_visibility_task(user, task, new_visibility):
    # Visibility-transition gate (can_toggle + a direction guard so a tenant-admin can't downgrade a
    # non-owned public job into can_delete's tenant branch). Same fail-closed contract: MT genuinely
    # absent -> allow (single-tenant); MT enabled but import broken -> deny.
    try:
        from users.tenancy import can_set_visibility_task as real
    except ImportError:
        return not _mt_enabled()
    return real(user, task, new_visibility)


def can_view_sample(user, *, sha256=None, sha1=None, md5=None, sample_id=None):
    try:
        from users.tenancy import can_view_sample as real
    except ImportError:
        return not _mt_enabled()
    return real(user, sha256=sha256, sha1=sha1, md5=md5, sample_id=sample_id)


def can_ban_user(actor, target_user_id):
    # The ban_user / ban_all_user_tasks VIEWS gate SOLELY on this call (they no longer carry their
    # own is_staff check), so the MT-absent fallback MUST preserve upstream's staff/superuser-only
    # boundary. Returning True would let ANY authenticated user (or anonymous, if WEB_AUTHENTICATION
    # is off) ban/disable accounts on a single-node build.
    try:
        from users.tenancy import can_ban_user as real
    except ImportError:
        return bool(getattr(actor, "is_staff", False) or getattr(actor, "is_superuser", False))
    return real(actor, target_user_id)


def submission_scope(request):
    """Resolve (tenant_id, visibility) for a new submission. The real function returns a
    2-tuple and every caller unpacks it (`_tid, _vis = submission_scope(request)`), so the
    MT-absent fallback must ALSO be a 2-tuple — single-tenant: no tenant, public default."""
    try:
        from users.tenancy import submission_scope as real
    except ImportError:
        # MT enabled+broken -> owner-only PRIVATE (never mint a cross-tenant-visible PUBLIC task);
        # genuinely absent -> upstream single-tenant PUBLIC default.
        return (None, PRIVATE) if _mt_enabled() else (None, PUBLIC)
    return real(request)


def viewer_scope_filter(user):
    """Facade for dashboard.views.entitled_scope_filter (None = see-all)."""
    try:
        from dashboard.views import entitled_scope_filter as real
    except ImportError:
        # None = see-all: safe only when MT is genuinely absent. MT enabled+broken -> a deny-all filter
        # (matches no doc) so the aggregate/search surfaces can't leak cross-tenant.
        return {"_id": {"$in": []}} if _mt_enabled() else None
    return real(user)


def entitled_scopes(user):
    try:
        from dashboard.views import entitled_scopes as real
    except ImportError:
        # ("global",) = see-all scope: safe only when MT is genuinely absent. MT enabled+broken -> no
        # scopes (deny) rather than global.
        return () if _mt_enabled() else ("global",)
    return real(user)
