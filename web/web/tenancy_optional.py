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
def viewer_for(user):
    try:
        from users.tenancy import viewer_for as real
    except ImportError:
        return Viewer()
    return real(user)


def multitenancy_config():
    try:
        from users.tenancy import multitenancy_config as real
    except ImportError:
        return MTConfig()
    return real()


def can_view_task(user, task):
    try:
        from users.tenancy import can_view_task as real
    except ImportError:
        return True
    return real(user, task)


def can_toggle_task(user, task):
    try:
        from users.tenancy import can_toggle_task as real
    except ImportError:
        return True
    return real(user, task)


def can_manage_task(user, task):
    try:
        from users.tenancy import can_manage_task as real
    except ImportError:
        return True
    return real(user, task)


def can_view_sample(user, *, sha256=None, sha1=None, md5=None, sample_id=None):
    try:
        from users.tenancy import can_view_sample as real
    except ImportError:
        return True
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
        return (None, PUBLIC)
    return real(request)


def viewer_scope_filter(user):
    """Facade for dashboard.views.entitled_scope_filter (None = see-all)."""
    try:
        from dashboard.views import entitled_scope_filter as real
    except ImportError:
        return None
    return real(user)


def entitled_scopes(user):
    try:
        from dashboard.views import entitled_scopes as real
    except ImportError:
        return ("global",)
    return real(user)
