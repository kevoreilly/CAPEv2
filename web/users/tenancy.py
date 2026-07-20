"""Bridge Django request.user -> the pure core predicate (lib.cuckoo.common.tenancy).

The web/apiv2 layers call can_view_task / can_toggle_task; the actual policy lives
in the framework-neutral predicate so the broker can reuse it unchanged.
"""
from lib.cuckoo.common.tenancy import Viewer, Job, can_read, can_toggle, multitenancy_config


def viewer_for(user) -> Viewer:
    """Build a predicate Viewer from a Django user, resolving the operator
    break-glass: when local_admins_manage_all_tenants is on, ANY superuser
    crosses tenants; when off, only IdP-provisioned superusers (those with a
    linked allauth SocialAccount) do — a local createsuperuser does not.
    """
    cfg = multitenancy_config()
    is_super = bool(getattr(user, "is_superuser", False))
    if not cfg.enabled:
        # Multitenancy off => legacy single-tenant behavior for EVERY principal,
        # INCLUDING anonymous (a no-auth public install, or apiv2 with token-auth
        # disabled => DRF AllowAny): see and manage everything, exactly like
        # upstream. is_local_admin short-circuits the predicate and the list
        # filter; existing/legacy tasks are NOT hidden. This MUST run BEFORE the
        # is_authenticated check, or anonymous requests on a disabled install get
        # is_local_admin=False and every can_read/visible_to guard denies the
        # private-default tasks upstream served (back-compat regression).
        return Viewer(user_id=getattr(user, "id", None), tenant_id=None, is_superuser=is_super,
                      is_tenant_admin=False, is_local_admin=True)

    if not getattr(user, "is_authenticated", False):
        # MT enabled: an anonymous request stays public-only (no break-glass).
        return Viewer(user_id=None, tenant_id=None)

    prof = getattr(user, "userprofile", None)
    if not is_super:
        is_local = False
    elif cfg.local_admins_manage_all_tenants:
        is_local = True
    else:
        # flag off -> force admin access through the IdP: only superusers with a
        # SocialAccount (IdP-provisioned) keep cross-tenant reach.
        try:
            is_local = user.socialaccount_set.exists()
        except Exception:
            is_local = False
    tenant_id = getattr(prof, "tenant_id", None)
    is_tenant_admin = bool(getattr(prof, "is_tenant_admin", False))
    # Fail closed for a deactivated tenant: once a Tenant is marked inactive its
    # members must NOT keep tenant-scoped read/submit access until the next SSO
    # login reconciles (reconcile_tenant already filters active=True). Drop the
    # tenant from the viewer if its Tenant row is inactive.
    if tenant_id is not None and prof is not None:
        _t = getattr(prof, "tenant", None)
        if _t is not None and not getattr(_t, "active", True):
            tenant_id = None
            is_tenant_admin = False
    return Viewer(
        user_id=user.id,
        tenant_id=tenant_id,
        is_superuser=is_super,
        is_tenant_admin=is_tenant_admin,
        is_local_admin=is_local,
    )


def _job_for(task) -> Job:
    return Job(
        owner_id=getattr(task, "user_id", None),
        tenant_id=getattr(task, "tenant_id", None),
        visibility=getattr(task, "visibility", "private"),
    )


def can_view_task(user, task) -> bool:
    return can_read(viewer_for(user), _job_for(task))


def can_toggle_task(user, task) -> bool:
    return can_toggle(viewer_for(user), _job_for(task))


def can_manage_task(user, task) -> bool:
    """Authorize a mutation (delete/reschedule/reprocess/comment/remove) on a
    task. Same policy as toggling visibility: owner, tenant-admin for the
    tenant's public/tenant jobs, or break-glass superuser — never another
    member's private job."""
    return can_toggle(viewer_for(user), _job_for(task))


def can_view_sample(user, *, sha256=None, sha1=None, md5=None, sample_id=None) -> bool:
    """True iff `user` may access a content-addressed sample identified by
    hash/id — i.e. has >=1 VISIBLE task referencing it. Samples are shared across
    tenants by sha256, so access follows the union of the viewer's visible tasks
    (the same intended boundary apiv2 _deny_by_hash enforces).

    No-op (returns True) when multitenancy is disabled or for a break-glass admin
    (viewer_for -> is_local_admin). THE single source of truth for every by-hash
    surface (apiv2 _deny_by_hash, web file() sample/static, submission resubmit /
    download-services) so they cannot drift apart.
    """
    viewer = viewer_for(user)
    if viewer.is_local_admin:
        return True
    from lib.cuckoo.core.database import Database

    db = Database()
    if sample_id is not None:
        sample = db.view_sample(sample_id)
    elif sha256 or sha1 or md5:
        sample = db.find_sample(sha256=sha256, sha1=sha1, md5=md5)
    else:
        sample = None
    if sample is None:
        return False
    return bool(db.list_tasks(sample_id=sample.id, visible_to=viewer, limit=1))


def can_ban_user(actor, target_user_id) -> bool:
    """Authorize banning target_user_id: deactivating the account (+ revoking API keys) and banning all
    their tasks. Mirrors can_manage_task at USER granularity -- a break-glass local/IdP admin bans anyone;
    a tenant admin bans only members of their OWN tenant; nobody else (a plain member or a non-admin
    is_staff operator cannot reach across tenants). MT-disabled installs never call this: viewer_for makes
    every principal a break-glass local-admin, and the tenancy_optional facade's MT-absent fallback keeps
    the upstream staff/superuser-only boundary -- so this preserves single-node behaviour.

    Fails closed (deny) on any resolution error rather than defaulting to allow."""
    viewer = viewer_for(actor)
    if viewer.is_local_admin:
        return True
    if not viewer.is_tenant_admin or viewer.tenant_id is None:
        return False
    from django.contrib.auth.models import User

    try:
        prof = User.objects.select_related("userprofile").get(id=int(target_user_id)).userprofile
        target_tenant = getattr(prof, "tenant_id", None)
    except Exception:
        return False
    return target_tenant is not None and target_tenant == viewer.tenant_id


def submission_scope(request):
    """Resolve (tenant_id, visibility) for a new submission from the request.

    Tenant comes from the submitting user; visibility is the explicit
    ``visibility`` param when valid, else the per-mode default. Raises
    ValueError on an invalid explicit visibility so the view can 400.
    """
    from lib.cuckoo.common.tenancy import default_visibility, VISIBILITIES, TENANT, PRIVATE, PUBLIC

    # Multitenancy OFF (default/legacy): visibility is meaningless (every principal is
    # a break-glass local-admin). IGNORE any caller-supplied value and return the
    # legacy (no tenant, public) scope. Persisting private/tenant here would plant a
    # backfill landmine (the migration skips already-stamped docs, so those rows would
    # unexpectedly hide analyses when MT is later enabled) and contradict the
    # visibility-toggle endpoint's disabled-MT guard. Use the MODULE-LEVEL
    # multitenancy_config (the same binding viewer_for uses and the test fixtures
    # patch) — an in-function re-import from the core module would bypass those.
    cfg = multitenancy_config()
    if not cfg.enabled:
        return None, PUBLIC

    v = viewer_for(request.user)
    data = getattr(request, "data", None)
    if data is None:
        data = getattr(request, "POST", None) or {}
    requested = data.get("visibility") if hasattr(data, "get") else None
    if requested:
        if requested not in VISIBILITIES:
            raise ValueError("invalid visibility")
        visibility = requested
    else:
        visibility = default_visibility(cfg)
    # A 'tenant'-visibility job needs a tenant to scope to. With tenant_id=None it
    # is readable only by its owner (or nobody, for an anonymous submitter) — never
    # the intended tenant pool (can_read's _same_tenant requires a non-None tenant).
    # Refuse an explicit request (the caller turns ValueError into a 400) and
    # downgrade a per-mode default to PRIVATE: the owner still reads via _is_owner,
    # and it fails closed rather than world-exposing an anon job in locked mode.
    if visibility == TENANT and v.tenant_id is None:
        if requested:
            raise ValueError("tenant visibility requires tenant membership")
        visibility = PRIVATE
    return v.tenant_id, visibility
