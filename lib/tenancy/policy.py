"""Pure, dependency-free job-visibility predicate — the single source of truth
for who may read/manage a task. Imported by the Django web layer, the apiv2
views, the SQLAlchemy task store, and (separately) validated by the broker.
No Django, no SQLAlchemy imports here — only plain dataclasses so it stays a
pure function set testable against tests/tenancy_vectors.py.
"""

import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

PUBLIC, TENANT, PRIVATE = "public", "tenant", "private"
VISIBILITIES = (PUBLIC, TENANT, PRIVATE)

MINE, GLOBAL = "mine", "global"
SCOPES = (PUBLIC, TENANT, MINE, GLOBAL)


@dataclass(frozen=True)
class Viewer:
    user_id: Optional[int]
    tenant_id: Optional[int]
    is_superuser: bool = False
    is_tenant_admin: bool = False
    is_local_admin: bool = False  # superuser AND cuckoo.conf break-glass flag on
    is_authenticated: bool = True
    tenant_ids: tuple[int, ...] = ()
    admin_tenant_ids: tuple[int, ...] = ()

    @property
    def effective_tenant_ids(self) -> tuple[int, ...]:
        """All tenant/group IDs this viewer belongs to (supports multi-group users)."""
        if self.tenant_ids:
            if self.tenant_id is not None and self.tenant_id not in self.tenant_ids:
                return (self.tenant_id, *self.tenant_ids)
            return self.tenant_ids
        if self.tenant_id is not None:
            return (self.tenant_id,)
        return ()

    @property
    def effective_admin_tenant_ids(self) -> tuple[int, ...]:
        """Tenant/group IDs where this viewer holds group/tenant admin privileges."""
        if self.admin_tenant_ids:
            return self.admin_tenant_ids
        if self.is_tenant_admin:
            return self.effective_tenant_ids
        return ()

    @property
    def see_all(self) -> bool:
        return bool(self.is_local_admin)

    @classmethod
    def anonymous(cls) -> "Viewer":
        return cls(
            user_id=None,
            tenant_id=None,
            is_superuser=False,
            is_tenant_admin=False,
            is_local_admin=False,
            is_authenticated=False,
            tenant_ids=(),
            admin_tenant_ids=(),
        )


@dataclass(frozen=True)
class Job:
    owner_id: Optional[int]
    tenant_id: Optional[int]
    visibility: str

    @property
    def user_id(self) -> Optional[int]:
        return self.owner_id


ViewerContext = Viewer
ResourceScope = Job


def _is_owner(v: Viewer, j: Job) -> bool:
    return v.user_id is not None and v.user_id == j.owner_id


def _same_tenant(v: Viewer, j: Job) -> bool:
    return j.tenant_id is not None and j.tenant_id in v.effective_tenant_ids


def _is_tenant_admin_for(v: Viewer, j: Job) -> bool:
    return j.tenant_id is not None and j.tenant_id in v.effective_admin_tenant_ids


def can_read(v: Viewer, j: Job) -> bool:
    if j.visibility == PUBLIC:
        return True
    if v.is_local_admin:  # operator break-glass (gated upstream)
        return True
    if _is_owner(v, j):
        return True
    if _is_tenant_admin_for(v, j):  # group/tenant admin sees all tasks (tenant + private) in their group
        return True
    if j.visibility == TENANT and _same_tenant(v, j):
        return True
    return False  # private => owner, group admin of that group, or break-glass only


def can_toggle(v: Viewer, j: Job) -> bool:
    if _is_owner(v, j):
        return True
    if v.is_local_admin:
        return True
    # group/tenant-admin manages public/tenant/private jobs in their own group
    if _is_tenant_admin_for(v, j) and j.visibility in (PUBLIC, TENANT, PRIVATE):
        return True
    return False


def can_delete(v: Viewer, j: Job) -> bool:
    """Authorize an irreversible task DELETE. Stricter than can_toggle for PUBLIC jobs: a public
    task is a shared/instance resource, so only its ORIGINAL SUBMITTER or a break-glass box admin
    may delete it -- a tenant-admin may toggle/manage a public job in their tenant but NOT delete
    it. TENANT & PRIVATE jobs: submitter, that group's tenant-admin, or box admin."""
    if v.is_local_admin:
        return True
    if _is_owner(v, j):
        return True
    if j.visibility in (TENANT, PRIVATE) and _is_tenant_admin_for(v, j):
        return True
    return False


def can_set_visibility(v: Viewer, j: Job, new_visibility: str) -> bool:
    """Authorize a visibility TRANSITION. Baseline is can_toggle, plus a direction guard that keeps
    can_delete's PUBLIC boundary from being reachable by a two-step move: a principal authorized ONLY
    by the tenant-admin path (not the owner, not a break-glass box admin) may not make a PUBLIC job
    MORE restrictive (public -> tenant/private)."""
    if not can_toggle(v, j):
        return False
    if _is_owner(v, j) or v.is_local_admin:
        return True
    if j.visibility == PUBLIC and new_visibility in (TENANT, PRIVATE):
        return False
    return True


def scope_match(scope: str, v: "Viewer"):
    """Mongo $match (dict) selecting the analysis docs in a stat SCOPE for viewer v.
    Mirrors the can_read branches. Returns None for 'global' (no filter). Keys target
    the report's info.* (stamped at report time)."""
    if scope == GLOBAL:
        return None
    if scope == PUBLIC:
        return {"info.visibility": PUBLIC}
    if scope == TENANT:
        if v is None:
            return {"info.id": -1}
        tids = v.effective_tenant_ids
        if not tids:
            return {"info.id": -1}
        admin_tids = v.effective_admin_tenant_ids
        non_admin_tids = tuple(t for t in tids if t not in admin_tids)
        sub_clauses = []
        if len(non_admin_tids) == 1:
            sub_clauses.append({"info.tenant_id": non_admin_tids[0], "info.visibility": TENANT})
        elif len(non_admin_tids) > 1:
            sub_clauses.append({"info.tenant_id": {"$in": list(non_admin_tids)}, "info.visibility": TENANT})
        if len(admin_tids) == 1:
            sub_clauses.append({"info.tenant_id": admin_tids[0], "info.visibility": {"$in": [TENANT, PRIVATE]}})
        elif len(admin_tids) > 1:
            sub_clauses.append({"info.tenant_id": {"$in": list(admin_tids)}, "info.visibility": {"$in": [TENANT, PRIVATE]}})
        if len(sub_clauses) == 1:
            return sub_clauses[0]
        return {"$or": sub_clauses}
    if scope == MINE:
        if v is None or v.user_id is None:
            return {"info.id": -1}
        return {"info.user_id": v.user_id}
    raise ValueError(f"unknown scope {scope!r}")


@dataclass(frozen=True)
class MTConfig:
    enabled: bool
    mode: str
    default_visibility: str
    local_admins_manage_all_tenants: bool

    @property
    def allow_superuser_all(self) -> bool:
        return self.local_admins_manage_all_tenants


MultitenancyConfig = MTConfig


def _as_bool(v, default: bool) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("yes", "true", "1", "on")
    if v is None:
        return default
    return bool(v)


class _AbsentConfigSectionError(Exception):
    """Sentinel raised when [multitenancy] is absent in cuckoo.conf."""


def _load_multitenancy_section() -> dict:
    try:
        from lib.cuckoo.common.config import Config
        from lib.cuckoo.common.exceptions import CuckooOperationalError
    except ImportError:
        return {}
    try:
        return Config("cuckoo").get("multitenancy")
    except CuckooOperationalError as exc:
        raise _AbsentConfigSectionError(str(exc)) from exc


def multitenancy_config() -> MTConfig:
    """Read the [multitenancy] section of cuckoo.conf (server-side policy)."""
    try:
        sec = _load_multitenancy_section()
    except _AbsentConfigSectionError:
        sec = {}
    except Exception:
        log.exception(
            "multitenancy_config: [multitenancy] unreadable; failing CLOSED "
            "(MT enabled, mode=locked) to preserve tenant isolation"
        )
        return MTConfig(
            enabled=True,
            mode="locked",
            default_visibility="private",
            local_admins_manage_all_tenants=False,
        )
    get = sec.get if hasattr(sec, "get") else (lambda k, d=None: d)
    mode = str(get("mode", "shared") or "shared").strip().lower()
    if mode not in ("shared", "locked"):
        mode = "locked"
    return MTConfig(
        enabled=_as_bool(get("enabled", False), False),
        mode=mode,
        default_visibility=str(get("default_visibility", "") or "").strip().lower(),
        local_admins_manage_all_tenants=_as_bool(get("local_admins_manage_all_tenants", True), True),
    )


def default_visibility(cfg: MTConfig) -> str:
    """The submit-time default visibility for the configured mode."""
    if cfg.default_visibility in VISIBILITIES:
        return cfg.default_visibility
    if cfg.default_visibility:
        log.warning("default_visibility %r unrecognized; failing closed to private", cfg.default_visibility)
        return PRIVATE
    return PUBLIC if cfg.mode == "shared" else TENANT


def viewer_scope_match(viewer):
    """Mongo $match restricting an analysis-collection query to the viewer's
    entitled tenant scopes (public OR own-tenant TENANT/PRIVATE-if-admin OR mine),
    or None when no filter applies (multitenancy disabled or break-glass)."""
    if viewer is None:
        return None
    cfg = multitenancy_config()
    if not cfg.enabled or getattr(viewer, "is_local_admin", False):
        return None
    clauses = [m for m in (scope_match(PUBLIC, viewer), scope_match(TENANT, viewer), scope_match(MINE, viewer)) if m is not None]
    return {"$or": clauses} if clauses else {"info.id": -1}


def viewer_scope_es_filter(viewer):
    """Elasticsearch bool-filter analogue of viewer_scope_match."""
    if viewer is None:
        return None
    cfg = multitenancy_config()
    if not cfg.enabled or getattr(viewer, "is_local_admin", False):
        return None
    shoulds = [{"term": {"info.visibility": PUBLIC}}]
    tids = getattr(viewer, "effective_tenant_ids", None)
    if tids is None:
        tid = getattr(viewer, "tenant_id", None)
        tids = (tid,) if tid is not None else ()
    admin_tids = getattr(viewer, "effective_admin_tenant_ids", None)
    if admin_tids is None:
        admin_tids = tids if getattr(viewer, "is_tenant_admin", False) else ()
    non_admin_tids = tuple(t for t in tids if t not in admin_tids)
    if len(non_admin_tids) == 1:
        shoulds.append(
            {
                "bool": {
                    "filter": [
                        {"term": {"info.tenant_id": non_admin_tids[0]}},
                        {"term": {"info.visibility": TENANT}},
                    ]
                }
            }
        )
    elif len(non_admin_tids) > 1:
        shoulds.append(
            {
                "bool": {
                    "filter": [
                        {"terms": {"info.tenant_id": list(non_admin_tids)}},
                        {"term": {"info.visibility": TENANT}},
                    ]
                }
            }
        )
    if len(admin_tids) == 1:
        shoulds.append(
            {
                "bool": {
                    "filter": [
                        {"term": {"info.tenant_id": admin_tids[0]}},
                        {"terms": {"info.visibility": [TENANT, PRIVATE]}},
                    ]
                }
            }
        )
    elif len(admin_tids) > 1:
        shoulds.append(
            {
                "bool": {
                    "filter": [
                        {"terms": {"info.tenant_id": list(admin_tids)}},
                        {"terms": {"info.visibility": [TENANT, PRIVATE]}},
                    ]
                }
            }
        )
    if getattr(viewer, "user_id", None) is not None:
        shoulds.append({"term": {"info.user_id": viewer.user_id}})
    return {"bool": {"should": shoulds, "minimum_should_match": 1}}
