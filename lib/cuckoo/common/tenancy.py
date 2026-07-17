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


@dataclass(frozen=True)
class Job:
    owner_id: Optional[int]
    tenant_id: Optional[int]
    visibility: str


def _is_owner(v: Viewer, j: Job) -> bool:
    return v.user_id is not None and v.user_id == j.owner_id


def _same_tenant(v: Viewer, j: Job) -> bool:
    return j.tenant_id is not None and v.tenant_id == j.tenant_id


def can_read(v: Viewer, j: Job) -> bool:
    if j.visibility == PUBLIC:
        return True
    if v.is_local_admin:          # operator break-glass (gated upstream)
        return True
    if _is_owner(v, j):
        return True
    if j.visibility == TENANT and _same_tenant(v, j):
        return True
    return False                  # private => owner/break-glass only


def can_toggle(v: Viewer, j: Job) -> bool:
    if _is_owner(v, j):
        return True
    if v.is_local_admin:
        return True
    # tenant-admin manages public/tenant jobs in their own tenant, never private
    if v.is_tenant_admin and _same_tenant(v, j) and j.visibility in (PUBLIC, TENANT):
        return True
    return False


def scope_match(scope: str, v: "Viewer"):
    """Mongo $match (dict) selecting the analysis docs in a stat SCOPE for viewer v.
    Mirrors the can_read branches. Returns None for 'global' (no filter). Keys target
    the report's info.* (stamped at report time)."""
    if scope == GLOBAL:
        return None
    if scope == PUBLIC:
        return {"info.visibility": PUBLIC}
    if scope == TENANT:
        if v is None or v.tenant_id is None:
            return {"info.id": -1}  # no viewer / tenant-less -> empty
        return {"info.tenant_id": v.tenant_id, "info.visibility": TENANT}
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


def _as_bool(v, default: bool) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("yes", "true", "1", "on")
    if v is None:
        return default
    return bool(v)


def multitenancy_config() -> MTConfig:
    """Read the [multitenancy] section of cuckoo.conf (server-side policy)."""
    from lib.cuckoo.common.config import Config
    from lib.cuckoo.common.exceptions import CuckooOperationalError

    try:
        sec = Config("cuckoo").get("multitenancy")
    except CuckooOperationalError:
        # [multitenancy] section absent => not configured => MT off. The legitimate
        # single-tenant default, NOT an error (Config.get raises this on a missing
        # section). This branch keeps single-tenant deployments working.
        sec = {}
    except Exception:
        # A malformed/unreadable cuckoo.conf (parse/IO error — NOT a merely-absent
        # section, which is the CuckooOperationalError branch above) must NOT silently
        # drop tenant isolation. Fail CLOSED — assume MT ON + the most restrictive
        # mode until the config reads cleanly — mirroring the mode normalization below
        # and the backfill node-role guard, which fail closed on the same class of
        # error rather than defaulting to the permissive branch. Log loudly so an
        # operator sees isolation was preserved defensively.
        log.exception(
            "multitenancy_config: [multitenancy] unreadable; failing CLOSED "
            "(MT enabled, mode=locked) to preserve tenant isolation"
        )
        # Fail closed on EVERY knob, not just enabled/mode: local_admins_manage_all_tenants
        # False is the RESTRICTIVE value (a deployment that set it 'no' must not have a
        # local Django superuser regain full break-glass on the fail-closed path; IdP
        # superusers still keep reach via viewer_for's socialaccount branch).
        # default_visibility="private" (NOT "" — which would resolve through
        # default_visibility()'s per-mode fallback to TENANT under mode=locked, widening
        # submit-time exposure during a config outage). private is the most restrictive
        # VISIBILITIES member, so pin it directly on the fail-closed path.
        return MTConfig(enabled=True, mode="locked", default_visibility="private",
                        local_admins_manage_all_tenants=False)
    get = sec.get if hasattr(sec, "get") else (lambda k, d=None: d)
    # Validate/normalize mode: an unknown/typo value must NOT silently disable
    # scoping. Case/whitespace-normalize and fail closed to the more restrictive
    # "locked" on anything unrecognized.
    mode = str(get("mode", "shared") or "shared").strip().lower()
    if mode not in ("shared", "locked"):
        mode = "locked"
    return MTConfig(
        enabled=_as_bool(get("enabled", False), False),
        mode=mode,
        # Normalize like `mode` above: an un-normalized "Private"/" private " fails the
        # exact `in VISIBILITIES` check in default_visibility() and silently falls back to
        # the per-mode default (PUBLIC in shared) — the one knob whose misparse WIDENS
        # exposure, so strip/lowercase it too.
        default_visibility=str(get("default_visibility", "") or "").strip().lower(),
        local_admins_manage_all_tenants=_as_bool(get("local_admins_manage_all_tenants", True), True),
    )


def default_visibility(cfg: MTConfig) -> str:
    """The submit-time default visibility for the configured mode."""
    if cfg.default_visibility in VISIBILITIES:
        return cfg.default_visibility
    if cfg.default_visibility:
        # Explicitly set but unrecognized (typo like "privte" / templating artifact):
        # fail CLOSED like the `mode` knob does, never fall open to the widest per-mode
        # default. Blank stays the documented per-mode-default sentinel below.
        log.warning("default_visibility %r unrecognized; failing closed to private",
                    cfg.default_visibility)
        return PRIVATE
    return PUBLIC if cfg.mode == "shared" else TENANT


def viewer_scope_match(viewer):
    """Mongo $match restricting an analysis-collection query to the viewer's
    entitled tenant scopes (public OR own-tenant TENANT OR mine), or None when no
    filter applies — multitenancy disabled or break-glass (is_local_admin). THE
    single source of truth (imported by web_utils, cape_utils, …) so the
    search/dedup/stats by-scope query builders can't drift. Mode-INDEPENDENT,
    mirroring can_read and the SQL list_tasks filter: shared mode still hides
    explicitly-private and other-tenant TENANT analyses (only PUBLIC is the shared
    pool) — it does NOT mean see-all. Keys target the report's stamped info.*.
    """
    if viewer is None:
        return None
    cfg = multitenancy_config()
    if not cfg.enabled or getattr(viewer, "is_local_admin", False):
        return None
    clauses = [m for m in (scope_match(PUBLIC, viewer), scope_match(TENANT, viewer), scope_match(MINE, viewer)) if m is not None]
    # No entitled scope resolved (tenant-less/anon) -> match nothing, never global.
    return {"$or": clauses} if clauses else {"info.id": -1}


def viewer_scope_es_filter(viewer):
    """Elasticsearch bool-filter analogue of viewer_scope_match (public OR
    own-tenant TENANT OR mine), or None when no filter applies (multitenancy
    disabled or break-glass). Mode-INDEPENDENT, same as viewer_scope_match. Uses
    the term/info.* idiom. A tenant-less/anonymous viewer sees only public.
    """
    if viewer is None:
        return None
    cfg = multitenancy_config()
    if not cfg.enabled or getattr(viewer, "is_local_admin", False):
        return None
    shoulds = [{"term": {"info.visibility": PUBLIC}}]
    if getattr(viewer, "tenant_id", None) is not None:
        shoulds.append({"bool": {"filter": [
            {"term": {"info.tenant_id": viewer.tenant_id}},
            {"term": {"info.visibility": TENANT}},
        ]}})
    if getattr(viewer, "user_id", None) is not None:
        shoulds.append({"term": {"info.user_id": viewer.user_id}})
    return {"bool": {"should": shoulds, "minimum_should_match": 1}}
