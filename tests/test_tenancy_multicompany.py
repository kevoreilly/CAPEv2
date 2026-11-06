"""End-to-end multi-company and multi-department isolation test suite for `lib.tenancy`.

Models three separate companies (Acme Corp, Globex Inc, Initech), two internal departments
within Acme Corp (`acme-ir` and `acme-soc`) inheriting company-wide tasks/resources from
`acme-corp`, and a cross-department collaboration group (`joint-threat-intel`) shared between
selected members of `acme-ir` and `acme-soc`.

Verifies isolation and sharing across:
- SQLAlchemy (`Task` + `TaskAcl` outer-join queries)
- MongoDB (`default_mongo_analysis_filter` + `perform_search` with default and custom projections)
- Elasticsearch (`default_es_query_filter`, `own_report_es_query`, `is_task_own_report`, bulk reconcile)
- `TenancyMiddleware` (`read`, `manage`, `delete`, `compare`, `guac`, `Recovery_<id>`, submissions)
- Sandbox VM, tag, route, timeout, and interactive-desktop entitlements per company and department
- Live `toggle_task_visibility_cas` transitions across SQL, MongoDB, and Elasticsearch.
"""

from __future__ import annotations

import types
from typing import Any, Dict, Iterable, List, Mapping

import pytest
from sqlalchemy import Column, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from lib.cuckoo.common import hooks as core_hooks
from lib.tenancy.acl import (
    TaskAcl,
    ensure_acl_schema,
    own_report_es_query,
    resolve_task_scope,
    set_task_acl,
    toggle_task_visibility_cas,
)
from lib.tenancy.context import (
    set_current_entitlements,
    set_current_submission_visibility,
    set_current_viewer,
)


@pytest.fixture(autouse=True)
def _reset_tenancy_context_and_hooks():
    set_current_viewer(None)
    set_current_entitlements(None)
    set_current_submission_visibility(None)
    core_hooks.clear_all_hooks()
    yield
    set_current_viewer(None)
    set_current_entitlements(None)
    set_current_submission_visibility(None)
    core_hooks.clear_all_hooks()
from lib.tenancy.hooks import (
    default_es_query_filter,
    default_machine_list_filter,
    default_mongo_analysis_filter,
    default_route_list_filter,
    default_sql_task_acl_clause,
    default_submission_context_filter,
    default_tag_list_filter,
)
from lib.tenancy.middleware import (
    TenancyMiddleware,
    default_viewer_resolver,
)
from lib.tenancy.policy import (
    PRIVATE,
    PUBLIC,
    TENANT,
    MultitenancyConfig,
    ResourceScope,
    ViewerContext,
    can_read,
)
from lib.tenancy.resources import (
    resolve_user_entitlements,
    validate_and_normalize_submission,
)

# ---------------------------------------------------------------------------
# Group & Company IDs
# ---------------------------------------------------------------------------
G_ACME_CORP = 100
G_ACME_ADMINS = 101
G_ACME_IR = 102
G_ACME_SOC = 103
G_JOINT_INTEL = 150

G_GLOBEX = 200
G_GLOBEX_ADMINS = 201

G_INITECH = 300

# ---------------------------------------------------------------------------
# User IDs
# ---------------------------------------------------------------------------
U_ALICE_IR = 11          # Acme IR + Joint Threat-Intel
U_FRANK_IR_ONLY = 12     # Acme IR only
U_DAVE_SOC = 13          # Acme SOC + Joint Threat-Intel
U_ERIN_SOC_ONLY = 14     # Acme SOC only
U_ADMIN_ACME = 15        # Acme tenant admin (covers 100, 102, 103)
U_BOB_GLOBEX = 21        # Globex regular analyst
U_ADMIN_GLOBEX = 22      # Globex tenant admin (covers 200)
U_CHARLIE_INITECH = 31   # Initech regular analyst
U_EVE_UNASSIGNED = 41    # Authenticated user with no groups
U_SCOPED_SUPER = 51      # Superuser when local_admins_manage_all_tenants=False
U_BOX_ADMIN = 99         # Superuser when local_admins_manage_all_tenants=True

# ---------------------------------------------------------------------------
# Task IDs
# ---------------------------------------------------------------------------
T_ACME_CORP_SHARED = 1001   # tenant=100 (acme-corp), vis=groups, owner=U_ADMIN_ACME
T_ACME_IR_DEPT = 1002       # tenant=102 (acme-ir), vis=groups, owner=U_FRANK_IR_ONLY
T_ACME_SOC_DEPT = 1003      # tenant=103 (acme-soc), vis=groups, owner=U_ERIN_SOC_ONLY
T_JOINT_INTEL = 1004        # tenant=150 (joint-intel), vis=groups, owner=U_ALICE_IR
T_ALICE_PRIVATE = 1005      # tenant=102 (acme-ir), vis=private, owner=U_ALICE_IR
T_GLOBEX_GROUP = 2001       # tenant=200 (globex), vis=groups, owner=U_BOB_GLOBEX
T_GLOBEX_PRIVATE = 2002     # tenant=200 (globex), vis=private, owner=U_BOB_GLOBEX
T_INITECH_GROUP = 3001      # tenant=300 (initech), vis=groups, owner=U_CHARLIE_INITECH
T_INITECH_PUBLIC = 3002     # tenant=300 (initech), vis=public, owner=U_CHARLIE_INITECH


class _TaskBase(DeclarativeBase):
    pass


class _SimTask(_TaskBase):
    __tablename__ = "sim_tasks"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=True)
    custom = Column(String(255), default="")


def _make_group_and_policy(
    gid: int,
    name: str,
    *,
    is_tenant_boundary: bool = True,
    is_tenant_admin_group: bool = False,
    parent_group: Any = None,
    inherit_parent_tasks: bool = True,
    inherit_parent_resources: bool = True,
    priority: int = 10,
    allowed_machines: Iterable[str] = (),
    allowed_tags: Iterable[str] = (),
    allowed_routes: Iterable[str] = (),
    allow_all_vms: bool = False,
    allow_route_none: bool = True,
    default_route: str = "none",
    max_timeout: int = 180,
    allow_interactive_desktop: bool = False,
    default_visibility: str = TENANT,
    allowed_visibilities: Iterable[str] = (PRIVATE, TENANT),
) -> Any:
    grp = types.SimpleNamespace(id=gid, name=name, sandbox_policy=None)
    pol = types.SimpleNamespace(
        id=gid,
        group=grp,
        group_id=gid,
        active=True,
        priority=priority,
        is_tenant_boundary=is_tenant_boundary,
        is_tenant_admin_group=is_tenant_admin_group,
        tenant_id=gid if is_tenant_boundary else (parent_group.id if parent_group is not None else None),
        parent_group=parent_group,
        inherit_parent_tasks=inherit_parent_tasks,
        inherit_parent_resources=inherit_parent_resources,
        allowed_machines=list(allowed_machines),
        allowed_tags=list(allowed_tags),
        forced_machine_tags=[],
        allowed_routes=list(allowed_routes),
        allow_all_vms=allow_all_vms,
        allow_route_none=allow_route_none,
        default_route=default_route,
        max_timeout=max_timeout,
        allow_enforce_timeout=False,
        allow_memory_dump=False,
        allow_procmemdump=True,
        allow_interactive_desktop=allow_interactive_desktop,
        default_visibility=default_visibility,
        allowed_visibilities=list(allowed_visibilities),
    )
    grp.sandbox_policy = pol
    return grp


def _make_user(
    uid: int,
    username: str,
    groups: Iterable[Any],
    *,
    is_superuser: bool = False,
    is_staff: bool = False,
) -> Any:
    return types.SimpleNamespace(
        id=uid,
        pk=uid,
        username=username,
        is_authenticated=True,
        is_superuser=is_superuser,
        is_staff=is_staff,
        userprofile=None,
        tenant_membership=None,
        groups=list(groups),
    )


# ---------------------------------------------------------------------------
# In-memory MongoDB & Elasticsearch query evaluators for realistic testing
# ---------------------------------------------------------------------------
def _get_nested(doc: Mapping[str, Any], dotted: str) -> Any:
    cur: Any = doc
    for part in dotted.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


_MISSING = object()


def _eval_mongo_query(doc: Mapping[str, Any], query: Mapping[str, Any]) -> bool:
    if not query:
        return True
    for k, cond in query.items():
        if k == "$and":
            if not all(_eval_mongo_query(doc, sub) for sub in cond):
                return False
        elif k == "$or":
            if not any(_eval_mongo_query(doc, sub) for sub in cond):
                return False
        else:
            val = _get_nested(doc, k)
            if isinstance(cond, Mapping):
                for op, target in cond.items():
                    if op == "$in":
                        effective = None if val is _MISSING else val
                        if effective not in target:
                            return False
                    elif op == "$nin":
                        if val is not _MISSING and val in target:
                            return False
                    elif op == "$ne":
                        effective = None if val is _MISSING else val
                        if effective == target:
                            return False
                    elif op == "$lte":
                        if val is _MISSING or val > target:
                            return False
                    elif op == "$exists":
                        exists = val is not _MISSING
                        if exists != bool(target):
                            return False
                    else:
                        raise AssertionError(f"Unsupported mongo op: {op}")
            else:
                effective = None if val is _MISSING else val
                if effective != cond:
                    return False
    return True


def _eval_es_clause(doc: Mapping[str, Any], clause: Mapping[str, Any]) -> bool:
    if not clause or "match_all" in clause:
        return True
    if "term" in clause:
        field, expected = next(iter(clause["term"].items()))
        val = _get_nested(doc, field)
        return val is not _MISSING and val == expected
    if "terms" in clause:
        field, expected_list = next(iter(clause["terms"].items()))
        val = _get_nested(doc, field)
        return val is not _MISSING and val in expected_list
    if "exists" in clause:
        field = clause["exists"]["field"]
        val = _get_nested(doc, field)
        return val is not _MISSING and val is not None
    if "range" in clause:
        field, bounds = next(iter(clause["range"].items()))
        val = _get_nested(doc, field)
        if val is _MISSING or val is None:
            return False
        if "lte" in bounds and not (val <= bounds["lte"]):
            return False
        return True
    if "match_phrase" in clause:
        field, phrase = next(iter(clause["match_phrase"].items()))
        val = _get_nested(doc, field)
        if not isinstance(val, str):
            return False
        # Standard analyzer tokenizes on hyphens: "ui-5" phrase-matches "ui-5" and "ui-5-extra".
        tokens = val.split("-")
        phrase_tokens = str(phrase).split("-")
        return any(tokens[i : i + len(phrase_tokens)] == phrase_tokens for i in range(len(tokens) - len(phrase_tokens) + 1))
    if "bool" in clause:
        b = clause["bool"]

        def _as_list(val: Any) -> List[Mapping[str, Any]]:
            if not val:
                return []
            if isinstance(val, Mapping):
                return [val]
            return list(val)

        for m in _as_list(b.get("must")):
            if not _eval_es_clause(doc, m):
                return False
        for f in _as_list(b.get("filter")):
            if not _eval_es_clause(doc, f):
                return False
        for mn in _as_list(b.get("must_not")):
            if _eval_es_clause(doc, mn):
                return False
        shoulds = _as_list(b.get("should"))
        min_should = b.get("minimum_should_match", 1 if shoulds else 0)
        if shoulds:
            matched = sum(1 for s in shoulds if _eval_es_clause(doc, s))
            if matched < min_should:
                return False
        return True
    raise AssertionError(f"Unsupported ES clause: {clause}")


@pytest.fixture()
def multicompany_env(monkeypatch):
    """Build 3 companies (Acme, Globex, Initech), 2 Acme departments, 1 shared view group, 11 users, and 9 tasks."""
    cfg = MultitenancyConfig(
        enabled=True,
        mode="locked",
        default_visibility=PRIVATE,
        local_admins_manage_all_tenants=True,
        readers_can_comment=False,
    )
    monkeypatch.setattr("lib.tenancy.policy.multitenancy_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.middleware.multitenancy_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.resources.multitenancy_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.hooks.multitenancy_config", lambda: cfg)

    # Company A: Acme Corp + 2 sub-departments + 1 admin group
    g_acme_corp = _make_group_and_policy(
        G_ACME_CORP,
        "acme-corp",
        priority=10,
        allowed_machines=["acme-win10", "acme-win11"],
        allowed_tags=["acme", "win10"],
        allowed_routes=["vpn-acme"],
        allow_route_none=True,
        default_route="vpn-acme",
        max_timeout=180,
        default_visibility=TENANT,
        allowed_visibilities=[PRIVATE, TENANT],
    )
    g_acme_ir = _make_group_and_policy(
        G_ACME_IR,
        "acme-ir",
        parent_group=g_acme_corp,
        inherit_parent_tasks=True,
        inherit_parent_resources=True,
        priority=20,
        allowed_machines=["acme-ir-forensics"],
        allowed_tags=["ir"],
        allowed_routes=["vpn-acme-ir"],
        max_timeout=240,
        default_visibility=TENANT,
        allowed_visibilities=[PRIVATE, TENANT],
    )
    g_acme_soc = _make_group_and_policy(
        G_ACME_SOC,
        "acme-soc",
        parent_group=g_acme_corp,
        inherit_parent_tasks=True,
        inherit_parent_resources=True,
        priority=20,
        allowed_machines=["acme-soc-triage"],
        allowed_tags=["soc"],
        allowed_routes=["vpn-acme-soc"],
        max_timeout=120,
        default_visibility=TENANT,
        allowed_visibilities=[PRIVATE, TENANT],
    )
    g_acme_admins = _make_group_and_policy(
        G_ACME_ADMINS,
        "acme-admins",
        is_tenant_boundary=False,
        is_tenant_admin_group=True,
        parent_group=g_acme_corp,
        priority=30,
        allow_interactive_desktop=True,
        max_timeout=300,
        allowed_visibilities=[PRIVATE, TENANT, PUBLIC],
    )
    # Also mark admin rights for g_acme_ir and g_acme_soc via admin sub-policies for U_ADMIN_ACME
    g_acme_ir_admin = _make_group_and_policy(
        G_ACME_IR,
        "acme-ir-admin-view",
        is_tenant_boundary=True,
        is_tenant_admin_group=True,
        parent_group=g_acme_corp,
        priority=25,
        allowed_machines=["acme-ir-forensics"],
        allowed_tags=["ir"],
        allowed_routes=["vpn-acme-ir"],
        allow_interactive_desktop=True,
        allowed_visibilities=[PRIVATE, TENANT, PUBLIC],
    )
    g_acme_soc_admin = _make_group_and_policy(
        G_ACME_SOC,
        "acme-soc-admin-view",
        is_tenant_boundary=True,
        is_tenant_admin_group=True,
        parent_group=g_acme_corp,
        priority=25,
        allowed_machines=["acme-soc-triage"],
        allowed_tags=["soc"],
        allowed_routes=["vpn-acme-soc"],
        allow_interactive_desktop=True,
        allowed_visibilities=[PRIVATE, TENANT, PUBLIC],
    )
    g_acme_corp_admin = _make_group_and_policy(
        G_ACME_CORP,
        "acme-corp-admin-view",
        is_tenant_boundary=True,
        is_tenant_admin_group=True,
        priority=30,
        allowed_machines=["acme-win10", "acme-win11"],
        allowed_tags=["acme", "win10"],
        allowed_routes=["vpn-acme"],
        allow_interactive_desktop=True,
        allowed_visibilities=[PRIVATE, TENANT, PUBLIC],
    )

    # Cross-Department Shared View Group (Joint Threat-Intel)
    g_joint_intel = _make_group_and_policy(
        G_JOINT_INTEL,
        "joint-threat-intel",
        priority=15,
        allowed_machines=["acme-win10"],
        allowed_tags=["intel"],
        allowed_routes=["vpn-acme"],
        default_visibility=TENANT,
        allowed_visibilities=[PRIVATE, TENANT],
    )

    # Company B: Globex Inc
    g_globex = _make_group_and_policy(
        G_GLOBEX,
        "globex-inc",
        priority=20,
        allowed_machines=["globex-win11"],
        allowed_tags=["globex"],
        allowed_routes=["vpn-globex"],
        allow_route_none=False,
        default_route="vpn-globex",
        max_timeout=120,
        default_visibility=PRIVATE,
        allowed_visibilities=[PRIVATE, TENANT],
    )
    g_globex_admin = _make_group_and_policy(
        G_GLOBEX,
        "globex-admins",
        is_tenant_boundary=True,
        is_tenant_admin_group=True,
        priority=30,
        allowed_machines=["globex-win11"],
        allowed_tags=["globex"],
        allowed_routes=["vpn-globex"],
        allow_route_none=False,
        default_route="vpn-globex",
        max_timeout=240,
        allow_interactive_desktop=True,
        default_visibility=TENANT,
        allowed_visibilities=[PRIVATE, TENANT],
    )

    # Company C: Initech
    g_initech = _make_group_and_policy(
        G_INITECH,
        "initech",
        priority=20,
        allowed_machines=["initech-linux"],
        allowed_tags=["initech"],
        allowed_routes=["tor"],
        allow_route_none=True,
        default_route="tor",
        max_timeout=150,
        default_visibility=TENANT,
        allowed_visibilities=[PRIVATE, TENANT, PUBLIC],
    )

    users = {
        "alice_ir": _make_user(U_ALICE_IR, "alice_ir", [g_acme_ir, g_joint_intel]),
        "frank_ir_only": _make_user(U_FRANK_IR_ONLY, "frank_ir_only", [g_acme_ir]),
        "dave_soc": _make_user(U_DAVE_SOC, "dave_soc", [g_acme_soc, g_joint_intel]),
        "erin_soc_only": _make_user(U_ERIN_SOC_ONLY, "erin_soc_only", [g_acme_soc]),
        "admin_acme": _make_user(
            U_ADMIN_ACME, "admin_acme", [g_acme_corp_admin, g_acme_ir_admin, g_acme_soc_admin, g_acme_admins]
        ),
        "bob_globex": _make_user(U_BOB_GLOBEX, "bob_globex", [g_globex]),
        "admin_globex": _make_user(U_ADMIN_GLOBEX, "admin_globex", [g_globex_admin]),
        "charlie_initech": _make_user(U_CHARLIE_INITECH, "charlie_initech", [g_initech]),
        "eve_unassigned": _make_user(U_EVE_UNASSIGNED, "eve_unassigned", []),
        "box_admin": _make_user(U_BOX_ADMIN, "box_admin", [], is_superuser=True, is_staff=True),
    }

    # SQLite in-memory database with sim_tasks + task_acl
    engine = create_engine("sqlite:///:memory:")
    _TaskBase.metadata.create_all(engine)
    ensure_acl_schema(engine)
    SessionLocal = sessionmaker(bind=engine)

    seed_tasks = [
        (T_ACME_CORP_SHARED, U_ADMIN_ACME, G_ACME_CORP, TENANT),
        (T_ACME_IR_DEPT, U_FRANK_IR_ONLY, G_ACME_IR, TENANT),
        (T_ACME_SOC_DEPT, U_ERIN_SOC_ONLY, G_ACME_SOC, TENANT),
        (T_JOINT_INTEL, U_ALICE_IR, G_JOINT_INTEL, TENANT),
        (T_ALICE_PRIVATE, U_ALICE_IR, G_ACME_IR, PRIVATE),
        (T_GLOBEX_GROUP, U_BOB_GLOBEX, G_GLOBEX, TENANT),
        (T_GLOBEX_PRIVATE, U_BOB_GLOBEX, G_GLOBEX, PRIVATE),
        (T_INITECH_GROUP, U_CHARLIE_INITECH, G_INITECH, TENANT),
        (T_INITECH_PUBLIC, U_CHARLIE_INITECH, G_INITECH, PUBLIC),
    ]

    mongo_docs: Dict[int, Dict[str, Any]] = {}
    es_docs: Dict[int, Dict[str, Any]] = {}

    with SessionLocal() as session:
        for tid, uid, tenant_id, vis in seed_tasks:
            session.add(_SimTask(id=tid, user_id=uid, custom=""))
            set_task_acl(session, tid, user_id=uid, tenant_id=tenant_id, visibility=vis)
            doc = {
                "_id": f"doc-{tid}",
                "info": {
                    "id": tid,
                    "user_id": uid,
                    "tenant_id": tenant_id,
                    "visibility": vis,
                    "visibility_seq": 1,
                    "tlp": "amber",
                },
                "target": {"file": {"sha256": "a" * 64}},
            }
            mongo_docs[tid] = doc
            es_docs[tid] = {
                "_index": "cape-analysis-2026.11.01",
                "_id": f"es-{tid}",
                "_source": {
                    "info": dict(doc["info"]),
                    "behavior": {"processes": []},
                },
            }
        session.commit()

    def query_sql_visible(viewer: ViewerContext) -> set[int]:
        with SessionLocal() as session:
            stmt = select(_SimTask.id)
            clause = default_sql_task_acl_clause(_SimTask.id, _SimTask.user_id, viewer)
            if clause is not None:
                stmt = stmt.outerjoin(TaskAcl, TaskAcl.task_id == _SimTask.id).filter(clause)
            return set(session.scalars(stmt).all())

    def query_mongo_visible(viewer: ViewerContext) -> set[int]:
        flt = default_mongo_analysis_filter("analysis", {}, viewer=viewer)
        return {tid for tid, doc in mongo_docs.items() if _eval_mongo_query(doc, flt)}

    def query_es_visible(viewer: ViewerContext) -> set[int]:
        body = default_es_query_filter({"query": {"match_all": {}}}, viewer=viewer)
        q = body["query"]
        return {tid for tid, hit in es_docs.items() if _eval_es_clause(hit["_source"], q)}

    def resolve_scope(task_id: int) -> ResourceScope:
        with SessionLocal() as session:
            t = session.get(_SimTask, int(task_id))
            fallback_uid = t.user_id if t is not None else None
            return resolve_task_scope(session, int(task_id), fallback_user_id=fallback_uid)

    return types.SimpleNamespace(
        cfg=cfg,
        users=users,
        SessionLocal=SessionLocal,
        mongo_docs=mongo_docs,
        es_docs=es_docs,
        query_sql_visible=query_sql_visible,
        query_mongo_visible=query_mongo_visible,
        query_es_visible=query_es_visible,
        resolve_scope=resolve_scope,
    )


# ===========================================================================
# 1. Cross-Company & Multi-Department Read Visibility Matrix (SQL, Mongo, ES)
# ===========================================================================
EXPECTED_VISIBLE_TASKS = {
    # Alice (Acme IR + Joint Threat-Intel + inherits Acme Corp):
    # Sees Acme Corp shared, Acme IR dept, Joint Threat-Intel, her own private task, and Initech public.
    # Cannot see Acme SOC dept, Globex group/private, or Initech group!
    "alice_ir": {
        T_ACME_CORP_SHARED,
        T_ACME_IR_DEPT,
        T_JOINT_INTEL,
        T_ALICE_PRIVATE,
        T_INITECH_PUBLIC,
    },
    # Frank (Acme IR only + inherits Acme Corp):
    # Sees Acme Corp shared, Acme IR dept, and Initech public.
    # Cannot see Joint Threat-Intel (not a member!), Alice's private task, Acme SOC dept, or Globex/Initech!
    "frank_ir_only": {
        T_ACME_CORP_SHARED,
        T_ACME_IR_DEPT,
        T_INITECH_PUBLIC,
    },
    # Dave (Acme SOC + Joint Threat-Intel + inherits Acme Corp):
    # Sees Acme Corp shared, Acme SOC dept, Joint Threat-Intel (shared with Alice!), and Initech public.
    # Cannot see Acme IR dept, Alice's private task, or Globex/Initech!
    "dave_soc": {
        T_ACME_CORP_SHARED,
        T_ACME_SOC_DEPT,
        T_JOINT_INTEL,
        T_INITECH_PUBLIC,
    },
    # Erin (Acme SOC only + inherits Acme Corp):
    # Sees Acme Corp shared, Acme SOC dept, and Initech public.
    # Cannot see Joint Threat-Intel, Acme IR dept, Alice's private task, or Globex/Initech!
    "erin_soc_only": {
        T_ACME_CORP_SHARED,
        T_ACME_SOC_DEPT,
        T_INITECH_PUBLIC,
    },
    # Acme Tenant Admin (admin over Acme Corp 100, Acme IR 102, Acme SOC 103):
    # Sees all Acme Corp, Acme IR, and Acme SOC tasks (including Alice's PRIVATE task in Acme IR!),
    # plus Initech public. Cannot see Joint Threat-Intel (150) or any Globex/Initech non-public task!
    "admin_acme": {
        T_ACME_CORP_SHARED,
        T_ACME_IR_DEPT,
        T_ACME_SOC_DEPT,
        T_ALICE_PRIVATE,
        T_INITECH_PUBLIC,
    },
    # Bob (Globex regular member):
    # Sees Globex group, his own Globex private task, and Initech public.
    # Zero visibility into Acme or Initech non-public tasks.
    "bob_globex": {
        T_GLOBEX_GROUP,
        T_GLOBEX_PRIVATE,
        T_INITECH_PUBLIC,
    },
    # Globex Tenant Admin:
    # Sees Globex group and Globex private tasks (even though owned by Bob), plus Initech public.
    # Zero visibility into Acme or Initech non-public tasks.
    "admin_globex": {
        T_GLOBEX_GROUP,
        T_GLOBEX_PRIVATE,
        T_INITECH_PUBLIC,
    },
    # Charlie (Initech regular member):
    # Sees Initech group and Initech public. Zero visibility into Acme or Globex.
    "charlie_initech": {
        T_INITECH_GROUP,
        T_INITECH_PUBLIC,
    },
    # Unassigned authenticated user:
    # Sees only public tasks.
    "eve_unassigned": {
        T_INITECH_PUBLIC,
    },
    # Platform box admin (is_superuser=True with local_admins_manage_all_tenants=True):
    # Sees all 9 tasks across all companies.
    "box_admin": {
        T_ACME_CORP_SHARED,
        T_ACME_IR_DEPT,
        T_ACME_SOC_DEPT,
        T_JOINT_INTEL,
        T_ALICE_PRIVATE,
        T_GLOBEX_GROUP,
        T_GLOBEX_PRIVATE,
        T_INITECH_GROUP,
        T_INITECH_PUBLIC,
    },
}


@pytest.mark.parametrize("persona", list(EXPECTED_VISIBLE_TASKS.keys()))
def test_multicompany_and_department_visibility_across_sql_mongo_and_es(multicompany_env, persona):
    user = multicompany_env.users[persona]
    viewer = default_viewer_resolver(user)
    expected = EXPECTED_VISIBLE_TASKS[persona]

    sql_visible = multicompany_env.query_sql_visible(viewer)
    mongo_visible = multicompany_env.query_mongo_visible(viewer)
    es_visible = multicompany_env.query_es_visible(viewer)

    assert sql_visible == expected, f"SQL mismatch for {persona}: got {sql_visible}, expected {expected}"
    assert mongo_visible == expected, f"Mongo mismatch for {persona}: got {mongo_visible}, expected {expected}"
    assert es_visible == expected, f"ES mismatch for {persona}: got {es_visible}, expected {expected}"

    # Verify policy.can_read agrees on every task in the corpus
    all_tids = EXPECTED_VISIBLE_TASKS["box_admin"]
    policy_visible = {tid for tid in all_tids if can_read(viewer, multicompany_env.resolve_scope(tid))}
    assert policy_visible == expected


# ===========================================================================
# 2. Middleware Enforcement Across Read, Manage, Delete, Compare & Recovery
# ===========================================================================
def test_middleware_enforces_company_and_department_boundaries(multicompany_env):
    mw = TenancyMiddleware(
        lambda req: types.SimpleNamespace(status_code=200),
        viewer_resolver=default_viewer_resolver,
        entitlements_resolver=resolve_user_entitlements,
        task_scope_resolver=multicompany_env.resolve_scope,
    )

    def _call_view(user_key: str, path: str, view_name: str, method: str = "GET", **kwargs) -> int:
        req = types.SimpleNamespace(
            user=multicompany_env.users[user_key],
            path=path,
            path_info=path,
            method=method,
            GET={},
            POST={},
            META={},
        )
        view_fn = lambda request, **kw: types.SimpleNamespace(status_code=200)  # noqa: E731
        view_fn.__name__ = view_name
        resp = mw.process_view(req, view_fn, (), kwargs)
        return 200 if resp is None else resp.status_code

    # 1. Cross-company read attempts return 404 (no existence leak)
    assert _call_view("bob_globex", f"/analysis/{T_ACME_IR_DEPT}/summary/", "report", task_id=T_ACME_IR_DEPT) == 404
    assert _call_view("admin_globex", f"/analysis/{T_ALICE_PRIVATE}/summary/", "report", task_id=T_ALICE_PRIVATE) == 404
    assert _call_view("admin_acme", f"/analysis/{T_GLOBEX_PRIVATE}/summary/", "report", task_id=T_GLOBEX_PRIVATE) == 404

    # 2. Intra-company department isolation: Dave (Acme SOC) cannot read Frank's Acme IR task (404),
    #    but CAN read Alice's Joint Threat-Intel task (200) and Acme Corp parent shared task (200)!
    assert _call_view("dave_soc", f"/analysis/{T_ACME_IR_DEPT}/summary/", "report", task_id=T_ACME_IR_DEPT) == 404
    assert _call_view("dave_soc", f"/analysis/{T_JOINT_INTEL}/summary/", "report", task_id=T_JOINT_INTEL) == 200
    assert _call_view("dave_soc", f"/analysis/{T_ACME_CORP_SHARED}/summary/", "report", task_id=T_ACME_CORP_SHARED) == 200

    # 3. Public task protection: Alice and Bob can READ Charlie's public task (200),
    #    but CANNOT delete or reboot it (denied with 404 by deny_response_factory)!
    assert _call_view("alice_ir", f"/analysis/{T_INITECH_PUBLIC}/summary/", "report", task_id=T_INITECH_PUBLIC) == 200
    assert _call_view("alice_ir", f"/analysis/remove/{T_INITECH_PUBLIC}/", "remove", task_id=T_INITECH_PUBLIC) == 404
    assert _call_view("bob_globex", f"/analysis/{T_INITECH_PUBLIC}/reboot/", "reboot_task", task_id=T_INITECH_PUBLIC) == 404

    # 4. Compare view checks BOTH left_id and right_id:
    #    Alice can compare her own task with Joint Threat-Intel (200),
    #    but comparing her task withAcme SOC's or Globex's returns 404!
    assert (
        _call_view(
            "alice_ir",
            f"/compare/{T_ALICE_PRIVATE}/{T_JOINT_INTEL}/",
            "compare_both",
            left_id=T_ALICE_PRIVATE,
            right_id=T_JOINT_INTEL,
        )
        == 200
    )
    assert (
        _call_view(
            "alice_ir",
            f"/compare/{T_ALICE_PRIVATE}/{T_ACME_SOC_DEPT}/",
            "compare_both",
            left_id=T_ALICE_PRIVATE,
            right_id=T_ACME_SOC_DEPT,
        )
        == 404
    )
    assert (
        _call_view(
            "alice_ir",
            f"/compare/{T_ALICE_PRIVATE}/{T_GLOBEX_GROUP}/",
            "compare_both",
            left_id=T_ALICE_PRIVATE,
            right_id=T_GLOBEX_GROUP,
        )
        == 404
    )

    # 5. Tenant Admin manage/delete rights within their own company vs other companies:
    assert _call_view("admin_acme", f"/analysis/remove/{T_ALICE_PRIVATE}/", "remove", task_id=T_ALICE_PRIVATE) == 200
    assert _call_view("admin_acme", f"/analysis/remove/{T_GLOBEX_GROUP}/", "remove", task_id=T_GLOBEX_GROUP) == 404


# ===========================================================================
# 3. Live Visibility Toggle CAS Across SQL, MongoDB, and Elasticsearch
# ===========================================================================
def test_live_visibility_toggle_updates_sql_mongo_and_es_atomically(multicompany_env):
    def _mongo_update_one(coll: str, flt: dict, update: dict) -> None:
        assert coll == "analysis"
        for doc in multicompany_env.mongo_docs.values():
            if _eval_mongo_query(doc, flt):
                for k, v in update.get("$set", {}).items():
                    _, subkey = k.split(".", 1)
                    doc["info"][subkey] = v

    def _es_update_by_query(query: dict, script: dict) -> None:
        params = script["params"]
        for hit in multicompany_env.es_docs.values():
            src = hit["_source"]
            if _eval_es_clause(src, query):
                src["info"].update(params["stamp"])

    frank_viewer = default_viewer_resolver(multicompany_env.users["frank_ir_only"])
    dave_viewer = default_viewer_resolver(multicompany_env.users["dave_soc"])
    bob_viewer = default_viewer_resolver(multicompany_env.users["bob_globex"])

    # Initially, Frank cannot see T_ALICE_PRIVATE
    assert T_ALICE_PRIVATE not in multicompany_env.query_sql_visible(frank_viewer)
    assert T_ALICE_PRIVATE not in multicompany_env.query_mongo_visible(frank_viewer)
    assert T_ALICE_PRIVATE not in multicompany_env.query_es_visible(frank_viewer)

    # Alice toggles T_ALICE_PRIVATE (in G_ACME_IR) from PRIVATE -> TENANT ("groups")
    with multicompany_env.SessionLocal() as session:
        stamp = toggle_task_visibility_cas(
            session,
            T_ALICE_PRIVATE,
            TENANT,
            expected_prior=PRIVATE,
            mongo_update_one=_mongo_update_one,
            es_update_by_query=_es_update_by_query,
        )
    assert stamp.visibility == TENANT
    assert stamp.visibility_seq == 2

    # Now Frank (also in G_ACME_IR) immediately sees T_ALICE_PRIVATE in SQL, Mongo, and ES!
    assert T_ALICE_PRIVATE in multicompany_env.query_sql_visible(frank_viewer)
    assert T_ALICE_PRIVATE in multicompany_env.query_mongo_visible(frank_viewer)
    assert T_ALICE_PRIVATE in multicompany_env.query_es_visible(frank_viewer)

    # Meanwhile Dave (Acme SOC, not in Acme IR) and Bob (Globex) still cannot see it!
    assert T_ALICE_PRIVATE not in multicompany_env.query_sql_visible(dave_viewer)
    assert T_ALICE_PRIVATE not in multicompany_env.query_mongo_visible(dave_viewer)
    assert T_ALICE_PRIVATE not in multicompany_env.query_es_visible(dave_viewer)
    assert T_ALICE_PRIVATE not in multicompany_env.query_sql_visible(bob_viewer)

    # Acme Admin toggles T_ACME_IR_DEPT from TENANT -> PRIVATE: Alice loses access, Frank (owner) keeps it
    alice_viewer = default_viewer_resolver(multicompany_env.users["alice_ir"])
    with multicompany_env.SessionLocal() as session:
        toggle_task_visibility_cas(
            session,
            T_ACME_IR_DEPT,
            PRIVATE,
            expected_prior=TENANT,
            mongo_update_one=_mongo_update_one,
            es_update_by_query=_es_update_by_query,
        )
    assert T_ACME_IR_DEPT not in multicompany_env.query_sql_visible(alice_viewer)
    assert T_ACME_IR_DEPT not in multicompany_env.query_mongo_visible(alice_viewer)
    assert T_ACME_IR_DEPT not in multicompany_env.query_es_visible(alice_viewer)
    assert T_ACME_IR_DEPT in multicompany_env.query_sql_visible(frank_viewer)


# ===========================================================================
# 4. Per-Company & Per-Department Sandbox Resource Entitlements
# ===========================================================================
def test_per_company_and_department_vm_route_tag_and_timeout_entitlements(multicompany_env):
    all_machines = [
        types.SimpleNamespace(name="acme-win10", label="acme-win10"),
        types.SimpleNamespace(name="acme-ir-forensics", label="acme-ir-forensics"),
        types.SimpleNamespace(name="acme-soc-triage", label="acme-soc-triage"),
        types.SimpleNamespace(name="globex-win11", label="globex-win11"),
        types.SimpleNamespace(name="initech-linux", label="initech-linux"),
    ]
    all_routes = ["vpn-acme", "vpn-acme-ir", "vpn-acme-soc", "vpn-globex", "tor"]

    # 1. Alice (Acme IR + inherits Acme Corp + Joint Intel):
    #    Gets union of Acme Corp VMs + Acme IR forensics VM, but NOT Acme SOC VM or Globex/Initech VMs!
    alice_ent = resolve_user_entitlements(multicompany_env.users["alice_ir"])
    set_current_entitlements(alice_ent)
    assert [m.name for m in default_machine_list_filter(all_machines)] == ["acme-win10", "acme-ir-forensics"]
    assert default_route_list_filter(all_routes) == ["vpn-acme", "vpn-acme-ir"]
    assert default_tag_list_filter(["acme", "ir", "intel", "soc", "globex"]) == ["acme", "ir", "intel"]

    # Alice cannot submit to Globex's VM or Acme SOC's VM
    ok, err, _ = validate_and_normalize_submission({"machine": "globex-win11", "route": "vpn-acme"}, alice_ent)
    assert not ok and "globex-win11" in err
    ok, err, _ = validate_and_normalize_submission({"machine": "acme-soc-triage", "route": "vpn-acme"}, alice_ent)
    assert not ok and "acme-soc-triage" in err

    # Alice's timeout is capped to max(180, 240) = 240
    ok, _, norm = validate_and_normalize_submission(
        {"machine": "acme-ir-forensics", "route": "vpn-acme-ir", "timeout": 999}, alice_ent
    )
    assert ok and int(norm["timeout"]) == 240

    # 2. Bob (Globex): only sees globex-win11 and vpn-globex; route="none" is denied
    bob_ent = resolve_user_entitlements(multicompany_env.users["bob_globex"])
    set_current_entitlements(bob_ent)
    assert [m.name for m in default_machine_list_filter(all_machines)] == ["globex-win11"]
    assert default_route_list_filter(all_routes) == ["vpn-globex"]
    ok, err, _ = validate_and_normalize_submission({"machine": "globex-win11", "route": "none"}, bob_ent)
    assert not ok

    # 3. Submission form context filtering strips unauthorized VMs and routes
    ctx = {
        "machines": list(all_machines),
        "vpns": [{"name": r} for r in all_routes],
        "tags": ["acme", "globex", "initech"],
    }
    default_submission_context_filter(ctx, bob_ent)
    assert [m.name for m in ctx["machines"]] == ["globex-win11"]
    assert [v["name"] for v in ctx["vpns"]] == ["vpn-globex"]
    assert ctx["tags"] == ["globex"]


# ===========================================================================
# 5. Regression Tests for All 8 GitHub Copilot Review Findings
# ===========================================================================
def test_copilot_1_es_own_report_matches_exact_id(monkeypatch):
    """own_report_es_query uses exact term filter on info.id, and is_task_own_report checks info.id."""
    from lib.tenancy.hooks import is_task_own_report, register_core_hooks

    monkeypatch.setattr(
        "lib.tenancy.hooks.multitenancy_config",
        lambda: MultitenancyConfig(
            enabled=True,
            mode="locked",
            default_visibility=PRIVATE,
            local_admins_manage_all_tenants=True,
        ),
    )
    register_core_hooks()
    try:
        es_q = own_report_es_query(5)
        own_doc = {"info": {"id": 5}}
        foreign_doc = {"info": {"id": 50}}

        assert _eval_es_clause(own_doc, es_q)
        assert not _eval_es_clause(foreign_doc, es_q)
        assert is_task_own_report(5, own_doc)
        assert not is_task_own_report(5, foreign_doc)
    finally:
        core_hooks.clear_all_hooks()


def test_copilot_2_reconcile_es_stamps_raises_on_bulk_item_errors(multicompany_env):
    """Copilot #2: `reconcile_es_stamps` must raise when `bulk_update` returns per-item errors."""
    from lib.tenancy.backfill import reconcile_es_stamps

    docs = [
        {
            "_index": "cape-analysis-2026.11.01",
            "_id": "es-1001",
            "_source": {"info": {"id": T_ACME_CORP_SHARED, "visibility": PUBLIC, "visibility_seq": 0}},
        }
    ]
    with multicompany_env.SessionLocal() as session:
        with pytest.raises(RuntimeError, match="Elasticsearch bulk restamp failed"):
            reconcile_es_stamps(
                session,
                scan=lambda: docs,
                bulk_update=lambda ops: (0, [{"update": {"_id": "es-1001", "status": 403}}]),
            )


def test_copilot_3_unassigned_superuser_denied_when_local_admins_do_not_manage_all_tenants(monkeypatch):
    """Copilot #3: When `local_admins_manage_all_tenants = no`, an unassigned superuser must be
    denied in locked mode just like any other unassigned user."""
    cfg = MultitenancyConfig(
        enabled=True,
        mode="locked",
        default_visibility=PRIVATE,
        local_admins_manage_all_tenants=False,
    )
    monkeypatch.setattr("lib.tenancy.resources.multitenancy_config", lambda: cfg)
    scoped_super = _make_user(U_SCOPED_SUPER, "scoped_super", [], is_superuser=True, is_staff=True)
    ent = resolve_user_entitlements(scoped_super)
    assert not ent.unrestricted
    assert ent.allowed_machines == frozenset()
    ok, _, _ = validate_and_normalize_submission({"machine": "acme-win10"}, ent)
    assert not ok


def test_copilot_4_and_5_es_and_mongo_reporters_skip_resync_for_renumbered_bridge_reports(monkeypatch):
    """Copilot #4 & #5: Reports carrying `info.local_task_id` (renumbered object-storage bridge
    reports) must not resync against the worker's local database, and local ES resync refreshes first."""
    from lib.tenancy.hooks import _resync_local_acl_stamp

    called = []
    monkeypatch.setattr("lib.tenancy.hooks._resync_retrieved_report", lambda tid: called.append(tid))

    # Bridge report has local_task_id=7, info.id=100, main_task_id=None -> must skip local resync
    _resync_local_acl_stamp({"info": {"id": 100, "local_task_id": 7}}, main_task_id=None)
    assert called == []

    # True local report (no main_task_id, no local_task_id) -> runs local resync
    _resync_local_acl_stamp({"info": {"id": 100}}, main_task_id=None)
    assert called == [100]


def test_copilot_6_and_7_perform_search_avoids_info_path_collision_and_preserves_custom_projection(monkeypatch):
    """MongoDB 4.4+ compatible `$lookup` (no `pipeline` alongside `localField`/`foreignField`),
    post-join `$match` before `$limit`, and caller custom `$project`."""
    import lib.cuckoo.common.web_utils as wu

    seen_pipelines: List[List[Dict[str, Any]]] = []
    monkeypatch.setattr(wu.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(wu, "mongo_aggregate", lambda coll, pipe, **kw: (seen_pipelines.append(pipe), [])[1], raising=False)

    core_hooks.register_mongo_filter(
        lambda coll, q: {**q, "info.tenant_id": G_ACME_IR} if coll == "analysis" else q
    )
    try:
        wu.perform_search("sha256", "a" * 64, privs=False, user_id=U_ALICE_IR)
        default_pipe = seen_pipelines[-1]
        lookup_stage = next(s["$lookup"] for s in default_pipe if "$lookup" in s)
        assert "pipeline" not in lookup_stage
        assert lookup_stage["localField"] == "_id"
        assert lookup_stage["foreignField"] == "info.id"
        assert {"$match": {"info.tenant_id": G_ACME_IR}} in default_pipe

        custom_proj = {"target.file.sha256": 1, "info.id": 1}
        wu.perform_search("sha256", "a" * 64, projection=custom_proj, privs=False, user_id=U_ALICE_IR)
        custom_pipe = seen_pipelines[-1]
        assert custom_pipe[-1] == {"$project": {**custom_proj, f"target.file.{wu.FILE_REF_KEY}": 1}}
        assert custom_proj == {"target.file.sha256": 1, "info.id": 1}
    finally:
        core_hooks.clear_all_hooks()


def test_tightening_toggle_restamps_after_commit_and_storage_file_nl_login_gate(multicompany_env, monkeypatch):
    """Tightening `toggle_task_visibility_cas` restamps stores both before and after `session.commit()`,
    and `_check_storage_view_login_required` enforces login on `file_nl` when `WEB_AUTHENTICATION=True`."""
    from lib.tenancy.views import _check_storage_view_login_required

    mongo_calls = []
    with multicompany_env.SessionLocal() as session:
        toggle_task_visibility_cas(
            session,
            T_INITECH_PUBLIC,
            PRIVATE,
            expected_prior=PUBLIC,
            mongo_update_one=lambda col, flt, upd: mongo_calls.append(upd["$set"]["info.visibility"]),
        )
    # Tightening PUBLIC -> PRIVATE stamps before commit AND restamps after commit
    assert mongo_calls == [PRIVATE, PRIVATE]

    from django.conf import settings

    monkeypatch.setattr(settings, "WEB_AUTHENTICATION", True, raising=False)
    monkeypatch.setattr(settings, "ANON_VIEW", False, raising=False)
    anon_req = types.SimpleNamespace(
        user=types.SimpleNamespace(is_authenticated=False),
        get_full_path=lambda: "/analysis/1/file_nl/dropped/abc/",
    )
    resp = _check_storage_view_login_required(anon_req, "file_nl")
    assert resp is not None and getattr(resp, "status_code", None) == 302


def test_mongo_delete_data_preserves_shared_file_refs_and_reconcile_cli_handles_rowless_public(
    multicompany_env, monkeypatch, capsys
):
    """`mongo_delete_data` skips `clean_UnusedFile_on_mongodb_delete` when another report shares `info.id`,
    and `tenancy_reconcile.py` exits 3 on rowless public reports unless `--adopt-public-from-reports` or `--demote-public`."""
    import dev_utils.mongodb as mongo_mod
    from lib.tenancy.backfill import reconcile_mongo_stamps
    from lib.tenancy.hooks import register_core_hooks

    monkeypatch.setattr(
        "lib.tenancy.hooks.multitenancy_config",
        lambda: MultitenancyConfig(
            enabled=True,
            mode="locked",
            default_visibility=PRIVATE,
            local_admins_manage_all_tenants=True,
        ),
    )
    register_core_hooks()

    remaining_docs = [{"_id": "broker-doc"}]
    cleaned_tids: List[int] = []
    deleted_calls: List[Any] = []
    monkeypatch.setattr(
        mongo_mod,
        "mongo_find",
        lambda coll, q, proj=None, **kw: [{"_id": "own-doc", "info": {"id": 55}, "behavior": {"processes": [{"calls": ["c1"]}]}}],
    )
    monkeypatch.setattr(mongo_mod, "mongo_delete_many", lambda coll, q: True)
    monkeypatch.setattr(mongo_mod, "mongo_delete_calls", lambda task_ids: deleted_calls.append(list(task_ids)))
    monkeypatch.setattr(
        mongo_mod,
        "mongo_find_one",
        lambda coll, q, proj=None, **kw: remaining_docs[0] if remaining_docs else None,
    )
    monkeypatch.setitem(mongo_mod.hooks[mongo_mod.mongo_delete_data], "analysis", [lambda tids: cleaned_tids.extend(tids)])

    # 1. Another analysis doc still shares info.id=55 -> do NOT clean shared files or call chunks by info.id
    mongo_mod.mongo_delete_data(55)
    assert cleaned_tids == []
    assert deleted_calls == []

    # 2. No remaining analysis doc shares info.id=55 -> cleans orphaned calls and runs unused-file hook
    remaining_docs.clear()
    mongo_mod.mongo_delete_data(55)
    assert cleaned_tids == [55]
    assert deleted_calls == [[55]]

    # 3. Reconcile adopts rowless public reports into task_acl when adopt_public_without_acl=True
    raw_docs = [{"_id": "m1", "info": {"id": 8888, "visibility": PUBLIC, "tenant_id": None, "user_id": 11, "visibility_seq": 1}}]
    with multicompany_env.SessionLocal() as session:
        unrec: List[int] = []
        changed = reconcile_mongo_stamps(
            session,
            find=lambda c, q, p: iter(raw_docs),
            bulk_update=lambda c, ops: len(ops),
            abort_on_unrecorded_public=True,
            unrecorded_public=unrec,
            task_owners=lambda ids: {8888: 11},
        )
        assert changed == 0
        assert unrec == [8888]
        assert session.get(TaskAcl, 8888) is None

        changed_adopt = reconcile_mongo_stamps(
            session,
            find=lambda c, q, p: iter(raw_docs),
            bulk_update=lambda c, ops: len(ops),
            preserve_public_without_acl=True,
            adopt_public_without_acl=True,
            task_owners=lambda ids: {8888: 11},
        )
        assert changed_adopt == 0
        adopted = session.get(TaskAcl, 8888)
        assert adopted is not None and adopted.visibility == PUBLIC and adopted.user_id == 11


def test_gcs_refetch_banned_inherits_source_scope_and_rebinds_dist(db, temp_pe32, monkeypatch):
    from pathlib import Path
    import sys

    from sqlalchemy.orm import Session

    import lib.cuckoo.common.gcp as gcp_mod
    from lib.cuckoo.core.data.task import TASK_BANNED, Task
    from lib.tenancy import hooks as thooks

    cfg = MultitenancyConfig(
        enabled=True, mode="shared", default_visibility="public", local_admins_manage_all_tenants=True
    )
    monkeypatch.setattr(thooks, "multitenancy_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.policy.multitenancy_config", lambda: cfg)
    monkeypatch.setenv("CAPE_AS_ROOT", "1")
    monkeypatch.setattr(gcp_mod, "HAVE_GCP", True)
    pe_bytes = Path(temp_pe32).read_bytes()
    monkeypatch.setattr(gcp_mod, "download_from_gcs", lambda uri, dst: Path(dst).write_bytes(pe_bytes) or True)

    core_hooks.clear_all_hooks()
    fake_dist = types.ModuleType("fake_dist_refetch")
    fake_dist.gcs_refetch_banned = gcp_mod.gcs_refetch_banned
    monkeypatch.setitem(sys.modules, "fake_dist_refetch", fake_dist)
    ensure_acl_schema(db.engine)
    try:
        thooks.register_core_hooks()
        assert fake_dist.gcs_refetch_banned is gcp_mod.gcs_refetch_banned
        assert getattr(fake_dist.gcs_refetch_banned, "_cape_tenancy_wrapped", False)

        set_current_viewer(ViewerContext(user_id=8, is_authenticated=True, tenant_id=2, tenant_ids=frozenset({2})))
        set_current_submission_visibility("private")
        src_tid = db.add_path(str(temp_pe32), user_id=8)
        with db.session.begin():
            t = db.session.get(Task, src_tid)
            t.status = TASK_BANNED
        set_current_viewer(None)
        set_current_submission_visibility(None)

        fake_dist.gcs_refetch_banned("1d", samples_bucket="test-bucket")
        with Session(db.engine) as s:
            all_tasks = s.query(Task).order_by(Task.id).all()
            assert len(all_tasks) == 2
            new_tid = all_tasks[-1].id
            assert new_tid != src_tid
            acl = s.get(TaskAcl, new_tid)
            assert acl is not None
            assert (acl.user_id, acl.tenant_id, acl.visibility) == (8, 2, "private")
    finally:
        core_hooks.clear_all_hooks()


def test_reprocess_tenant_id_does_not_revert_concurrent_visibility_tightening(tmp_path, monkeypatch):
    import sqlalchemy as sa
    from sqlalchemy.orm import Session

    from lib.tenancy import hooks as thooks

    cfg = MultitenancyConfig(
        enabled=True, mode="shared", default_visibility="public", local_admins_manage_all_tenants=True
    )
    monkeypatch.setattr(thooks, "multitenancy_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.policy.multitenancy_config", lambda: cfg)

    engine = sa.create_engine(f"sqlite:///{tmp_path}/reproc_race.db")
    ensure_acl_schema(engine)
    with Session(engine) as s:
        set_task_acl(s, 15, user_id=8, tenant_id=2, visibility="public")
        s.commit()

    orig_set_acl = thooks.set_task_acl

    def _set_acl_after_concurrent_toggle(session, task_id, **kw):
        # Simulate a concurrent toggle tightening task 15 to private right before set_task_acl locks it
        with Session(engine) as concurrent_session:
            toggle_task_visibility_cas(concurrent_session, int(task_id), "private")
        return orig_set_acl(session, task_id, **kw)

    monkeypatch.setattr(thooks, "set_task_acl", _set_acl_after_concurrent_toggle)
    monkeypatch.setattr(
        "lib.cuckoo.core.database.Database",
        lambda: types.SimpleNamespace(engine=engine, session=Session(engine)),
    )

    task_dict = {"id": 15, "attributes": {}}
    results = {"info": {"id": 15, "user_id": 8}}
    thooks.default_report_stamp_hook(
        results, task=task_dict, db=types.SimpleNamespace(engine=engine), tenant_id=5, stage="process"
    )
    with Session(engine) as s:
        row = s.get(TaskAcl, 15)
        assert (row.user_id, row.tenant_id, row.visibility) == (8, 5, "private")
    assert (results["info"]["tenant_id"], results["info"]["visibility"]) == (5, "private")


def test_ensure_tenancy_indexes_and_check_file_uniq_utc(db, temp_pe32, monkeypatch):
    import os
    import time

    import dev_utils.mongodb as dm
    from lib.tenancy import hooks as thooks

    # 1. _ensure_tenancy_indexes passes collection name "analysis" (not Collection object)
    created_indexes = []

    class _FakeAnalysisColl:
        def create_index(self, index, background=True, name=False):
            created_indexes.append((index, background, name))

    cfg = MultitenancyConfig(
        enabled=True, mode="shared", default_visibility="private", local_admins_manage_all_tenants=True
    )
    monkeypatch.setattr(thooks, "multitenancy_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.policy.multitenancy_config", lambda: cfg)
    monkeypatch.setattr(thooks, "_tenancy_indexes_ready", False)
    monkeypatch.setattr(dm, "results_db", types.SimpleNamespace(analysis=_FakeAnalysisColl()))
    thooks._ensure_tenancy_indexes()
    assert len(created_indexes) == 3
    assert thooks._tenancy_indexes_ready is True

    # 2. _wrapped_check_uniq uses UTC even when local timezone is ahead of UTC (e.g. Etc/GMT-5 = UTC+5)
    ensure_acl_schema(db.engine)
    core_hooks.clear_all_hooks()
    try:
        thooks.register_core_hooks()
        set_current_viewer(ViewerContext(user_id=8, is_authenticated=True, tenant_id=2, tenant_ids=frozenset({2})))
        tid = db.add_path(str(temp_pe32), user_id=8)
        sha256 = db.view_sample(db.view_task(tid).sample_id).sha256
        old_tz = os.environ.get("TZ")
        os.environ["TZ"] = "Etc/GMT-5"
        if hasattr(time, "tzset"):
            time.tzset()
        try:
            with db.session.begin():
                assert db.check_file_uniq(sha256, hours=1) is True
        finally:
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            if hasattr(time, "tzset"):
                time.tzset()
    finally:
        set_current_viewer(None)
        core_hooks.clear_all_hooks()


def test_dist_worker_reprocess_preserves_newer_existing_report_stamp(monkeypatch):
    """When a dist/bridged worker reprocesses a task whose main_task_id has a newer stamp in Mongo/ES,
    default_report_stamp_hook preserves the newer stamp across process, mongodb, and elasticsearchdb stages.
    """
    from lib.tenancy import hooks as thooks

    cfg = MultitenancyConfig(
        enabled=True, mode="shared", default_visibility="private", local_admins_manage_all_tenants=True
    )
    monkeypatch.setattr(thooks, "multitenancy_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.policy.multitenancy_config", lambda: cfg)

    import dev_utils.mongodb as mongo_mod

    mongo_docs = {
        100: {
            "_id": "doc100",
            "info": {
                "id": 100,
                "job_id": None,
                "user_id": 7,
                "tenant_id": 3,
                "visibility": "private",
                "visibility_seq": 2,
            },
        }
    }

    def _mock_mongo_find_one(collection, query, proj=None, **kw):
        if collection == "analysis":
            q_id = query.get("info.id")
            if q_id == 100:
                doc = mongo_docs.get(100)
                if doc:
                    if isinstance(proj, dict):
                        projected_info = {}
                        for k, v in doc["info"].items():
                            if proj.get(f"info.{k}"):
                                projected_info[k] = v
                        return {"_id": doc["_id"], "info": projected_info}
                    return dict(doc)
        return None

    monkeypatch.setattr(mongo_mod, "mongo_find_one", _mock_mongo_find_one)

    task = {
        "id": 5,
        "attributes": {
            "main_task_id": 100,
            "task_acl": {
                "user_id": 7,
                "tenant_id": 3,
                "visibility": "public",
                "visibility_seq": 1,
            },
        },
    }

    # 1. stage="process"
    results_process = {"info": {"id": 100}}
    thooks.default_report_stamp_hook(results_process, task=task, stage="process")
    assert results_process["info"]["visibility"] == "private"
    assert results_process["info"]["visibility_seq"] == 2
    assert results_process["info"]["user_id"] == 7
    assert results_process["info"]["tenant_id"] == 3
    assert task.get("_existing_remote_acl", {}).get("visibility_seq") == 2

    # Simulate mongodb deleting and replacing the document during reprocess
    mongo_docs.clear()

    # 2. stage="mongodb" (cached _existing_remote_acl retains the newer stamp)
    results_mongo = {"info": {"id": 100}}
    thooks.default_report_stamp_hook(results_mongo, task=task, stage="mongodb")
    assert results_mongo["info"]["visibility"] == "private"
    assert results_mongo["info"]["visibility_seq"] == 2

    # 3. stage="elasticsearchdb"
    results_es = {"info": {"id": 100}}
    thooks.default_report_stamp_hook(results_es, task=task, stage="elasticsearchdb")
    assert results_es["info"]["visibility"] == "private"
    assert results_es["info"]["visibility_seq"] == 2


def test_dist_worker_reprocess_colliding_foreign_broker_doc_ignored(monkeypatch):
    """Verify that a foreign report doc with a different info.id is ignored by
    _lookup_existing_report_stamp and does NOT overwrite task 100's stamp.
    """
    from lib.tenancy import hooks as thooks

    cfg = MultitenancyConfig(
        enabled=True, mode="shared", default_visibility="private", local_admins_manage_all_tenants=True
    )
    monkeypatch.setattr(thooks, "multitenancy_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.policy.multitenancy_config", lambda: cfg)

    import dev_utils.mongodb as mongo_mod

    foreign_no_seq = {
        "_id": "foreign-1",
        "info": {"id": 100, "job_id": "broker-other", "user_id": 99, "tenant_id": 99, "visibility": "public"},
    }
    own_doc = {
        "_id": "own-2",
        "info": {
            "id": 100,
            "user_id": 7,
            "tenant_id": 3,
            "visibility": "private",
            "visibility_seq": 2,
        },
    }

    def _mock_mongo_find(collection, query, proj=None, **kw):
        if collection == "analysis" and query.get("info.id") == 100:
            return [dict(foreign_no_seq), dict(own_doc)]
        return []

    monkeypatch.setattr(mongo_mod, "mongo_find", _mock_mongo_find)

    class _MockES:
        def search(self, index, body=None, **kw):
            return {
                "hits": {
                    "hits": [
                        {
                            "_id": "es-other",
                            "_source": {
                                "info": {
                                    "id": 999,
                                    "user_id": 99,
                                    "tenant_id": 99,
                                    "visibility": "public",
                                    "visibility_seq": 99,
                                }
                            },
                        },
                        {
                            "_id": "es-own",
                            "_source": {
                                "info": {
                                    "id": 100,
                                    "user_id": 7,
                                    "tenant_id": 3,
                                    "visibility": "private",
                                    "visibility_seq": 2,
                                }
                            },
                        },
                    ]
                }
            }

    import modules.reporting.elasticsearchdb as es_mod

    monkeypatch.setattr(es_mod, "elastic_handler", _MockES(), raising=False)
    monkeypatch.setattr(es_mod, "get_analysis_index", lambda: "cape-analysis", raising=False)

    stamp = thooks._lookup_existing_report_stamp(100)
    assert stamp is not None
    assert stamp["visibility"] == "private"
    assert stamp["visibility_seq"] == 2
    assert stamp["user_id"] == 7
    assert stamp["tenant_id"] == 3

    task = {
        "id": 5,
        "attributes": {
            "main_task_id": 100,
            "task_acl": {
                "user_id": 7,
                "tenant_id": 3,
                "visibility": "public",
                "visibility_seq": 1,
            },
        },
    }
    report = {"info": {"id": 100}}
    thooks.default_report_stamp_hook(report, task=task, stage="mongodb")
    assert report["info"]["visibility"] == "private"
    assert report["info"]["visibility_seq"] == 2
    assert report["info"]["user_id"] == 7
    assert report["info"]["tenant_id"] == 3


def test_dist_worker_reprocess_older_or_absent_existing_report_uses_snapshot(monkeypatch):
    """When existing report in MongoDB has older or equal seq, or when no existing report exists yet,
    the dispatch task_acl snapshot is used as before.
    """
    from lib.tenancy import hooks as thooks

    cfg = MultitenancyConfig(
        enabled=True, mode="shared", default_visibility="private", local_admins_manage_all_tenants=True
    )
    monkeypatch.setattr(thooks, "multitenancy_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.policy.multitenancy_config", lambda: cfg)

    import dev_utils.mongodb as mongo_mod

    # 1. Existing report in Mongo has older or equal seq (seq=1) vs dispatch task_acl (seq=1)
    existing_doc = {
        "_id": "doc100",
        "info": {
            "id": 100,
            "job_id": None,
            "user_id": 7,
            "tenant_id": 3,
            "visibility": "public",
            "visibility_seq": 1,
        },
    }

    def _mock_find_one_older(coll, q, proj=None, **kw):
        if isinstance(proj, dict):
            p_info = {k: v for k, v in existing_doc["info"].items() if proj.get(f"info.{k}")}
            return {"_id": existing_doc["_id"], "info": p_info}
        return dict(existing_doc)

    monkeypatch.setattr(mongo_mod, "mongo_find_one", _mock_find_one_older)

    task = {
        "id": 5,
        "attributes": {
            "main_task_id": 100,
            "task_acl": {
                "user_id": 7,
                "tenant_id": 3,
                "visibility": "public",
                "visibility_seq": 1,
            },
        },
    }
    results = {"info": {"id": 100}}
    thooks.default_report_stamp_hook(results, task=task, stage="process")
    assert results["info"]["visibility"] == "public"
    assert results["info"]["visibility_seq"] == 1
    assert results["info"]["user_id"] == 7
    assert results["info"]["tenant_id"] == 3

    # 2. No existing report exists yet (normal first-time worker run)
    monkeypatch.setattr(mongo_mod, "mongo_find_one", lambda coll, q, proj=None, **kw: None)

    task_first = {
        "id": 6,
        "attributes": {
            "main_task_id": 101,
            "task_acl": {
                "user_id": 10,
                "tenant_id": 4,
                "visibility": "tenant",
                "visibility_seq": 1,
            },
        },
    }
    results_first = {"info": {"id": 101}}
    thooks.default_report_stamp_hook(results_first, task=task_first, stage="process")
    assert results_first["info"]["visibility"] == "tenant"
    assert results_first["info"]["visibility_seq"] == 1
    assert results_first["info"]["user_id"] == 10
    assert results_first["info"]["tenant_id"] == 4
