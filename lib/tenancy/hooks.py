"""Data-layer, object-storage, and sandbox resource hooks for MongoDB, SQLAlchemy Tasking, Elasticsearch, and VMs/Routes/Tags.

When `lib.tenancy` is active, these hooks automatically merge the active
request's `ViewerContext` and `ResourceEntitlements` filters into:
- MongoDB `"analysis"` queries (`mongo_find`, `mongo_find_one`, `mongo_aggregate`, `mongo_delete_data`)
- SQLAlchemy task list/count queries (`TaskAcl` outer-join / filter)
- Elasticsearch search queries (`viewer_scope_es_filter`)
- Sandbox VM (`list_machines`), tag (`load_vms_tags`), route/exitnode (`load_vms_exits`),
  and submission UI context (`submission/index.html`) discovery surfaces
- Worker report stamping (`TaskAcl` / `dist.py` env vars + `[object_storage]` artifact upload).
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import json
import logging
import os
import re
import sys
from typing import Any, Callable, Dict, Iterable, List, MutableMapping, Optional

from sqlalchemy import or_

from lib.tenancy.acl import TaskAcl, ensure_acl_schema_once, resolve_task_scope, set_task_acl
from lib.tenancy.context import (
    get_current_entitlements,
    get_current_submission_visibility,
    get_current_viewer,
)
from lib.tenancy.policy import (
    PRIVATE,
    PUBLIC,
    TENANT,
    VISIBILITIES,
    ResourceScope,
    ViewerContext,
    default_visibility as resolve_default_visibility,
    multitenancy_config,
    viewer_scope_es_filter,
    viewer_scope_match,
)
from lib.tenancy.resources import (
    ResourceEntitlements,
    filter_submission_form_context,
    machine_name_by_label,
    validate_and_normalize_submission,
)

log = logging.getLogger(__name__)

# Scope of the task being rescheduled, read by the wrapped `add` that creates its copy.
_rescheduled_from: contextvars.ContextVar[Optional[ResourceScope]] = contextvars.ContextVar(
    "cape_tenancy_rescheduled_from", default=None
)


# Set by the wrapped reschedule: whether the wrapped add refused the copy.
_copy_denied: contextvars.ContextVar[Optional[list]] = contextvars.ContextVar("cape_tenancy_copy_denied", default=None)


@contextlib.contextmanager
def inherit_task_scope(db: Any, task_id: Any):
    """Make tasks added in this block copies of `task_id`: same owner, tenant and visibility.

    Copies (reschedule, banned-task refetch) are added outside any submission, so `add` would
    otherwise stamp the deployment default. Fails closed to owner-only when the scope is unreadable.
    """
    src_scope = ResourceScope(owner_id=None, tenant_id=None, visibility=PRIVATE)
    sess = getattr(db, "session", None)
    raw = sess() if callable(sess) else sess  # the scoped_session proxy has no in_transaction()
    if raw is not None:
        # Inside the caller's transaction (init_tasks) a savepoint keeps a failed read from aborting
        # it on Postgres; otherwise a short transaction of our own, so the reads don't autobegin one
        # that turns every later begin() into a bare flush.
        def _txn():
            return raw.begin_nested() if raw.in_transaction() else raw.begin()

        try:
            with _txn():
                owner_id = getattr(db.view_task(task_id), "user_id", None) or None
            src_scope = ResourceScope(owner_id=owner_id, tenant_id=None, visibility=PRIVATE)
            ensure_acl_schema_once(raw.get_bind())
            with _txn():
                src_scope = resolve_task_scope(raw, int(task_id), fallback_user_id=owner_id)
        except Exception:
            log.exception("tenancy: cannot resolve the scope of task %s; its copy stays owner-only", task_id)
    token = _rescheduled_from.set(src_scope)
    try:
        yield src_scope
    finally:
        _rescheduled_from.reset(token)


def _trusted_submitter() -> bool:
    """Internal callers (no request viewer) and box admins, e.g. a dist node's or broker's account.

    A superuser counts only with `local_admins_manage_all_tenants`; otherwise they are tenant-scoped.
    """
    viewer = get_current_viewer()
    return viewer is None or bool(getattr(viewer, "is_local_admin", False))


# Task objects no VM runs: analysis_manager never schedules a machine or route for them.
_VMLESS_TASK_OBJECTS = ("PCAP", "Static")


def _enforce_task_entitlements(
    kwargs: Dict[str, Any], db: Any = None, *, vmless: bool = False, copy: bool = False
) -> Optional[str]:
    """Check the final `add` kwargs against the request's entitlements; normalize them in place.

    The middleware checks the submitted form early, but API bodies (JSON, re-parsed urlencoded)
    and the views' own rewriting reach `add` unchecked. Returns the denial message, or None.
    """
    ent = get_current_entitlements()
    if ent is None or ent.unrestricted:
        return None
    tags = kwargs.get("tags")
    if isinstance(tags, (list, tuple, set)):
        tags = ",".join(str(t) for t in tags)
    tags = tags or ""
    kept_tags = ""
    if copy and tags:
        # A copy carries the arch tags add() appended to its source; the submitter never chose them.
        parts = [t for t in tags.split(",") if t.strip()]
        kept_tags = ",".join(t for t in parts if t.strip().lower() in ("x86", "x64"))
        tags = ",".join(t for t in parts if t.strip().lower() not in ("x86", "x64"))
    machine = kwargs.get("machine") or ""
    params = {
        "machine": machine,
        "route": kwargs.get("route") or "",
        "tags": tags,
        "timeout": kwargs.get("timeout") or 0,
        "options": kwargs.get("options") or "",
    }
    allowed, err, normalized = validate_and_normalize_submission(
        params, ent, vmless=vmless, machine_name_of=machine_name_by_label(db)
    )
    if not allowed:
        return err or "Submission denied by group policy"
    if normalized.get("route"):
        kwargs["route"] = normalized["route"]
    if normalized.get("tags") != params["tags"] or not isinstance(kwargs.get("tags"), (str, type(None))):
        # add() drops a list of tags, so the checked tags always go back as a string.
        kwargs["tags"] = ",".join(t for t in (normalized.get("tags") or "", kept_tags) if t)
    if str(normalized.get("timeout")) != str(params["timeout"]):
        kwargs["timeout"] = int(normalized["timeout"])
    if normalized.get("options") != params["options"]:
        kwargs["options"] = normalized["options"]
    return None


# Attributes only dist sets when it hands a task to a worker.
_DIST_ONLY_ATTRIBUTES = ("task_acl", "main_task_id", "parent_sample")


def _strip_untrusted_task_acl(attributes: Any) -> Any:
    """Drop the dist-only attributes from submitted attributes unless the submitter is trusted.

    The reporters copy attributes.task_acl into the report and file it under attributes.main_task_id
    (replacing that task's report); from an ordinary API submitter they would be a forged owner,
    visibility and seq, and an overwrite of any other task's report.
    """
    if _trusted_submitter():
        return attributes
    if isinstance(attributes, str):
        try:
            attributes = json.loads(attributes)
        except ValueError:
            return attributes  # add() discards invalid JSON itself
    if isinstance(attributes, dict) and any(k in attributes for k in _DIST_ONLY_ATTRIBUTES):
        attributes = {k: v for k, v in attributes.items() if k not in _DIST_ONLY_ATTRIBUTES}
    return attributes


def _strip_untrusted_broker_job_id(custom: Any) -> Any:
    """Drop a `job_id=` field from `custom` unless the submitter is trusted.

    Object-storage reporting takes the broker job id from it; "job_id=ui-N" renumbers the report
    to task N, stamps it with N's ACL and overwrites N's stored artifacts and Mongo report.
    """
    if not custom or not isinstance(custom, str) or _trusted_submitter():
        return custom
    custom = ",".join(f for f in custom.split(",") if not f.strip().startswith("job_id="))
    if re.match(r"^\s*Recovery_\d+\s*$", custom):
        # A recovered task's custom "Recovery_<id>" sends apiv2's artifact views to task <id>.
        return ""
    if custom and _object_storage_enabled():
        from lib.tenancy.storage.artifact_storage import job_id_from_custom

        if job_id_from_custom(custom) is not None:
            # A bare token is the broker job id too ("local-7" is task 7's job).
            log.warning("tenancy: dropping bare custom %r, which object storage would take as a job id", custom)
            return ""
    return custom


def _object_storage_enabled() -> bool:
    try:
        from lib.tenancy.storage import config as storage_cfg

        return bool(storage_cfg.central_mode_config().enabled)
    except Exception:
        return False


MongoFilterFn = Callable[[str, Dict[str, Any], Optional[ViewerContext]], Dict[str, Any]]
SqlFilterFn = Callable[[Any, Any, Optional[ViewerContext]], Any]
EsFilterFn = Callable[[Dict[str, Any], Optional[ViewerContext]], Dict[str, Any]]

_mongo_filters: List[MongoFilterFn] = []
_sql_filters: List[SqlFilterFn] = []
_es_filters: List[EsFilterFn] = []
_patched_modules: set[str] = set()
_undo_callbacks: List[Callable[[], None]] = []


def _record_attr_patch(target: Any, attr: str, orig_val: Any) -> None:
    _undo_callbacks.append(lambda t=target, a=attr, v=orig_val: setattr(t, a, v))


def _restore_all_wrapped() -> None:
    while _undo_callbacks:
        cb = _undo_callbacks.pop()
        try:
            cb()
        except Exception:
            pass
    _patched_modules.clear()
    _mongo_filters.clear()
    _sql_filters.clear()
    _es_filters.clear()


def default_mongo_analysis_filter(
    collection: str,
    query: Optional[Dict[str, Any]],
    viewer: Optional[ViewerContext] = None,
) -> Dict[str, Any]:
    """Automatically scope queries on the MongoDB `'analysis'` collection to `viewer`."""
    base_query = dict(query) if query else {}
    if collection != "analysis":
        return base_query

    active_viewer = viewer if viewer is not None else get_current_viewer()
    if active_viewer is None:
        return base_query

    scope_pred = viewer_scope_match(active_viewer)
    if scope_pred is None:
        return base_query

    if not base_query:
        return scope_pred
    return {"$and": [base_query, scope_pred]}


def default_es_query_filter(
    body: Dict[str, Any],
    viewer: Optional[ViewerContext] = None,
) -> Dict[str, Any]:
    """Automatically wrap an Elasticsearch query dict with `viewer_scope_es_filter`."""
    active_viewer = viewer if viewer is not None else get_current_viewer()
    if active_viewer is None:
        return body

    es_filter = viewer_scope_es_filter(active_viewer)
    if es_filter is None:
        return body

    existing_query = body.get("query", {"match_all": {}})
    scoped_body = dict(body)
    scoped_body["query"] = {
        "bool": {
            "must": [existing_query],
            "filter": [es_filter],
        }
    }
    return scoped_body


def default_sql_task_acl_clause(
    task_id_col: Any,
    task_user_id_col: Any,
    viewer: Optional[ViewerContext] = None,
) -> Optional[Any]:
    """Build a SQLAlchemy filter clause against `TaskAcl` for `viewer`."""
    active_viewer = viewer if viewer is not None else get_current_viewer()
    if active_viewer is None or active_viewer.see_all:
        return None
    if not active_viewer.is_authenticated:
        return TaskAcl.visibility == PUBLIC

    arms = [TaskAcl.visibility == PUBLIC]
    if active_viewer.user_id is not None:
        arms.append(TaskAcl.user_id == int(active_viewer.user_id))
        arms.append((TaskAcl.task_id.is_(None)) & (task_user_id_col == int(active_viewer.user_id)))
    tids = getattr(active_viewer, "effective_tenant_ids", None)
    if tids is None:
        tid = getattr(active_viewer, "tenant_id", None)
        tids = (int(tid),) if tid is not None else ()
    admin_tids = getattr(active_viewer, "effective_admin_tenant_ids", None)
    if admin_tids is None:
        admin_tids = tids if getattr(active_viewer, "is_tenant_admin", False) else ()
    non_admin_tids = tuple(int(t) for t in tids if t not in admin_tids)
    admin_tids = tuple(int(t) for t in admin_tids)
    if len(non_admin_tids) == 1:
        arms.append((TaskAcl.tenant_id == non_admin_tids[0]) & (TaskAcl.visibility == TENANT))
    elif len(non_admin_tids) > 1:
        arms.append(TaskAcl.tenant_id.in_(list(non_admin_tids)) & (TaskAcl.visibility == TENANT))
    if len(admin_tids) == 1:
        arms.append((TaskAcl.tenant_id == admin_tids[0]) & TaskAcl.visibility.in_((TENANT, PRIVATE)))
    elif len(admin_tids) > 1:
        arms.append(TaskAcl.tenant_id.in_(list(admin_tids)) & TaskAcl.visibility.in_((TENANT, PRIVATE)))
    return or_(*arms)


def default_machine_list_filter(
    machines: Iterable[Any],
    entitlements: Optional[ResourceEntitlements] = None,
) -> List[Any]:
    """Filter a list of `Machine` objects/dicts/tuples according to the active `ResourceEntitlements`."""
    active_ent = entitlements if entitlements is not None else get_current_entitlements()
    if active_ent is None or active_ent.unrestricted:
        return list(machines)
    return active_ent.filter_machines(machines)


def default_tag_list_filter(
    tags: Iterable[Any],
    entitlements: Optional[ResourceEntitlements] = None,
) -> List[Any]:
    """Filter a list of machine tags according to the active `ResourceEntitlements`."""
    active_ent = entitlements if entitlements is not None else get_current_entitlements()
    if active_ent is None or active_ent.unrestricted:
        return list(tags)
    return active_ent.filter_tags(tags)


def default_route_list_filter(
    routes: Iterable[Any],
    route_type: Optional[str] = None,
    *,
    entitlements: Optional[ResourceEntitlements] = None,
) -> List[Any]:
    """Filter a list of route/VPN/exit-node entries according to the active `ResourceEntitlements`."""
    active_ent = entitlements if entitlements is not None else get_current_entitlements()
    if active_ent is None or active_ent.unrestricted:
        return list(routes)
    return active_ent.filter_routes(routes, route_type=route_type)


def default_submission_context_filter(
    context: MutableMapping[str, Any],
    entitlements: Optional[ResourceEntitlements] = None,
) -> MutableMapping[str, Any]:
    """Filter CAPEv2's `submission/index.html` context dict according to the active `ResourceEntitlements`."""
    active_ent = entitlements if entitlements is not None else get_current_entitlements()
    return filter_submission_form_context(context, active_ent)


def register_mongo_filter(fn: MongoFilterFn) -> None:
    if fn not in _mongo_filters:
        _mongo_filters.append(fn)


def register_sql_filter(fn: SqlFilterFn) -> None:
    if fn not in _sql_filters:
        _sql_filters.append(fn)


def register_es_filter(fn: EsFilterFn) -> None:
    if fn not in _es_filters:
        _es_filters.append(fn)


def apply_mongo_filters(
    collection: str,
    query: Optional[Dict[str, Any]],
    viewer: Optional[ViewerContext] = None,
) -> Dict[str, Any]:
    out = dict(query) if query else {}
    for fn in _mongo_filters:
        out = fn(collection, out, viewer)
    return out


def _rebind_from_imports(name: str, replaced: Dict[int, Any]) -> None:
    """Point every loaded module's `name` that is a replaced original at its wrapper."""
    if not replaced:
        return
    for mod in list(sys.modules.values()):
        held = getattr(mod, name, None) if mod is not None else None
        if held is not None and id(held) in replaced:
            _record_attr_patch(mod, name, held)
            setattr(mod, name, replaced[id(held)])


def wrap_mongodb_module(mongodb_mod: Any) -> None:
    """Wrap `dev_utils.mongodb` functions in-place so `'analysis'` queries and deletes are auto-scoped."""
    if getattr(mongodb_mod, "_NATIVE_TENANCY_HOOKS", False):
        if not _mongo_filters:
            register_mongo_filter(default_mongo_analysis_filter)
        return
    mod_id = getattr(mongodb_mod, "__name__", str(id(mongodb_mod)))
    if mod_id in _patched_modules:
        return

    if not _mongo_filters:
        register_mongo_filter(default_mongo_analysis_filter)

    replaced: Dict[int, Any] = {}  # id(original) -> wrapper
    orig_find_raw = getattr(mongodb_mod, "mongo_find", None)
    for fn_name in ("mongo_find", "mongo_find_one"):
        orig = getattr(mongodb_mod, fn_name, None)
        if orig is None or getattr(orig, "_cape_tenancy_wrapped", False):
            continue

        @functools.wraps(orig)
        def _wrapped(collection: str, query: Dict[str, Any], *args: Any, _orig=orig, **kwargs: Any):
            scoped_q = apply_mongo_filters(collection, query)
            return _orig(collection, scoped_q, *args, **kwargs)

        _wrapped._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
        _record_attr_patch(mongodb_mod, fn_name, orig)
        setattr(mongodb_mod, fn_name, _wrapped)
        replaced[id(orig)] = _wrapped

    orig_agg = getattr(mongodb_mod, "mongo_aggregate", None)
    if orig_agg is not None and not getattr(orig_agg, "_cape_tenancy_wrapped", False):

        @functools.wraps(orig_agg)
        def _wrapped_agg(collection: str, pipeline: List[Dict[str, Any]], *args: Any, _orig=orig_agg, **kwargs: Any):
            scoped_q = apply_mongo_filters(collection, {})
            if scoped_q:
                pipeline = [{"$match": scoped_q}] + list(pipeline)
            return _orig(collection, pipeline, *args, **kwargs)

        _wrapped_agg._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
        _record_attr_patch(mongodb_mod, "mongo_aggregate", orig_agg)
        setattr(mongodb_mod, "mongo_aggregate", _wrapped_agg)
        replaced[id(orig_agg)] = _wrapped_agg

    orig_del = getattr(mongodb_mod, "mongo_delete_data", None)
    if orig_del is not None and not getattr(orig_del, "_cape_tenancy_wrapped", False):

        @functools.wraps(orig_del)
        def _wrapped_del(task_ids: Any, *args: Any, _orig=orig_del, **kwargs: Any):
            mt_on = multitenancy_config().enabled
            viewer = get_current_viewer()
            delete_many = getattr(mongodb_mod, "mongo_delete_many", None)
            if (not mt_on and (viewer is None or viewer.see_all)) or orig_find_raw is None or delete_many is None:
                return _orig(task_ids, *args, **kwargs)

            tids = [int(task_ids)] if isinstance(task_ids, int) else [int(t) for t in (task_ids or [])]
            if not tids:
                return None

            from lib.tenancy.acl import own_report_mongo_query

            clauses = [
                apply_mongo_filters("analysis", own_report_mongo_query(tid) if mt_on else {"info.id": tid})
                for tid in tids
            ]
            doc_q = clauses[0] if len(clauses) == 1 else {"$or": clauses}
            proj = {"_id": 1, "info.id": 1, "behavior.processes.calls": 1}
            try:
                docs = list(orig_find_raw("analysis", doc_q, proj, no_hooks=True))
            except TypeError:
                docs = list(orig_find_raw("analysis", doc_q, proj))
            if not docs:
                return None

            call_ids: List[Any] = []
            doc_ids: List[Any] = []
            matched_tids: List[int] = []
            for d in docs:
                if "_id" in d:
                    doc_ids.append(d["_id"])
                tid_val = (d.get("info") or {}).get("id")
                if isinstance(tid_val, int) and tid_val not in matched_tids:
                    matched_tids.append(tid_val)
                for proc in ((d.get("behavior") or {}).get("processes") or []):
                    if isinstance(proc, dict):
                        call_ids.extend(proc.get("calls") or [])
            if call_ids:
                delete_many("calls", {"_id": {"$in": call_ids}})
            if doc_ids:
                delete_many("analysis", {"_id": {"$in": doc_ids}})
            reg = getattr(mongodb_mod, "hooks", None)
            if reg is not None and matched_tids:
                for hook in reg[_wrapped_del]["analysis"]:
                    hook(matched_tids)
            return None

        _wrapped_del._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
        _record_attr_patch(mongodb_mod, "mongo_delete_data", orig_del)
        setattr(mongodb_mod, "mongo_delete_data", _wrapped_del)
        replaced[id(orig_del)] = _wrapped_del

    # Modules imported before this ran (web_utils, via the core hooks) did
    # `from dev_utils.mongodb import mongo_aggregate` and still hold the unscoped originals.
    for name in ("mongo_find", "mongo_find_one", "mongo_aggregate", "mongo_delete_data"):
        _rebind_from_imports(name, replaced)
    # The originals look their result hooks up as hooks[mongo_find], a module global that now
    # names the wrapper: share the registrations (files-collection denormalization) with it.
    registry = getattr(mongodb_mod, "hooks", None)
    if registry is not None:
        for name in ("mongo_find", "mongo_find_one", "mongo_aggregate", "mongo_delete_data"):
            wrapper = getattr(mongodb_mod, name, None)
            for orig_id, new in replaced.items():
                if new is wrapper:
                    for key in list(registry):
                        if id(key) == orig_id:
                            registry[wrapper] = registry[key]
                            _undo_callbacks.append(lambda r=registry, w=wrapper: r.pop(w, None))

    _patched_modules.add(mod_id)


class _ViewerScopedCacheFunction:
    """Stand-in for web_utils.top_detections/top_asn whose `cache` attribute is per viewer scope.

    The originals read and write `<their module global>.cache`, which names this object once it
    replaces them, so each scope (local admins share one) gets its own cached result.
    """

    _cape_tenancy_wrapped = True

    def __init__(self, fn: Callable[..., Any]) -> None:
        functools.update_wrapper(self, fn)
        self.__dict__.pop("cache", None)
        self._orig = fn
        self._caches: Dict[Any, Any] = {}

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._orig(*args, **kwargs)

    @staticmethod
    def _scope() -> Any:
        viewer = get_current_viewer()
        if viewer is None or getattr(viewer, "see_all", False):
            return None
        return (viewer.user_id, tuple(viewer.tenant_ids or ()), tuple(viewer.admin_tenant_ids or ()))

    @property
    def cache(self) -> Any:
        try:
            return self._caches[self._scope()]
        except KeyError:
            raise AttributeError("cache") from None

    @cache.setter
    def cache(self, value: Any) -> None:
        if len(self._caches) >= 256:  # one entry per scope that loaded the dashboard; stay bounded
            self._caches.clear()
        self._caches[self._scope()] = value


def wrap_submission_and_web_utils(
    *,
    machines_cls: Any = None,
    tasking_cls: Any = None,
    web_utils_mod: Any = None,
    submission_views_mod: Any = None,
) -> None:
    """Wrap CAPEv2's machine list, task creation, tag loader, exit-node loader, and submission template render in-place."""
    if tasking_cls is None:
        try:
            from lib.cuckoo.core.data.tasking import TasksMixIn as tasking_cls
        except ImportError:
            tasking_cls = None

    if tasking_cls is not None:
        orig_add = getattr(tasking_cls, "add", None)
        if orig_add is not None and not getattr(orig_add, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_add)
            def _wrapped_task_add(self: Any, *args: Any, _orig=orig_add, **kwargs: Any):
                inherited = _rescheduled_from.get()
                # A copy (reschedule) is checked against the current submitter's entitlements too:
                # the source ran under older ones, or another member's.
                obj = args[0] if args else kwargs.get("obj")
                vmless = type(obj).__name__ in _VMLESS_TASK_OBJECTS
                denied = _enforce_task_entitlements(kwargs, self, vmless=vmless, copy=inherited is not None)
                if denied:
                    log.warning("tenancy: task not added: %s", denied)
                    flag = _copy_denied.get()
                    if flag is not None and inherited is not None:
                        flag[0] = True
                    return None
                if inherited is None:  # a copy keeps its source's fields
                    if kwargs.get("attributes"):
                        kwargs["attributes"] = _strip_untrusted_task_acl(kwargs["attributes"])
                    if kwargs.get("custom"):
                        kwargs["custom"] = _strip_untrusted_broker_job_id(kwargs["custom"])
                if inherited is not None and inherited.owner_id is not None and not kwargs.get("user_id"):
                    kwargs["user_id"] = inherited.owner_id  # tasks.user_id still keys bans and listings
                task_id = _orig(self, *args, **kwargs)
                if task_id:
                    try:
                        viewer = get_current_viewer()
                        ent = get_current_entitlements()
                        sub_vis = get_current_submission_visibility()
                        raw_uid = kwargs.get("user_id")
                        owner_id = (
                            getattr(viewer, "user_id", None)
                            if viewer is not None and getattr(viewer, "user_id", None) is not None
                            else (int(raw_uid) if raw_uid else None)
                        )
                        tenant_id = getattr(viewer, "tenant_id", None) if viewer is not None else None
                        if sub_vis in (PRIVATE, TENANT, PUBLIC):
                            vis = sub_vis
                        elif ent is not None and getattr(ent, "default_visibility", None) in (PRIVATE, TENANT, PUBLIC):
                            vis = ent.default_visibility
                        else:
                            cfg = multitenancy_config()
                            vis = resolve_default_visibility(cfg) if cfg.enabled else (PRIVATE if owner_id else PUBLIC)
                        if vis == TENANT and tenant_id is None:
                            vis = PRIVATE
                        if inherited is not None:
                            owner_id, tenant_id, vis = inherited.owner_id, inherited.tenant_id, inherited.visibility
                        sess = getattr(self, "session", None)
                        if sess is not None and (
                            multitenancy_config().enabled or owner_id is not None or sub_vis is not None
                        ):
                            raw_sess = sess() if callable(sess) else sess
                            bind = getattr(sess, "bind", None) or (
                                raw_sess.get_bind() if hasattr(raw_sess, "get_bind") else None
                            )
                            if raw_sess is not None and hasattr(raw_sess, "in_transaction") and raw_sess.in_transaction():
                                from lib.tenancy.acl import AclBase

                                AclBase.metadata.create_all(raw_sess.connection(), checkfirst=True)
                            elif bind is not None:
                                ensure_acl_schema_once(bind)
                            with sess.begin():
                                set_task_acl(
                                    sess,
                                    int(task_id),
                                    user_id=owner_id,
                                    tenant_id=tenant_id,
                                    visibility=vis,
                                )
                    except Exception:
                        log.exception("tenancy: failed to record TaskAcl for task %s", task_id)
                return task_id

            _wrapped_task_add._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(tasking_cls, "add", orig_add)
            setattr(tasking_cls, "add", _wrapped_task_add)

        orig_reschedule = getattr(tasking_cls, "reschedule", None)
        if orig_reschedule is not None and not getattr(orig_reschedule, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_reschedule)
            def _wrapped_reschedule(self: Any, task_id: Any, *args: Any, _orig=orig_reschedule, **kwargs: Any):
                # reschedule() marks the source recovered before add(); a copy the entitlements
                # refuse must leave the source as it was, not "recovered" with custom Recovery_None.
                try:
                    src = self.view_task(task_id)
                    before = (src.status, src.custom) if src is not None else None
                except Exception:
                    before = None
                denied = _copy_denied.set([False])
                try:
                    with inherit_task_scope(self, task_id):
                        new_id = _orig(self, task_id, *args, **kwargs)
                    if not new_id and _copy_denied.get()[0] and before is not None:
                        from lib.cuckoo.core.data.task import Task

                        row = self.session.get(Task, int(task_id))
                        if row is not None and row.status == "recovered":  # only reschedule's own change
                            row.status, row.custom = before
                    return new_id
                finally:
                    _copy_denied.reset(denied)

            _wrapped_reschedule._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(tasking_cls, "reschedule", orig_reschedule)
            setattr(tasking_cls, "reschedule", _wrapped_reschedule)

    if machines_cls is None:
        try:
            from lib.cuckoo.core.data.machines import MachinesMixIn as machines_cls
        except ImportError:
            machines_cls = None

    if machines_cls is not None and not getattr(machines_cls, "_NATIVE_TENANCY_HOOKS", False):
        orig_list_machines = getattr(machines_cls, "list_machines", None)
        if orig_list_machines is not None and not getattr(orig_list_machines, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_list_machines)
            def _wrapped_list_machines(self: Any, *args: Any, _orig=orig_list_machines, **kwargs: Any):
                res = _orig(self, *args, **kwargs)
                return default_machine_list_filter(res)

            _wrapped_list_machines._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(machines_cls, "list_machines", orig_list_machines)
            setattr(machines_cls, "list_machines", _wrapped_list_machines)

    if web_utils_mod is None:
        try:
            import lib.cuckoo.common.web_utils as web_utils_mod
        except ImportError:
            web_utils_mod = None

    if web_utils_mod is not None and not getattr(web_utils_mod, "_NATIVE_TENANCY_HOOKS", False):
        orig_tags = getattr(web_utils_mod, "load_vms_tags", None)
        if orig_tags is not None and not getattr(orig_tags, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_tags)
            def _wrapped_load_vms_tags(*args: Any, _orig=orig_tags, **kwargs: Any):
                tags = _orig(*args, **kwargs)
                if not tags:
                    return tags
                return sorted(default_tag_list_filter(tags))

            _wrapped_load_vms_tags._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(web_utils_mod, "load_vms_tags", orig_tags)
            setattr(web_utils_mod, "load_vms_tags", _wrapped_load_vms_tags)

        orig_exits = getattr(web_utils_mod, "load_vms_exits", None)
        if orig_exits is not None and not getattr(orig_exits, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_exits)
            def _wrapped_load_vms_exits(*args: Any, _orig=orig_exits, **kwargs: Any):
                exits = _orig(*args, **kwargs)
                if not exits:
                    return exits
                if isinstance(exits, dict):
                    allowed = set(default_route_list_filter(list(exits.keys()), route_type="exit"))
                    return {k: v for k, v in exits.items() if k in allowed}
                return sorted(default_route_list_filter(exits, route_type="exit"))

            _wrapped_load_vms_exits._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(web_utils_mod, "load_vms_exits", orig_exits)
            setattr(web_utils_mod, "load_vms_exits", _wrapped_load_vms_exits)

        # These cache their (now viewer-scoped) aggregation on the function object they look up
        # by their module global, process-wide: give each viewer scope its own cache.
        for cached_name in ("top_detections", "top_asn"):
            orig_cached = getattr(web_utils_mod, cached_name, None)
            if orig_cached is None or getattr(orig_cached, "_cape_tenancy_wrapped", False):
                continue

            scoped = _ViewerScopedCacheFunction(orig_cached)
            _record_attr_patch(web_utils_mod, cached_name, orig_cached)
            setattr(web_utils_mod, cached_name, scoped)
            _rebind_from_imports(cached_name, {id(orig_cached): scoped})

    if submission_views_mod is None:
        try:
            import submission.views as submission_views_mod  # type: ignore[import-not-found]
        except Exception:
            try:
                import web.submission.views as submission_views_mod  # type: ignore[import-not-found]
            except Exception:
                submission_views_mod = None

    if submission_views_mod is not None and not getattr(submission_views_mod, "_NATIVE_TENANCY_HOOKS", False):
        if web_utils_mod is not None:
            for helper_name in ("load_vms_tags", "load_vms_exits"):
                if hasattr(submission_views_mod, helper_name) and hasattr(web_utils_mod, helper_name):
                    cur_helper = getattr(submission_views_mod, helper_name)
                    new_helper = getattr(web_utils_mod, helper_name)
                    if cur_helper is not new_helper:
                        _record_attr_patch(submission_views_mod, helper_name, cur_helper)
                        setattr(submission_views_mod, helper_name, new_helper)

        orig_render = getattr(submission_views_mod, "render", None)
        if orig_render is not None and not getattr(orig_render, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_render)
            def _wrapped_render(
                request: Any,
                template_name: Any,
                context: Optional[MutableMapping[str, Any]] = None,
                *args: Any,
                _orig=orig_render,
                **kwargs: Any,
            ):
                if template_name == "submission/index.html" and isinstance(context, MutableMapping):
                    ent = getattr(request, "entitlements", None) or get_current_entitlements()
                    default_submission_context_filter(context, ent)
                return _orig(request, template_name, context, *args, **kwargs)

            _wrapped_render._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(submission_views_mod, "render", orig_render)
            setattr(submission_views_mod, "render", _wrapped_render)


def _reconcile_login_groups(user: Any, idp_groups: set) -> None:
    from lib.tenancy.resources import reconcile_idp_groups_to_django_groups

    reconcile_idp_groups_to_django_groups(user, idp_groups)


def default_sql_task_query_filter(query: Any, viewer: Optional[ViewerContext] = None) -> Any:
    """Apply `TaskAcl` outer-join and visibility clause to a SQLAlchemy `Task` query."""
    active_viewer = viewer if viewer is not None else get_current_viewer()
    if active_viewer is None or active_viewer.see_all:
        return query
    try:
        from lib.cuckoo.core.data.task import Task
    except ImportError:
        return query
    clause = default_sql_task_acl_clause(Task.id, Task.user_id, active_viewer)
    if clause is None:
        return query
    _ensure_acl_table()
    return query.outerjoin(TaskAcl, TaskAcl.task_id == Task.id).filter(clause)


def _ensure_acl_table() -> None:
    try:
        from lib.cuckoo.core.database import Database

        ensure_acl_schema_once(Database().engine)
    except Exception:
        pass  # the query will surface a real database problem


def _stamp_from_dist_env(info: Dict[str, Any]) -> bool:
    """Stamp `info` from `CAPE_TASK_*` env vars passed by `utils/dist.py` when present."""
    env_vis = (os.environ.get("CAPE_TASK_VISIBILITY") or "").strip().lower()
    env_tid = (os.environ.get("CAPE_TASK_TENANT_ID") or "").strip()
    env_uid = (os.environ.get("CAPE_TASK_USER_ID") or "").strip()
    env_seq = (os.environ.get("CAPE_TASK_VISIBILITY_SEQ") or "").strip()
    if not (env_vis or env_tid or env_uid):
        return False
    if env_uid:
        try:
            info["user_id"] = int(env_uid)
        except ValueError:
            pass
    if env_tid:
        try:
            info["tenant_id"] = int(env_tid)
        except ValueError:
            pass
    info["visibility"] = env_vis if env_vis in VISIBILITIES else PRIVATE
    try:
        info["visibility_seq"] = int(env_seq) if env_seq else 1
    except ValueError:
        info["visibility_seq"] = 1
    return True


def default_report_stamp_hook(results: Dict[str, Any]) -> None:
    """Stamp tenancy fields (`TaskAcl` or `dist.py` env vars) and ship artifacts when `[object_storage]` is enabled."""
    try:
        from lib.tenancy.storage.config import object_storage_config
        from lib.tenancy.storage.reporting import upload_analysis_artifacts

        if object_storage_config().enabled:
            upload_analysis_artifacts(results)
    except Exception:
        pass

    info = results.get("info")
    if not isinstance(info, dict):
        return
    if not multitenancy_config().enabled:
        return
    task_id = info.get("id")
    if task_id is None:
        return
    # Filed under the main/central server's task id (dist, object-storage bridge): this node's
    # task_acl row with that number is not that task's ACL; the stamp that server sent applies.
    renumbered = info.get("local_task_id") is not None
    if not renumbered:
        try:
            from lib.cuckoo.core.database import Database

            db = Database()
            with db.session.begin():
                row = db.session.get(TaskAcl, int(task_id))
                if row is not None:
                    info["user_id"] = row.user_id
                    info["tenant_id"] = row.tenant_id
                    info["visibility"] = row.visibility
                    info["visibility_seq"] = int(row.visibility_seq or 1)
                    return
        except Exception:
            pass

    if renumbered:
        # This node's submitter and tenant ids mean nothing (or someone else) on that server.
        info["user_id"] = info["tenant_id"] = None
    if _stamp_from_dist_env(info):
        return
    info.setdefault("visibility", "private")
    info.setdefault("visibility_seq", 0)


def _resync_retrieved_report(task_id: int) -> None:
    """dist fetched a worker's report: re-apply this server's current task_acl to it."""
    if not multitenancy_config().enabled:
        return
    from sqlalchemy.orm import Session

    from lib.cuckoo.core.database import Database
    from lib.tenancy.backfill import _resync_one

    try:
        with Session(Database().engine) as session:
            _resync_one(session, task_id)
    except Exception:
        log.exception("Task %s: could not restamp the fetched report; run utils/tenancy_reconcile.py --task %s", task_id, task_id)


def _own_report_query(task_id: int, store: str) -> Optional[Dict[str, Any]]:
    from lib.tenancy.acl import own_report_es_query, own_report_mongo_query

    if not multitenancy_config().enabled:
        return None  # object storage alone: the stock info.id lookup
    return own_report_es_query(task_id) if store == "es" else own_report_mongo_query(task_id)


def register_core_hooks() -> bool:
    """Register `lib.tenancy` Mongo, SQL, ES, Report, and Resource hooks into `lib.cuckoo.common.hooks`."""
    wrap_submission_and_web_utils()
    try:
        from lib.cuckoo.common import hooks as core_hooks
    except ImportError:
        return False

    if hasattr(core_hooks, "register_cleanup_hook"):
        core_hooks.register_cleanup_hook(_restore_all_wrapped)
    core_hooks.register_mongo_filter(lambda collection, query: default_mongo_analysis_filter(collection, query))
    core_hooks.register_sql_task_filter(default_sql_task_query_filter)
    core_hooks.register_es_filter(lambda body: default_es_query_filter(body))
    core_hooks.register_report_hook(default_report_stamp_hook)
    if hasattr(core_hooks, "register_machine_filter"):
        core_hooks.register_machine_filter(default_machine_list_filter)
    if hasattr(core_hooks, "register_tag_filter"):
        core_hooks.register_tag_filter(default_tag_list_filter)
    if hasattr(core_hooks, "register_route_filter"):
        core_hooks.register_route_filter(default_route_list_filter)
    if hasattr(core_hooks, "register_submission_context_filter"):
        core_hooks.register_submission_context_filter(default_submission_context_filter)
    if hasattr(core_hooks, "register_login_groups_hook"):
        core_hooks.register_login_groups_hook(_reconcile_login_groups)
    if hasattr(core_hooks, "register_task_copy_scope_hook"):
        core_hooks.register_task_copy_scope_hook(inherit_task_scope)
    if hasattr(core_hooks, "register_task_report_query_hook"):
        core_hooks.register_task_report_query_hook(_own_report_query)
    if hasattr(core_hooks, "register_report_retrieved_hook"):
        core_hooks.register_report_retrieved_hook(_resync_retrieved_report)
    if hasattr(core_hooks, "register_cache_scope_hook"):
        core_hooks.register_cache_scope_hook(_ViewerScopedCacheFunction._scope)
    return True
