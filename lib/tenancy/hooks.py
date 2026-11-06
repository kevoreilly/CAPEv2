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
import lib.tenancy.policy as _policy_mod
from lib.tenancy.policy import (
    PRIVATE,
    PUBLIC,
    TENANT,
    VISIBILITIES,
    ResourceScope,
    ViewerContext,
    default_visibility as resolve_default_visibility,
    multitenancy_config as _orig_multitenancy_config,
    viewer_scope_es_filter,
    viewer_scope_match,
)


def multitenancy_config():
    return getattr(_policy_mod, "multitenancy_config", _orig_multitenancy_config)()
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


task_copy_scope = inherit_task_scope


def local_task_id(info: Any) -> Any:
    """Return this node's local task ID (`info['local_task_id']` when renumbered, else `info['id']`)."""
    if isinstance(info, (dict, MutableMapping)):
        lid = info.get("local_task_id")
        return lid if lid is not None else info.get("id")
    return None


def task_report_query(task_id: int, store: str = "mongo") -> Optional[Dict[str, Any]]:
    """Return the query matching only `task_id`'s own report in `store` (`'mongo'` or `'es'`), or `None` when multitenancy is off."""
    return _own_report_query(int(task_id), store)


def is_task_own_report(task_id: int, doc: Any) -> bool:
    """Return True if `doc` (an analysis report dict) is `task_id`'s own report."""
    if not isinstance(doc, dict):
        return False
    info = doc.get("info") or {}
    try:
        if int(info.get("id")) != int(task_id):
            return False
    except (TypeError, ValueError):
        return False
    job_id = info.get("job_id")
    return job_id in (None, "", str(int(task_id)), f"ui-{int(task_id)}", f"local-{int(task_id)}")



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


def _strip_untrusted_custom(custom: Any) -> Any:
    """Drop forged `Recovery_<id>` tokens from untrusted `custom`.

    A recovered task's custom `Recovery_<id>` sends apiv2's artifact views to task `<id>`.
    """
    if not custom or not isinstance(custom, str) or _trusted_submitter():
        return custom
    parts = [f for f in custom.split(",") if not re.match(r"^\s*Recovery_\d+\s*$", f)]
    return ",".join(parts)


_strip_untrusted_broker_job_id = _strip_untrusted_custom


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


# Set while a `no_hooks=True` MongoDB read is in progress so inner filter hooks are bypassed.
_skip_mongo_filter_ctx: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "cape_tenancy_skip_mongo_filter", default=False
)


def default_mongo_analysis_filter(
    collection: str,
    query: Optional[Dict[str, Any]],
    viewer: Optional[ViewerContext] = None,
) -> Dict[str, Any]:
    """Automatically scope queries on the MongoDB `'analysis'` collection to `viewer`."""
    base_query = dict(query) if query else {}
    if collection != "analysis" or _skip_mongo_filter_ctx.get():
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
    mod_id = getattr(mongodb_mod, "__name__", str(id(mongodb_mod)))
    if mod_id in _patched_modules:
        return

    if not _mongo_filters:
        register_mongo_filter(default_mongo_analysis_filter)

    replaced: Dict[int, Any] = {}  # id(original) -> wrapper
    for fn_name in ("mongo_find", "mongo_find_one"):
        orig = getattr(mongodb_mod, fn_name, None)
        if orig is None or getattr(orig, "_cape_tenancy_wrapped", False):
            continue

        @functools.wraps(orig)
        def _wrapped(collection: str, query: Dict[str, Any], *args: Any, _orig=orig, **kwargs: Any):
            if kwargs.get("no_hooks"):
                tok = _skip_mongo_filter_ctx.set(True)
                try:
                    try:
                        return _orig(collection, query, *args, **kwargs)
                    except TypeError:
                        stripped = {k: v for k, v in kwargs.items() if k != "no_hooks"}
                        return _orig(collection, query, *args, **stripped)
                finally:
                    _skip_mongo_filter_ctx.reset(tok)
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
            cur_find = getattr(mongodb_mod, "mongo_find", None)
            cur_find_one = getattr(mongodb_mod, "mongo_find_one", None)
            delete_many = getattr(mongodb_mod, "mongo_delete_many", None)
            if (not mt_on and (viewer is None or viewer.see_all)) or cur_find is None or delete_many is None:
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
                docs = list(cur_find("analysis", doc_q, proj, no_hooks=True))
            except TypeError:
                docs = list(cur_find("analysis", doc_q, proj))
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

            def _still_referenced(tid: int) -> bool:
                if cur_find_one is None:
                    return False
                try:
                    return cur_find_one("analysis", {"info.id": tid}, {"_id": 1}, no_hooks=True) is not None
                except TypeError:
                    return cur_find_one("analysis", {"info.id": tid}, {"_id": 1}) is not None

            unshared_tids = [tid for tid in matched_tids if not _still_referenced(tid)]
            if unshared_tids:
                delete_calls = getattr(mongodb_mod, "mongo_delete_calls", None)
                if callable(delete_calls):
                    delete_calls(task_ids=unshared_tids)
                reg = getattr(mongodb_mod, "hooks", None)
                if reg is not None:
                    seen_hooks: List[Any] = []
                    for fn_key in (orig_del, _wrapped_del):
                        if fn_key in reg:
                            for hook in reg[fn_key].get("analysis", ()):
                                if hook not in seen_hooks:
                                    seen_hooks.append(hook)
                    for hook in seen_hooks:
                        hook(unshared_tids)
            return None

        _wrapped_del._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
        reg = getattr(mongodb_mod, "hooks", None)
        if reg is not None and orig_del in reg:
            reg[_wrapped_del] = reg[orig_del]
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


# Set while compare or on_demand views execute so task-ID lookups resolve the task's own report per-request.
_own_report_lookup_ctx: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "cape_tenancy_own_report_lookup", default=False
)


def _ensure_own_report_wrappers(mod: Any, core_hooks: Any, *, include_es: bool = False) -> None:
    if mod is None:
        return
    if include_es:
        es_obj = getattr(mod, "es", None)
        orig_search = getattr(es_obj, "search", None) if es_obj is not None else None
        if (
            callable(orig_search)
            and not getattr(orig_search, "_cape_own_report_wrapped", False)
            and not getattr(orig_search, "_cape_tenancy_wrapped", False)
        ):

            def _ctx_scoped_search(index: Any, body: Any = None, query: Any = None, _os=orig_search, **kw: Any):
                if not _own_report_lookup_ctx.get():
                    if body is not None:
                        return _os(index=index, body=body, **kw)
                    if query is not None:
                        return _os(index=index, query=query, **kw)
                    return _os(index=index, **kw)
                eff_body = body if body is not None else ({"query": query} if query is not None else {})
                if isinstance(eff_body, dict):
                    eff_body = core_hooks.apply_es_filter(eff_body)
                return _os(index=index, body=eff_body, **kw)

            _ctx_scoped_search._cape_own_report_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(es_obj, "search", orig_search)
            setattr(es_obj, "search", _ctx_scoped_search)

    orig_q_by_id = getattr(mod, "get_query_by_info_id", None)
    if callable(orig_q_by_id) and not getattr(orig_q_by_id, "_cape_own_report_wrapped", False):

        def _ctx_scoped_q_by_id(tid: Any, *a: Any, _oq=orig_q_by_id, **kw: Any):
            if _own_report_lookup_ctx.get():
                own = task_report_query(int(tid), "es")
                if own is not None:
                    return own
            return _oq(tid, *a, **kw)

        _ctx_scoped_q_by_id._cape_own_report_wrapped = True  # type: ignore[attr-defined]
        _record_attr_patch(mod, "get_query_by_info_id", orig_q_by_id)
        setattr(mod, "get_query_by_info_id", _ctx_scoped_q_by_id)

    orig_m_find_one = getattr(mod, "mongo_find_one", None)
    if callable(orig_m_find_one) and not getattr(orig_m_find_one, "_cape_own_report_wrapped", False):

        def _ctx_scoped_m_find_one(coll: str, q: Any, *a: Any, _om=orig_m_find_one, **kw: Any):
            if (
                _own_report_lookup_ctx.get()
                and coll == "analysis"
                and isinstance(q, dict)
                and set(q.keys()) == {"info.id"}
            ):
                q = task_report_query(int(q["info.id"]), "mongo") or q
            return _om(coll, q, *a, **kw)

        _ctx_scoped_m_find_one._cape_own_report_wrapped = True  # type: ignore[attr-defined]
        if getattr(orig_m_find_one, "_cape_tenancy_wrapped", False):
            _ctx_scoped_m_find_one._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
        _record_attr_patch(mod, "mongo_find_one", orig_m_find_one)
        setattr(mod, "mongo_find_one", _ctx_scoped_m_find_one)


def _wrap_compare_and_analysis_views() -> None:
    try:
        from lib.cuckoo.common import hooks as core_hooks
    except ImportError:
        return

    c_mod = sys.modules.get("compare.views") or sys.modules.get("web.compare.views")
    if c_mod is None:
        try:
            import compare.views as c_mod  # type: ignore[import-not-found]
        except Exception:
            try:
                import web.compare.views as c_mod  # type: ignore[import-not-found]
            except Exception:
                c_mod = None

    if c_mod is not None:
        _ensure_own_report_wrappers(c_mod, core_hooks, include_es=True)
        comp_lib = sys.modules.get("lib.cuckoo.common.compare")
        if comp_lib is not None:
            _ensure_own_report_wrappers(comp_lib, core_hooks, include_es=True)
        for view_name in ("left", "hash", "both", "diff", "diff_data"):
            orig_fn = getattr(c_mod, view_name, None)
            if orig_fn is None or getattr(orig_fn, "_cape_tenancy_wrapped", False):
                continue

            @functools.wraps(orig_fn)
            def _wrapped_compare_view(*args: Any, _orig=orig_fn, _cmod=c_mod, **kwargs: Any):
                _ensure_own_report_wrappers(_cmod, core_hooks, include_es=True)
                cur_comp_lib = sys.modules.get("lib.cuckoo.common.compare")
                if cur_comp_lib is not None:
                    _ensure_own_report_wrappers(cur_comp_lib, core_hooks, include_es=True)
                tok = _own_report_lookup_ctx.set(True)
                try:
                    return _orig(*args, **kwargs)
                finally:
                    _own_report_lookup_ctx.reset(tok)

            _wrapped_compare_view._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(c_mod, view_name, orig_fn)
            setattr(c_mod, view_name, _wrapped_compare_view)

    es_db_mod = sys.modules.get("dev_utils.elasticsearchdb")
    if es_db_mod is None:
        try:
            import dev_utils.elasticsearchdb as es_db_mod  # type: ignore[import-not-found]
        except Exception:
            es_db_mod = None
    if es_db_mod is not None:
        orig_es_del = getattr(es_db_mod, "delete_analysis_and_related_calls", None)
        if orig_es_del is not None and not getattr(orig_es_del, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_es_del)
            def _wrapped_es_del(task_id: Any, _esmod=es_db_mod, _orig=orig_es_del):
                handler = getattr(_esmod, "elastic_handler", None)
                get_a_idx = getattr(_esmod, "get_analysis_index", None)
                get_c_idx = getattr(_esmod, "get_calls_index", None)
                get_q = getattr(_esmod, "get_query_by_info_id", None)
                if handler is None or not (callable(get_a_idx) and callable(get_c_idx) and callable(get_q)):
                    return _orig(task_id)
                tid_int = int(task_id)
                es_body = core_hooks.apply_es_filter({"query": task_report_query(tid_int, "es") or get_q(task_id)})
                hits = [
                    h
                    for h in handler.search(index=get_a_idx(), body=es_body).get("hits", {}).get("hits", [])
                    if is_task_own_report(tid_int, h.get("_source"))
                ]
                for hit in hits:
                    analysis = hit.get("_source") or {}
                    for process in (analysis.get("behavior") or {}).get("processes", []):
                        for call in process.get("calls", []):
                            handler.delete_by_query(index=get_c_idx(), body={"query": {"match": {"_id": call}}})
                    if "_index" in hit and "_id" in hit and hasattr(handler, "delete"):
                        handler.delete(index=hit["_index"], id=hit["_id"])
                    elif task_report_query(tid_int, "es") is None:
                        handler.delete_by_query(index=get_a_idx(), body=es_body)

            _wrapped_es_del._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(es_db_mod, "delete_analysis_and_related_calls", orig_es_del)
            setattr(es_db_mod, "delete_analysis_and_related_calls", _wrapped_es_del)
            _rebind_from_imports("delete_analysis_and_related_calls", {id(orig_es_del): _wrapped_es_del})

    a_mod = sys.modules.get("analysis.views") or sys.modules.get("web.analysis.views")
    if a_mod is None:
        try:
            import analysis.views as a_mod  # type: ignore[import-not-found]
        except Exception:
            try:
                import web.analysis.views as a_mod  # type: ignore[import-not-found]
            except Exception:
                a_mod = None

    if a_mod is not None:
        orig_comments = getattr(a_mod, "comments", None)
        if orig_comments is not None and not getattr(orig_comments, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_comments)
            def _wrapped_comments(request: Any, task_id: Any, _amod=a_mod, _orig=orig_comments):
                if getattr(request, "method", "") != "POST" or not getattr(_amod.settings, "COMMENTS", False):
                    return _orig(request, task_id)
                user = getattr(request, "user", None)
                if not getattr(user, "is_authenticated", False) and (
                    getattr(_amod.settings, "WEB_AUTHENTICATION", False)
                    or multitenancy_config().enabled
                    or user is not None
                ):
                    from django.contrib.auth.decorators import login_required

                    return login_required(_orig)(request, task_id)
                comment = request.POST.get("commentbox", "")
                if not comment:
                    return _amod.render(request, "error.html", {"error": "No comment provided."})

                import datetime as _dt

                m_report, m_id = None, None
                es_report, esid, esidx = None, None, None
                tid_int = int(task_id)
                if _amod.enabledconf.get("mongodb"):
                    q_mongo = task_report_query(tid_int, "mongo") or {"info.id": tid_int}
                    m_report = _amod.mongo_find_one("analysis", q_mongo, {"info.comments": 1}, sort=[("_id", -1)])
                    if isinstance(m_report, dict):
                        m_id = m_report.get("_id")
                if getattr(_amod, "es_as_db", False):
                    q_es = task_report_query(tid_int, "es") or _amod.get_query_by_info_id(task_id)
                    body = core_hooks.apply_es_filter({"query": q_es})
                    raw_hits = _amod.es.search(index=_amod.get_analysis_index(), body=body).get("hits", {}).get("hits", [])
                    hits = [
                        h
                        for h in raw_hits
                        if ((h.get("_source") or {}).get("info") or {}).get("id") is None
                        or is_task_own_report(tid_int, h.get("_source"))
                    ]
                    if hits:
                        es_report = hits[0].get("_source") or {}
                        esid = hits[0].get("_id")
                        esidx = hits[0].get("_index")

                report = m_report or es_report
                curcomments = list((report.get("info") or {}).get("comments") or []) if isinstance(report, dict) else []
                escape_map = {"&": "&amp;", '"': "&quot;", "'": "&apos;", "<": "&lt;", ">": "&gt;", "\n": "<br />"}
                buf = {
                    "Timestamp": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "Data": "".join(escape_map.get(ch, ch) for ch in comment),
                    "Status": "posted",
                }
                curcomments.insert(0, buf)
                if _amod.enabledconf.get("mongodb") and m_report is not None:
                    upd_q = {"_id": m_id} if m_id is not None else (task_report_query(tid_int, "mongo") or {"info.id": tid_int})
                    _amod.mongo_update_one("analysis", upd_q, {"$set": {"info.comments": curcomments}})
                if getattr(_amod, "es_as_db", False) and esid is not None and esidx is not None:
                    _amod.es.update(index=esidx, id=esid, body={"doc": {"info": {"comments": curcomments}}})
                return _amod.redirect("report", task_id=task_id)

            _wrapped_comments._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(a_mod, "comments", orig_comments)
            setattr(a_mod, "comments", _wrapped_comments)

        orig_on_demand = getattr(a_mod, "on_demand", None)
        if orig_on_demand is not None and not getattr(orig_on_demand, "_cape_tenancy_wrapped", False):
            _ensure_own_report_wrappers(a_mod, core_hooks, include_es=False)

            @functools.wraps(orig_on_demand)
            def _wrapped_on_demand(
                request: Any, service: Any, task_id: Any, category: Any, sha256: Any, _amod=a_mod, _orig=orig_on_demand
            ):
                _ensure_own_report_wrappers(_amod, core_hooks, include_es=False)
                tok = _own_report_lookup_ctx.set(True)
                try:
                    return _orig(request, service, task_id, category, sha256)
                finally:
                    _own_report_lookup_ctx.reset(tok)

            _wrapped_on_demand._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(a_mod, "on_demand", orig_on_demand)
            setattr(a_mod, "on_demand", _wrapped_on_demand)


# Per-call state for `gcs_refetch_banned`: tracks the banned task being refetched across
# `SamplesMixIn.view_sample` and `utils.submit.submit_file` without mutating module globals.
_refetch_state_ctx: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "cape_tenancy_refetch_state", default=None
)


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
                if inherited is None:
                    refetch_state = _refetch_state_ctx.get()
                    if refetch_state is not None and refetch_state.get("current_tid") is not None:
                        with inherit_task_scope(refetch_state.get("db") or self, refetch_state["current_tid"]):
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
                sess_pre = getattr(self, "session", None)
                raw_pre = sess_pre() if callable(sess_pre) else sess_pre
                was_in_tx = bool(raw_pre is not None and hasattr(raw_pre, "in_transaction") and raw_pre.in_transaction())
                task_id = _orig(self, *args, **kwargs)
                if task_id:
                    try:
                        sess = getattr(self, "session", None)
                        raw_sess = sess() if callable(sess) else sess
                        if (
                            not was_in_tx
                            and raw_sess is not None
                            and hasattr(raw_sess, "in_transaction")
                            and raw_sess.in_transaction()
                            and hasattr(raw_sess, "commit")
                        ):
                            raw_sess.commit()
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
                        if sess is not None and (
                            multitenancy_config().enabled or owner_id is not None or sub_vis is not None
                        ):
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

    try:
        from lib.cuckoo.core.data.samples import SamplesMixIn as samples_cls
    except ImportError:
        samples_cls = None

    if samples_cls is not None:
        orig_count_samples = getattr(samples_cls, "count_samples", None)
        if orig_count_samples is not None and not getattr(orig_count_samples, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_count_samples)
            def _wrapped_count_samples(self: Any, *args: Any, _orig=orig_count_samples, **kwargs: Any):
                viewer = get_current_viewer()
                if viewer is None or viewer.see_all:
                    return _orig(self, *args, **kwargs)
                from sqlalchemy import func

                from lib.cuckoo.core.data.task import Task

                q = self.session.query(func.count(func.distinct(Task.sample_id))).filter(Task.sample_id.isnot(None))
                return default_sql_task_query_filter(q, viewer).scalar() or 0

            _wrapped_count_samples._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(samples_cls, "count_samples", orig_count_samples)
            setattr(samples_cls, "count_samples", _wrapped_count_samples)

        orig_check_uniq = getattr(samples_cls, "check_file_uniq", None)
        if orig_check_uniq is not None and not getattr(orig_check_uniq, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_check_uniq)
            def _wrapped_check_uniq(self: Any, sha256: str, hours: int = 0, _orig=orig_check_uniq):
                viewer = get_current_viewer()
                if viewer is None or viewer.see_all:
                    return _orig(self, sha256, hours=hours)
                from datetime import datetime, timedelta, timezone

                from lib.cuckoo.core.data.task import Task

                sample = self.find_sample(sha256=sha256)
                if not sample:
                    return False
                q = self.session.query(Task).filter(Task.sample_id == sample.id)
                if hours and int(hours) > 0:
                    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
                    q = q.filter(Task.added_on >= now_utc - timedelta(hours=int(hours)))
                return default_sql_task_query_filter(q, viewer).first() is not None

            _wrapped_check_uniq._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(samples_cls, "check_file_uniq", orig_check_uniq)
            setattr(samples_cls, "check_file_uniq", _wrapped_check_uniq)

        orig_view_sample = getattr(samples_cls, "view_sample", None)
        if orig_view_sample is not None and not getattr(orig_view_sample, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_view_sample)
            def _wrapped_view_sample(self: Any, sample_id: Any, *a: Any, _orig=orig_view_sample, **kw: Any):
                state = _refetch_state_ctx.get()
                if state is not None:
                    state["db"] = self
                    by_sample = state.get("tasks_by_sample")
                    if by_sample is None:
                        by_sample = {}
                        try:
                            from sqlalchemy import select

                            from lib.cuckoo.core.data.task import TASK_BANNED, Task

                            rows = self.session.scalars(select(Task).where(Task.status == TASK_BANNED)).all()
                            for t in rows:
                                sid = getattr(t, "sample_id", None)
                                tid = getattr(t, "id", None)
                                if sid is not None and tid is not None:
                                    by_sample.setdefault(sid, []).append(tid)
                        except Exception:
                            pass
                        state["tasks_by_sample"] = by_sample
                    q_list = by_sample.get(sample_id) or []
                    state["current_tid"] = q_list.pop(0) if q_list else None
                return _orig(self, sample_id, *a, **kw)

            _wrapped_view_sample._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(samples_cls, "view_sample", orig_view_sample)
            setattr(samples_cls, "view_sample", _wrapped_view_sample)

    custom_machines = machines_cls is not None
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
            if custom_machines:
                _record_attr_patch(machines_cls, "list_machines", orig_list_machines)
            setattr(machines_cls, "list_machines", _wrapped_list_machines)

    custom_web_utils = web_utils_mod is not None
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
            if custom_web_utils:
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
            if custom_web_utils:
                _record_attr_patch(web_utils_mod, "load_vms_exits", orig_exits)
            setattr(web_utils_mod, "load_vms_exits", _wrapped_load_vms_exits)

        orig_validate_task = getattr(web_utils_mod, "validate_task", None)
        if orig_validate_task is not None and not getattr(orig_validate_task, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_validate_task)
            def _wrapped_validate_task(task_id: Any, *args: Any, _orig=orig_validate_task, **kwargs: Any):
                res = _orig(task_id, *args, **kwargs)
                if isinstance(res, dict) and not res.get("error"):
                    rtid = res.get("rtid")
                    if rtid is not None and str(rtid) != str(task_id):
                        viewer = get_current_viewer()
                        if viewer is not None and not viewer.see_all:
                            from lib.cuckoo.core.data.task import Task
                            from lib.cuckoo.core.database import Database
                            from lib.tenancy.policy import can_read

                            db_inst = Database()
                            ensure_acl_schema_once(db_inst.engine)
                            with db_inst.session.begin():
                                t_obj = res.get("task")
                                if t_obj is None:
                                    try:
                                        t_obj = db_inst.session.get(Task, int(rtid))
                                    except Exception:
                                        t_obj = None
                                fb_uid = getattr(t_obj, "user_id", None) if t_obj is not None else None
                                scope = resolve_task_scope(db_inst.session, int(rtid), fallback_user_id=fb_uid)
                            if not can_read(viewer, scope):
                                return {"error": True, "error_value": "Task does not exist"}
                return res

            _wrapped_validate_task._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            if custom_web_utils:
                _record_attr_patch(web_utils_mod, "validate_task", orig_validate_task)
            setattr(web_utils_mod, "validate_task", _wrapped_validate_task)
            _rebind_from_imports("validate_task", {id(orig_validate_task): _wrapped_validate_task})

        orig_parse_args = getattr(web_utils_mod, "parse_request_arguments", None)
        if orig_parse_args is not None and not getattr(orig_parse_args, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_parse_args)
            def _wrapped_parse_args(
                request: Any, keyword: str = "POST", *args: Any, _orig=orig_parse_args, **kwargs: Any
            ):
                res = _orig(request, keyword=keyword, *args, **kwargs)
                norm = getattr(request, "_tenancy_normalized_params", None)
                if isinstance(norm, dict) and norm and isinstance(res, tuple) and len(res) >= 18:
                    items = list(res)
                    if norm.get("timeout") is not None:
                        try:
                            items[2] = int(norm["timeout"])
                        except (TypeError, ValueError):
                            pass
                    if norm.get("options") is not None:
                        items[4] = norm["options"]
                    if norm.get("machine") is not None:
                        items[5] = norm["machine"]
                    if norm.get("tags") is not None:
                        items[7] = norm["tags"]
                    if norm.get("route") is not None:
                        items[16] = norm["route"]
                    return tuple(items)
                return res

            _wrapped_parse_args._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            if custom_web_utils:
                _record_attr_patch(web_utils_mod, "parse_request_arguments", orig_parse_args)
            setattr(web_utils_mod, "parse_request_arguments", _wrapped_parse_args)
            _rebind_from_imports("parse_request_arguments", {id(orig_parse_args): _wrapped_parse_args})

        # These cache their (now viewer-scoped) aggregation on the function object they look up
        # by their module global, process-wide: give each viewer scope its own cache.
        for cached_name in ("top_detections", "top_asn"):
            orig_cached = getattr(web_utils_mod, cached_name, None)
            if orig_cached is None or getattr(orig_cached, "_cape_tenancy_wrapped", False):
                continue

            scoped = _ViewerScopedCacheFunction(orig_cached)
            if custom_web_utils:
                _record_attr_patch(web_utils_mod, cached_name, orig_cached)
            setattr(web_utils_mod, cached_name, scoped)
            _rebind_from_imports(cached_name, {id(orig_cached): scoped})

    custom_sub_views = submission_views_mod is not None
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
                        if custom_sub_views:
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
            if custom_sub_views:
                _record_attr_patch(submission_views_mod, "render", orig_render)
            setattr(submission_views_mod, "render", _wrapped_render)

        orig_sub_index = getattr(submission_views_mod, "index", None)
        if orig_sub_index is not None and not getattr(orig_sub_index, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_sub_index)
            def _wrapped_sub_index(
                request: Any,
                task_id: Any = None,
                resubmit_hash: Any = None,
                *args: Any,
                _orig=orig_sub_index,
                _sv=submission_views_mod,
                **kwargs: Any,
            ):
                post = getattr(request, "POST", None)
                resub_hash = post.get("hash") if hasattr(post, "get") else None
                if resub_hash:
                    h = str(resub_hash).strip()
                    if not re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", h) or (
                        task_id is not None and not str(task_id).isdigit()
                    ):
                        return _sv.render(request, "error.html", {"error": "Invalid sample hash"})
                if "sha256" in kwargs and resubmit_hash is None:
                    resubmit_hash = kwargs.pop("sha256")
                return _orig(request, task_id=task_id, resubmit_hash=resubmit_hash, *args, **kwargs)

            _wrapped_sub_index._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            if custom_sub_views:
                _record_attr_patch(submission_views_mod, "index", orig_sub_index)
            setattr(submission_views_mod, "index", _wrapped_sub_index)

    for mod_path, cls_name in (
        ("modules.reporting.tmpfsclean", "TMPFSCLEAN"),
        ("modules.reporting.callback", "CALLBACKHOME"),
    ):
        try:
            mod = __import__(mod_path, fromlist=[cls_name])
            cls_obj = getattr(mod, cls_name, None)
            orig_run = getattr(cls_obj, "run", None)
            if orig_run is not None and not getattr(orig_run, "_cape_tenancy_wrapped", False):

                @functools.wraps(orig_run)
                def _wrapped_local_run(self: Any, results: Dict[str, Any], *a: Any, _orig=orig_run, **kw: Any):
                    info = results.get("info") if isinstance(results, dict) else None
                    orig_id = info.get("id") if isinstance(info, dict) else None
                    lid = local_task_id(info)
                    if isinstance(info, dict) and lid is not None:
                        info["id"] = lid
                    try:
                        return _orig(self, results, *a, **kw)
                    finally:
                        if isinstance(info, dict) and orig_id is not None:
                            info["id"] = orig_id

                _wrapped_local_run._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
                setattr(cls_obj, "run", _wrapped_local_run)
        except Exception:
            pass

    try:
        from lib.cuckoo.common.abstracts import Signature

        orig_get_pids = getattr(Signature, "get_pids", None)
        if orig_get_pids is not None and not getattr(orig_get_pids, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_get_pids)
            def _wrapped_get_pids(self: Any, *a: Any, _orig=orig_get_pids, **kw: Any):
                res_dict = getattr(self, "results", None)
                info = res_dict.get("info") if isinstance(res_dict, dict) else None
                orig_id = info.get("id") if isinstance(info, dict) else None
                lid = local_task_id(info)
                if isinstance(info, dict) and lid is not None:
                    info["id"] = lid
                try:
                    return _orig(self, *a, **kw)
                finally:
                    if isinstance(info, dict) and orig_id is not None:
                        info["id"] = orig_id

            _wrapped_get_pids._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            setattr(Signature, "get_pids", _wrapped_get_pids)
    except Exception:
        pass

    try:
        from lib.cuckoo.common import gcp as gcp_mod

        def _ensure_submit_file_wrapper(target_mod: Any) -> None:
            if target_mod is None:
                return
            orig_sf = getattr(target_mod, "submit_file", None)
            if not callable(orig_sf) or getattr(orig_sf, "_cape_refetch_wrapped", False):
                return

            @functools.wraps(orig_sf)
            def _ctx_scoped_submit(*sa: Any, _osf=orig_sf, **skw: Any):
                state = _refetch_state_ctx.get()
                if state is not None:
                    tid = state.get("current_tid")
                    db_obj = skw.get("db") or (sa[0] if sa else None) or state.get("db")
                    if tid is not None and db_obj is not None:
                        with inherit_task_scope(db_obj, tid):
                            return _osf(*sa, **skw)
                return _osf(*sa, **skw)

            _ctx_scoped_submit._cape_refetch_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(target_mod, "submit_file", orig_sf)
            setattr(target_mod, "submit_file", _ctx_scoped_submit)
            _rebind_from_imports("submit_file", {id(orig_sf): _ctx_scoped_submit})

        try:
            import utils.submit as submit_mod  # type: ignore[import-not-found]
        except Exception:
            submit_mod = sys.modules.get("utils.submit")
        _ensure_submit_file_wrapper(submit_mod)
        _ensure_submit_file_wrapper(gcp_mod)

        orig_refetch = getattr(gcp_mod, "gcs_refetch_banned", None)
        if orig_refetch is not None and not getattr(orig_refetch, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_refetch)
            def _wrapped_refetch(*a: Any, _orig=orig_refetch, _gmod=gcp_mod, **kw: Any):
                try:
                    import utils.submit as cur_submit_mod  # type: ignore[import-not-found]
                except Exception:
                    cur_submit_mod = sys.modules.get("utils.submit")
                _ensure_submit_file_wrapper(cur_submit_mod)
                _ensure_submit_file_wrapper(_gmod)

                g_db = getattr(_gmod, "db", None)
                orig_list = getattr(g_db, "list_tasks", None) if g_db is not None else None
                if callable(orig_list) and not getattr(orig_list, "_cape_refetch_wrapped", False):

                    def _ctx_tracking_list(*la: Any, _ol=orig_list, **lkw: Any):
                        for item in _ol(*la, **lkw):
                            st = _refetch_state_ctx.get()
                            if st is not None:
                                st["current_tid"] = item.get("id") if isinstance(item, dict) else getattr(item, "id", None)
                            yield item

                    _ctx_tracking_list._cape_refetch_wrapped = True  # type: ignore[attr-defined]
                    _record_attr_patch(g_db, "list_tasks", orig_list)
                    setattr(g_db, "list_tasks", _ctx_tracking_list)

                tok = _refetch_state_ctx.set({"db": g_db, "tasks_by_sample": None, "current_tid": None})
                try:
                    return _orig(*a, **kw)
                finally:
                    _refetch_state_ctx.reset(tok)

            _wrapped_refetch._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            _record_attr_patch(gcp_mod, "gcs_refetch_banned", orig_refetch)
            setattr(gcp_mod, "gcs_refetch_banned", _wrapped_refetch)
            _rebind_from_imports("gcs_refetch_banned", {id(orig_refetch): _wrapped_refetch})
        elif orig_refetch is not None:
            unwrapped_refetch = getattr(orig_refetch, "__wrapped__", None)
            if unwrapped_refetch is not None:
                _rebind_from_imports("gcs_refetch_banned", {id(unwrapped_refetch): orig_refetch})
    except Exception:
        pass

    _wrap_compare_and_analysis_views()


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


_tenancy_indexes_ready = False


def _ensure_tenancy_indexes() -> None:
    global _tenancy_indexes_ready
    if _tenancy_indexes_ready or not multitenancy_config().enabled:
        return
    try:
        from dev_utils.mongodb import mongo_create_index
        from pymongo import ASCENDING

        for keys, name in (
            ([("info.visibility", ASCENDING)], "info.visibility_1"),
            ([("info.tenant_id", ASCENDING), ("info.visibility", ASCENDING)], "info.tenant_id_1_info.visibility_1"),
            ([("info.user_id", ASCENDING)], "info.user_id_1"),
        ):
            mongo_create_index("analysis", keys, background=True, name=name)
        _tenancy_indexes_ready = True
    except Exception as e:
        log.debug("Could not ensure tenancy MongoDB indexes: %s", e)


def _resync_local_acl_stamp(results: Dict[str, Any], main_task_id: Optional[int] = None) -> None:
    """Re-apply the current `TaskAcl` row after inserting a local report so mid-reporting visibility toggles win."""
    info = results.get("info") if isinstance(results, dict) else None
    if main_task_id or not isinstance(info, dict) or info.get("local_task_id") is not None:
        return
    tid = info.get("id")
    if not tid:
        return
    try:
        _resync_retrieved_report(int(tid))
    except Exception as e:
        log.debug("Post-insert tenancy stamp resync skipped for task %s: %s", tid, e)


def _lookup_existing_report_stamp(remote_task_id: int) -> Optional[Dict[str, Any]]:
    """Resolve the tenancy stamp of an existing report for `remote_task_id` from MongoDB/ES."""
    candidates: List[Dict[str, Any]] = []

    mongo_mod = sys.modules.get("dev_utils.mongodb") or sys.modules.get("modules.reporting.mongodb")
    mongo_find = getattr(mongo_mod, "mongo_find", None) if mongo_mod is not None else None
    mongo_find_one = getattr(mongo_mod, "mongo_find_one", None) if mongo_mod is not None else None
    if callable(mongo_find) or callable(mongo_find_one):
        from lib.tenancy.acl import own_report_mongo_query

        m_query = own_report_mongo_query(int(remote_task_id))
        m_proj = {
            "info.id": 1,
            "info.job_id": 1,
            "info.user_id": 1,
            "info.tenant_id": 1,
            "info.visibility": 1,
            "info.visibility_seq": 1,
        }
        tok = _skip_mongo_filter_ctx.set(True)
        m_docs: List[Dict[str, Any]] = []
        try:
            if callable(mongo_find):
                try:
                    m_docs = list(mongo_find("analysis", m_query, m_proj, no_hooks=True) or [])
                except TypeError:
                    with contextlib.suppress(Exception):
                        m_docs = list(mongo_find("analysis", m_query, m_proj) or [])
                except Exception:
                    m_docs = []
            if not m_docs and callable(mongo_find_one):
                try:
                    one = mongo_find_one("analysis", m_query, m_proj, no_hooks=True)
                except TypeError:
                    try:
                        one = mongo_find_one("analysis", m_query, m_proj)
                    except TypeError:
                        one = mongo_find_one("analysis", m_query)
                if isinstance(one, dict):
                    m_docs = [one]
        except Exception:
            m_docs = []
        finally:
            _skip_mongo_filter_ctx.reset(tok)

        for m_doc in m_docs:
            if not isinstance(m_doc, dict):
                continue
            m_info = m_doc.get("info")
            if isinstance(m_info, dict) and is_task_own_report(int(remote_task_id), m_doc):
                vis = m_info.get("visibility")
                v_seq = int(m_info.get("visibility_seq") or 0)
                if vis in VISIBILITIES and v_seq > 0:
                    candidates.append({
                        "user_id": m_info.get("user_id"),
                        "tenant_id": m_info.get("tenant_id"),
                        "visibility": vis,
                        "visibility_seq": v_seq,
                    })

    es_client = None
    get_analysis_index = None
    for es_mod_name in ("dev_utils.elasticsearchdb", "modules.reporting.elasticsearchdb"):
        es_mod = sys.modules.get(es_mod_name)
        if es_mod is None:
            continue
        cand_client = getattr(es_mod, "es", None) or getattr(es_mod, "elastic_handler", None)
        cand_idx = getattr(es_mod, "get_analysis_index", None) or getattr(es_mod, "get_daily_analysis_index", None)
        if cand_client is not None and callable(cand_idx) and hasattr(cand_client, "search"):
            es_client = cand_client
            get_analysis_index = cand_idx
            break
    if es_client is not None and callable(get_analysis_index) and hasattr(es_client, "search"):
        from lib.tenancy.acl import own_report_es_query

        es_q = own_report_es_query(int(remote_task_id))
        raw_hits = []
        try:
            try:
                idx = get_analysis_index()
            except TypeError:
                idx = None
            if idx:
                res = es_client.search(index=idx, body={"query": es_q})
                raw_hits = res.get("hits", {}).get("hits", []) if isinstance(res, dict) else []
        except Exception:
            raw_hits = []

        for hit in raw_hits:
            src = hit.get("_source") if isinstance(hit, dict) else None
            if not isinstance(src, dict):
                continue
            h_info = src.get("info")
            if not isinstance(h_info, dict):
                continue
            if not is_task_own_report(int(remote_task_id), src):
                continue
            vis = h_info.get("visibility")
            v_seq = int(h_info.get("visibility_seq") or 0)
            if vis in VISIBILITIES and v_seq > 0:
                candidates.append({
                    "user_id": h_info.get("user_id"),
                    "tenant_id": h_info.get("tenant_id"),
                    "visibility": vis,
                    "visibility_seq": v_seq,
                })

    if candidates:
        return max(candidates, key=lambda c: int(c.get("visibility_seq") or 0))
    return None


def default_report_stamp_hook(results: Dict[str, Any], **context: Any) -> None:
    """Stamp tenancy fields (`TaskAcl` or `dist.py` env vars) and ship artifacts when `[object_storage]` is enabled."""
    stage = context.get("stage")
    task = context.get("task")
    attrs = (task.get("attributes") or {}) if isinstance(task, dict) else {}
    main_task_id = attrs.get("main_task_id") if isinstance(attrs, dict) else None
    if not main_task_id:
        main_task_id = os.environ.get("CAPE_MAIN_TASK_ID")

    if stage == "post_mongodb":
        info_post = results.get("info") if isinstance(results, dict) else None
        if not main_task_id and isinstance(info_post, dict) and info_post.get("local_task_id") is None:
            _resync_local_acl_stamp(results, main_task_id)
        return
    if stage == "post_elasticsearchdb":
        info_post = results.get("info") if isinstance(results, dict) else None
        if not main_task_id and isinstance(info_post, dict) and info_post.get("local_task_id") is None:
            try:
                import modules.reporting.elasticsearchdb as es_rep_mod

                es_client = getattr(es_rep_mod, "es", None) or getattr(es_rep_mod, "elastic_handler", None)
                get_idx = getattr(es_rep_mod, "get_daily_analysis_index", None)
                if es_client is not None and callable(get_idx):
                    try:
                        idx_name = get_idx(results)
                    except TypeError:
                        idx_name = get_idx()
                    es_client.indices.refresh(index=idx_name)
            except Exception:
                pass
            _resync_local_acl_stamp(results, main_task_id)
        return

    if stage == "mongodb":
        _ensure_tenancy_indexes()

    info = results.get("info")
    if isinstance(info, dict) and main_task_id:
        info.setdefault("local_task_id", info.get("id"))
        try:
            info["id"] = int(main_task_id)
        except (TypeError, ValueError):
            pass

    if stage != "acl_probe":
        try:
            from lib.tenancy.storage.config import object_storage_config
            from lib.tenancy.storage.reporting import upload_analysis_artifacts

            if object_storage_config().enabled:
                upload_analysis_artifacts(results, task=task if isinstance(task, dict) else None)
        except Exception:
            pass

    info = results.get("info")
    if not isinstance(info, dict):
        return

    renumbered = bool(info.get("local_task_id") is not None or main_task_id is not None)
    remote_tid = main_task_id if main_task_id is not None else info.get("id")

    cli_vis = context.get("visibility")
    cli_tid = context.get("tenant_id")
    acl_override: Dict[str, Any] = {}
    if cli_vis:
        acl_override["visibility"] = cli_vis
    if cli_tid is not None:
        acl_override["tenant_id"] = cli_tid
    if stage == "process" and acl_override:
        if isinstance(task, dict):
            task["_acl_override"] = dict(acl_override)
        loc_tid = task.get("id") if isinstance(task, dict) else info.get("id")
        if not main_task_id and loc_tid and info.get("local_task_id") is None:
            try:
                from sqlalchemy.orm import Session

                db_obj = context.get("db")
                if db_obj is None:
                    from lib.cuckoo.core.database import Database

                    db_obj = Database()
                ensure_acl_schema_once(db_obj.engine)
                with Session(db_obj.engine) as acl_session, acl_session.begin():
                    acl_row = set_task_acl(
                        acl_session, int(loc_tid), tenant_id=cli_tid, visibility=cli_vis or None
                    )
                    if acl_row.user_id is None and info.get("user_id") is not None:
                        acl_row.user_id = info.get("user_id")
                        acl_session.flush()
                    acl_override["visibility_seq"] = int(acl_row.visibility_seq or 1)
                    if isinstance(task, dict):
                        task["_acl_override"] = dict(acl_override)
            except Exception as e:
                log.debug("Failed to apply CLI TaskAcl override for task %s: %s", loc_tid, e)

    stamped_from_db = False

    def _apply_dist_and_override() -> None:
        task_acl = attrs.get("task_acl") if isinstance(attrs, dict) else None
        if isinstance(task_acl, dict):
            for k, default in (("user_id", None), ("tenant_id", None), ("visibility", "private"), ("visibility_seq", 0)):
                val = task_acl.get(k, default)
                info[k] = default if val is None and default is not None else val

        if (
            renumbered
            and stage != "acl_probe"
            and remote_tid is not None
            and (multitenancy_config().enabled or isinstance(task_acl, dict))
        ):
            cached_remote = task.get("_existing_remote_acl") if isinstance(task, dict) else None
            fresh_stamp = _lookup_existing_report_stamp(int(remote_tid))
            candidates = [s for s in (cached_remote, fresh_stamp) if isinstance(s, dict)]
            best_remote = max(candidates, key=lambda s: int(s.get("visibility_seq") or 0)) if candidates else None
            if best_remote is not None and isinstance(task, dict):
                task["_existing_remote_acl"] = dict(best_remote)
            if best_remote is not None and int(best_remote.get("visibility_seq") or 0) > int(info.get("visibility_seq") or 0):
                for k in ("user_id", "tenant_id", "visibility", "visibility_seq"):
                    if k in best_remote:
                        info[k] = best_remote[k]

        eff_override = (task.get("_acl_override") if isinstance(task, dict) else None) or acl_override
        if isinstance(eff_override, dict) and eff_override:
            eff_seq = eff_override.get("visibility_seq")
            db_newer = stamped_from_db and int(info.get("visibility_seq") or 0) > int(eff_seq or 0)
            for k in ("tenant_id", "visibility", "visibility_seq"):
                if k in eff_override and eff_override[k] is not None:
                    if db_newer and k in ("visibility", "visibility_seq"):
                        continue
                    if k == "visibility_seq" and int(eff_override[k]) <= int(info.get("visibility_seq") or 0):
                        continue
                    info[k] = eff_override[k]

    if not multitenancy_config().enabled:
        _apply_dist_and_override()
        return
    task_id = info.get("id")
    if task_id is None:
        _apply_dist_and_override()
        return
    # Filed under the main/central server's task id (dist, object-storage bridge): this node's
    # task_acl row with that number is not that task's ACL; the stamp that server sent applies.
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
                    stamped_from_db = True
        except Exception:
            pass

    if not stamped_from_db:
        if renumbered:
            # This node's submitter and tenant ids mean nothing (or someone else) on that server.
            info["user_id"] = info["tenant_id"] = None
        if not _stamp_from_dist_env(info):
            info.setdefault("visibility", "private")
            info.setdefault("visibility_seq", 0)

    _apply_dist_and_override()


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
    mongo_mod = sys.modules.get("dev_utils.mongodb")
    if mongo_mod is not None:
        wrap_mongodb_module(mongo_mod)
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
    if hasattr(core_hooks, "register_report_retrieved_hook"):
        core_hooks.register_report_retrieved_hook(_resync_retrieved_report)
    return True
