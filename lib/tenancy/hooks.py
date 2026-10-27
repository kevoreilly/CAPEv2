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

import functools
import os
from typing import Any, Callable, Dict, Iterable, List, MutableMapping, Optional

from sqlalchemy import or_

from lib.tenancy.acl import TaskAcl, ensure_acl_schema, set_task_acl
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
    ViewerContext,
    default_visibility as resolve_default_visibility,
    multitenancy_config,
    viewer_scope_es_filter,
    viewer_scope_match,
)
from lib.tenancy.resources import (
    ResourceEntitlements,
    filter_submission_form_context,
)

MongoFilterFn = Callable[[str, Dict[str, Any], Optional[ViewerContext]], Dict[str, Any]]
SqlFilterFn = Callable[[Any, Any, Optional[ViewerContext]], Any]
EsFilterFn = Callable[[Dict[str, Any], Optional[ViewerContext]], Dict[str, Any]]

_mongo_filters: List[MongoFilterFn] = []
_sql_filters: List[SqlFilterFn] = []
_es_filters: List[EsFilterFn] = []
_patched_modules: set[str] = set()


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
    *,
    route_type: Optional[str] = None,
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


def wrap_mongodb_module(mongodb_mod: Any) -> None:
    """Wrap `dev_utils.mongodb` functions in-place so `'analysis'` queries are auto-scoped."""
    mod_id = getattr(mongodb_mod, "__name__", str(id(mongodb_mod)))
    if mod_id in _patched_modules:
        return

    if not _mongo_filters:
        register_mongo_filter(default_mongo_analysis_filter)

    for fn_name in ("mongo_find", "mongo_find_one"):
        orig = getattr(mongodb_mod, fn_name, None)
        if orig is None or getattr(orig, "_cape_tenancy_wrapped", False):
            continue

        @functools.wraps(orig)
        def _wrapped(collection: str, query: Dict[str, Any], *args: Any, _orig=orig, **kwargs: Any):
            scoped_q = apply_mongo_filters(collection, query)
            return _orig(collection, scoped_q, *args, **kwargs)

        _wrapped._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
        setattr(mongodb_mod, fn_name, _wrapped)

    orig_agg = getattr(mongodb_mod, "mongo_aggregate", None)
    if orig_agg is not None and not getattr(orig_agg, "_cape_tenancy_wrapped", False):

        @functools.wraps(orig_agg)
        def _wrapped_agg(collection: str, pipeline: List[Dict[str, Any]], *args: Any, _orig=orig_agg, **kwargs: Any):
            scoped_q = apply_mongo_filters(collection, {})
            if scoped_q:
                pipeline = [{"$match": scoped_q}] + list(pipeline)
            return _orig(collection, pipeline, *args, **kwargs)

        _wrapped_agg._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
        setattr(mongodb_mod, "mongo_aggregate", _wrapped_agg)

    _patched_modules.add(mod_id)


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
                        sess = getattr(self, "session", None)
                        if sess is not None and (
                            multitenancy_config().enabled or owner_id is not None or sub_vis is not None
                        ):
                            bind = getattr(sess, "bind", None) or (
                                sess.get_bind() if hasattr(sess, "get_bind") else None
                            )
                            if bind is not None:
                                ensure_acl_schema(bind)
                            with sess.begin():
                                set_task_acl(
                                    sess,
                                    int(task_id),
                                    user_id=owner_id,
                                    tenant_id=tenant_id,
                                    visibility=vis,
                                )
                    except Exception:
                        pass
                return task_id

            _wrapped_task_add._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            setattr(tasking_cls, "add", _wrapped_task_add)

    if machines_cls is None:
        try:
            from lib.cuckoo.core.data.machines import MachinesMixIn as machines_cls
        except ImportError:
            machines_cls = None

    if machines_cls is not None:
        orig_list_machines = getattr(machines_cls, "list_machines", None)
        if orig_list_machines is not None and not getattr(orig_list_machines, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_list_machines)
            def _wrapped_list_machines(self: Any, *args: Any, _orig=orig_list_machines, **kwargs: Any):
                res = _orig(self, *args, **kwargs)
                return default_machine_list_filter(res)

            _wrapped_list_machines._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            setattr(machines_cls, "list_machines", _wrapped_list_machines)

    if web_utils_mod is None:
        try:
            import lib.cuckoo.common.web_utils as web_utils_mod
        except ImportError:
            web_utils_mod = None

    if web_utils_mod is not None:
        orig_tags = getattr(web_utils_mod, "load_vms_tags", None)
        if orig_tags is not None and not getattr(orig_tags, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_tags)
            def _wrapped_load_vms_tags(*args: Any, _orig=orig_tags, **kwargs: Any):
                tags = _orig(*args, **kwargs)
                if not tags:
                    return tags
                return sorted(default_tag_list_filter(tags))

            _wrapped_load_vms_tags._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            setattr(web_utils_mod, "load_vms_tags", _wrapped_load_vms_tags)

        orig_exits = getattr(web_utils_mod, "load_vms_exits", None)
        if orig_exits is not None and not getattr(orig_exits, "_cape_tenancy_wrapped", False):

            @functools.wraps(orig_exits)
            def _wrapped_load_vms_exits(*args: Any, _orig=orig_exits, **kwargs: Any):
                exits = _orig(*args, **kwargs)
                if not exits:
                    return exits
                return sorted(default_route_list_filter(exits, route_type="exit"))

            _wrapped_load_vms_exits._cape_tenancy_wrapped = True  # type: ignore[attr-defined]
            setattr(web_utils_mod, "load_vms_exits", _wrapped_load_vms_exits)

    if submission_views_mod is None:
        try:
            import submission.views as submission_views_mod  # type: ignore[import-not-found]
        except Exception:
            try:
                import web.submission.views as submission_views_mod  # type: ignore[import-not-found]
            except Exception:
                submission_views_mod = None

    if submission_views_mod is not None:
        if web_utils_mod is not None:
            for helper_name in ("load_vms_tags", "load_vms_exits"):
                if hasattr(submission_views_mod, helper_name) and hasattr(web_utils_mod, helper_name):
                    setattr(submission_views_mod, helper_name, getattr(web_utils_mod, helper_name))

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
            setattr(submission_views_mod, "render", _wrapped_render)


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
    return query.outerjoin(TaskAcl, TaskAcl.task_id == Task.id).filter(clause)


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

    if not multitenancy_config().enabled:
        return
    info = results.get("info")
    if not isinstance(info, dict):
        return
    task_id = info.get("id")
    if task_id is None:
        return
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

    if _stamp_from_dist_env(info):
        return
    info.setdefault("visibility", "private")
    info.setdefault("visibility_seq", 0)


def register_core_hooks() -> bool:
    """Register `lib.tenancy` Mongo, SQL, ES, Report, and Resource hooks into `lib.cuckoo.common.hooks`."""
    wrap_submission_and_web_utils()
    try:
        from lib.cuckoo.common import hooks as core_hooks
    except ImportError:
        return False

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
    return True
