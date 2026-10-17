"""HTTP views and object-storage view dispatcher for `lib.tenancy`.

Provides:
1. `tasks_set_visibility(request, task_id)` — `/apiv2/tasks/visibility/<task_id>/`
   visibility toggle endpoint (backed by `TaskAcl` + `toggle_task_visibility_cas`).
2. `dispatch_object_storage_view(request, view_func, view_args, view_kwargs)` (aliased as
   `dispatch_central_view`) — automatic object-storage artifact view interceptor invoked
   by `TenancyMiddleware.process_view` after task/sample authorization succeeds.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, Optional, Sequence

from lib.tenancy.acl import (
    VisibilityConflictError,
    resolve_task_scope,
    toggle_task_visibility_cas,
)
from lib.tenancy.middleware import default_viewer_resolver
from lib.tenancy.policy import (
    TENANT,
    VISIBILITIES,
    ResourceScope,
    ViewerContext,
    can_read,
    can_set_visibility,
    multitenancy_config,
)


def _json_response(payload: Dict[str, Any], status: int = 200) -> Any:
    try:
        from django.conf import settings
        from django.http import JsonResponse

        if settings.configured:
            return JsonResponse(payload, status=status)
    except Exception:
        pass
    return {"status_code": status, **payload}


def _extract_visibility_param(request: Any) -> Optional[str]:
    data = getattr(request, "data", None)
    if isinstance(data, dict) and "visibility" in data:
        return data.get("visibility")
    post = getattr(request, "POST", None)
    if isinstance(post, dict) and "visibility" in post:
        return post.get("visibility")
    if hasattr(post, "get"):
        val = post.get("visibility")
        if val is not None:
            return val
    body = getattr(request, "body", None)
    if body:
        try:
            parsed = json.loads(body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else body)
            if isinstance(parsed, dict):
                return parsed.get("visibility")
        except Exception:
            pass
    return None


def _default_session_and_task_scope(task_id: int) -> tuple[Any, Optional[ResourceScope]]:
    from lib.cuckoo.core.database import Database

    db = Database()
    task = db.view_task(task_id)
    if task is None:
        return None, None
    session = db.Session()
    scope = resolve_task_scope(session, task_id, fallback_user_id=getattr(task, "user_id", None))
    return session, scope


def _default_mongo_update_one(collection: str, filter_q: dict, update_doc: dict) -> Any:
    from dev_utils.mongodb import mongo_update_one

    return mongo_update_one(collection, filter_q, update_doc)


def tasks_set_visibility(
    request: Any,
    task_id: Any,
    *,
    viewer_resolver: Callable[[Any], ViewerContext] = default_viewer_resolver,
    scope_loader: Optional[Callable[[int], tuple[Any, Optional[ResourceScope]]]] = None,
    mongo_update_one: Optional[Callable[[str, dict, dict], Any]] = None,
) -> Any:
    """Handle `POST /apiv2/tasks/visibility/<task_id>/`."""
    method = getattr(request, "method", "POST")
    if method and method.upper() not in ("POST", "PUT", "PATCH"):
        return _json_response({"error": True, "error_value": "Method not allowed"}, status=405)

    if not multitenancy_config().enabled:
        return _json_response({"error": True, "error_value": "multitenancy is not enabled"}, status=400)

    try:
        tid = int(task_id)
    except (TypeError, ValueError):
        return _json_response({"error": True, "error_value": "Task not found"}, status=404)

    viewer: Optional[ViewerContext] = getattr(request, "viewer", None)
    if viewer is None:
        viewer = viewer_resolver(getattr(request, "user", None))

    loader = scope_loader or _default_session_and_task_scope
    session, scope = loader(tid)
    try:
        if scope is None or not can_read(viewer, scope):
            return _json_response({"error": True, "error_value": "Task not found"}, status=404)

        vis = _extract_visibility_param(request)
        if vis not in VISIBILITIES:
            return _json_response({"error": True, "error_value": "invalid visibility"}, status=400)

        if not can_set_visibility(viewer, scope, vis):
            return _json_response({"error": True, "error_value": "Access denied"}, status=403)

        if vis == TENANT and scope.tenant_id is None:
            return _json_response(
                {"error": True, "error_value": "tenant visibility requires the task to belong to a tenant"},
                status=400,
            )

        updater = mongo_update_one if mongo_update_one is not None else _default_mongo_update_one
        try:
            toggle_task_visibility_cas(
                session,
                tid,
                vis,
                expected_prior=scope.visibility,
                mongo_update_one=updater,
            )
        except VisibilityConflictError:
            return _json_response(
                {"error": True, "error_value": "visibility changed concurrently; re-read and retry"},
                status=409,
            )
        except Exception:
            if session is not None and hasattr(session, "rollback"):
                session.rollback()
            return _json_response(
                {
                    "error": True,
                    "error_value": "visibility change aborted (report store unreachable); no change made, retry",
                },
                status=503,
            )

        return _json_response({"error": False, "data": {"task_id": tid, "visibility": vis}}, status=200)
    finally:
        if session is not None and hasattr(session, "close"):
            session.close()


def dispatch_object_storage_view(
    request: Any,
    view_func: Callable[..., Any],
    view_args: Sequence[Any],
    view_kwargs: Dict[str, Any],
) -> Optional[Any]:
    """Intercept analysis artifact download/streaming views when `[object_storage] enabled = yes`."""
    try:
        from lib.tenancy.storage import config as storage_cfg

        if not storage_cfg.central_mode_config().enabled:
            return None
    except Exception:
        return None

    view_name = getattr(view_func, "__name__", "")
    if not view_name:
        return None

    from lib.tenancy.storage import views as storage_views

    if view_name == "file_nl":
        category = view_kwargs.get("category") or (view_args[0] if len(view_args) > 0 else None)
        task_id = view_kwargs.get("task_id") or (view_args[1] if len(view_args) > 1 else None)
        dlfile = view_kwargs.get("dlfile") or (view_args[2] if len(view_args) > 2 else None)
        return storage_views.central_file_nl(request, category, task_id, dlfile)

    if view_name == "filereport":
        task_id = view_kwargs.get("task_id") or (view_args[0] if len(view_args) > 0 else None)
        key = view_kwargs.get("key") or (view_args[1] if len(view_args) > 1 else None)
        formats = {
            "json": "report.json",
            "html": "report.html",
            "htmlsummary": "summary-report.html",
            "pdf": "report.pdf",
            "maec": "report.maec-1.1.xml",
            "metadata": "report.metadata.xml",
            "litereport": "litereport.json",
        }
        fname = formats.get(str(key), "report.json")
        return storage_views.central_filereport(request, task_id, fname)

    if view_name == "full_memory_dump_file":
        analysis_number = view_kwargs.get("analysis_number") or (view_args[0] if len(view_args) > 0 else None)
        return storage_views.central_full_memory_dump(request, analysis_number, ("memory.dmp.zip", "memory.dmp"))

    if view_name == "full_memory_dump_strings":
        analysis_number = view_kwargs.get("analysis_number") or (view_args[0] if len(view_args) > 0 else None)
        return storage_views.central_full_memory_dump(
            request,
            analysis_number,
            ("memory.dmp.strings.zip", "memory.dmp.strings"),
        )

    if view_name == "file":
        category = view_kwargs.get("category") or (view_args[0] if len(view_args) > 0 else None)
        task_id = view_kwargs.get("task_id") or (view_args[1] if len(view_args) > 1 else None)
        dlfile = view_kwargs.get("dlfile") or (view_args[2] if len(view_args) > 2 else None)
        try:
            from analysis.views import ANALYSIS_BASE_PATH, CUCKOO_ROOT, zip_categories
        except ImportError:
            zip_categories = ()
            ANALYSIS_BASE_PATH = ""
            CUCKOO_ROOT = ""

        if category in zip_categories:
            if category == "memdumpzip" and dlfile and ANALYSIS_BASE_PATH:
                dest = os.path.join(ANALYSIS_BASE_PATH, str(task_id), "memory", f"{dlfile}.dmp")
                storage_views.central_stage_one(request, task_id, f"memory/{dlfile}.dmp", dest)
            elif category == "staticzip" and dlfile and CUCKOO_ROOT:
                dest = os.path.join(CUCKOO_ROOT, "storage", "binaries", str(dlfile))
                storage_views.central_stage_one(request, task_id, "binary", dest)
            else:
                storage_views.central_stage_local(request, task_id)
            return None
        return storage_views.central_file(request, category, task_id, dlfile)

    if view_name == "vtupload":
        category = view_kwargs.get("category") or (view_args[0] if len(view_args) > 0 else None)
        task_id = view_kwargs.get("task_id") or (view_args[1] if len(view_args) > 1 else None)
        filename = view_kwargs.get("filename") or (view_args[2] if len(view_args) > 2 else None)
        dlfile = view_kwargs.get("dlfile") or (view_args[3] if len(view_args) > 3 else None)
        return storage_views.central_vtupload(request, category, task_id, filename, dlfile)

    if view_name == "pcapstream":
        return storage_views.central_pcapstream(request)

    if view_name == "on_demand":
        return storage_views.central_on_demand(request)

    return None


dispatch_central_view = dispatch_object_storage_view
