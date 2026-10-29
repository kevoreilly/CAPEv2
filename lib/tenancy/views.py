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
    ensure_acl_schema_once,
    VisibilityConflictError,
    resolve_task_scope,
    toggle_task_visibility_cas,
)
from lib.tenancy.middleware import _view_name, default_viewer_resolver
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
    ensure_acl_schema_once(db.engine)
    session = db.session
    scope = resolve_task_scope(session, task_id, fallback_user_id=getattr(task, "user_id", None))
    return session, scope


def _default_mongo_update_one(collection: str, filter_q: dict, update_doc: dict) -> Any:
    from dev_utils.mongodb import mongo_update_one

    return mongo_update_one(collection, filter_q, update_doc)


def _session_user_with_csrf(request: Any, user: Any) -> tuple[Any, Optional[tuple[int, str]]]:
    if not getattr(user, "is_authenticated", False):
        return user, None
    from django.middleware.csrf import CsrfViewMiddleware

    check = CsrfViewMiddleware(lambda _request: None)
    check.process_request(request)
    if check.process_view(request, None, (), {}) is not None:
        return None, (403, "CSRF verification failed")
    return user, None


def _default_es_update_by_query() -> Optional[Callable[[dict, dict], Any]]:
    """An ES restamper when Elasticsearch holds report copies, else None."""
    try:
        from lib.cuckoo.common.config import Config

        if not Config("reporting").elasticsearchdb.enabled:
            return None
        from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index
    except Exception:
        return None

    def _update(query: dict, script: dict) -> Any:
        # A concurrent write (e.g. a comment) makes update_by_query skip the doc as a version conflict;
        # retry, and fail the toggle rather than report success with the old stamp still searchable.
        for _ in range(3):
            # body=, not query=/script=: CAPE's client is elasticsearch-py 7.x (see dev_utils.elasticsearchdb).
            resp = elastic_handler.update_by_query(
                index=get_analysis_index(), body={"query": query, "script": script}, refresh=True, conflicts="proceed"
            )
            if not (resp or {}).get("version_conflicts"):
                return resp
        raise RuntimeError("Elasticsearch restamp kept hitting version conflicts")

    return _update


def _authenticate_api_caller(request: Any, user: Any) -> tuple[Any, Optional[tuple[int, str]]]:
    """Return `(user, denial)` the way /apiv2/ authenticates: API key first, session + CSRF only where enabled."""
    try:
        from rest_framework.exceptions import APIException, ParseError
        from rest_framework.request import Request
        from rest_framework.settings import api_settings
    except ImportError:
        return _session_user_with_csrf(request, user)
    authenticators = [a() for a in api_settings.DEFAULT_AUTHENTICATION_CLASSES]
    if not authenticators:
        # token_auth_enabled = no: /apiv2/ runs on the Django session, but this endpoint still needs CSRF.
        return _session_user_with_csrf(request, user)
    getattr(request, "body", None)  # cache it: the CSRF check may parse the stream before the view reads it
    drf_request = Request(request, parsers=[p() for p in api_settings.DEFAULT_PARSER_CLASSES], authenticators=authenticators)
    try:
        return drf_request.user, None
    except ParseError as e:
        return None, (400, str(getattr(e, "detail", e)))
    except APIException as e:
        return None, (403, str(getattr(e, "detail", e)))


def tasks_set_visibility(
    request: Any,
    task_id: Any,
    *,
    viewer_resolver: Callable[[Any], ViewerContext] = default_viewer_resolver,
    scope_loader: Optional[Callable[[int], tuple[Any, Optional[ResourceScope]]]] = None,
    mongo_update_one: Optional[Callable[[str, dict, dict], Any]] = None,
    es_update_by_query: Optional[Callable[[dict, dict], Any]] = None,
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

    user = getattr(request, "user", None)
    if user is not None:
        # Served from TenancyMiddleware.__call__, ahead of URL routing: neither DRF authentication
        # nor CsrfViewMiddleware has run, so authenticate here as the other /apiv2/ views do.
        user, denied = _authenticate_api_caller(request, user)
        if denied:
            return _json_response({"error": True, "error_value": denied[1]}, status=denied[0])
        viewer = viewer_resolver(user)
    else:
        viewer = getattr(request, "viewer", None) or viewer_resolver(None)

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
                owner_id=scope.owner_id,
                tenant_id=scope.tenant_id,
                es_update_by_query=es_update_by_query or _default_es_update_by_query(),
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

    view_name = _view_name(view_func)  # DRF's @api_view wrapper is named "view"
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
        key = view_kwargs.get("category") or view_kwargs.get("key") or (view_args[1] if len(view_args) > 1 else None)
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

    if view_name == "file" and ("category" in view_kwargs or view_args):  # not apiv2's files/get "file"
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
                # Staged under binaries/<dlfile> for every later reader: it must be this task's sample.
                if storage_views._task_sample_sha256(request, task_id) != str(dlfile).lower():
                    from django.http import Http404

                    raise Http404("File not found")
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
