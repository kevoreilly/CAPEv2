"""Django `TenancyMiddleware` implementing automatic per-request scoping, VM/route/tag gating, and `process_view` checks.

Enforces task, sample, machine, and submission policies and dispatches object-storage
artifact download/streaming views without requiring inline checks across `web/`.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, MutableMapping, Optional, Sequence

from lib.tenancy.context import (
    reset_current_entitlements,
    reset_current_submission_visibility,
    reset_current_viewer,
    set_current_entitlements,
    set_current_submission_visibility,
    set_current_viewer,
)
from lib.tenancy.policy import (
    PRIVATE,
    PUBLIC,
    TENANT,
    VISIBILITIES,
    ResourceScope,
    ViewerContext,
    can_delete,
    can_read,
    can_toggle,
    default_visibility as resolve_default_visibility,
    multitenancy_config,
)
from lib.tenancy.resources import (
    ResourceEntitlements,
    resolve_user_entitlements,
    validate_and_normalize_submission,
)

_DELETE_KEYWORDS = ("delete", "remove", "purge")
# A live guac console grants keyboard/framebuffer control of the analysis VM: a task action, not a read.
_MANAGE_KEYWORDS = ("reprocess", "reboot", "visibility", "toggle", "reschedule", "/guac/", "remote_session")
_TASK_ID_KWARGS = ("task_id", "analysis_id", "analysis_number", "left_id", "right_id")
_SAMPLE_HASH_KWARGS = ("sha256", "sha1", "md5", "sample_id")
# Route kwargs that carry a bare hash of unspecified type (compare/<id>/<hash>, resubmit/<id>/<hash>).
_UNTYPED_HASH_KWARGS = ("right_hash", "resubmit_hash")
_HASH_FIELD_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
# Views that take their task ids from the POST body instead of the route.
_BODY_TASK_ID_FIELDS = {"tasks_delete_many": "ids"}
# Upper bound on ids expanded from a "start-end" range kwarg (tasks/delete/1-5/).
_MAX_TASK_ID_RANGE = 1000
_SUBMISSION_VIEW_NAMES = (
    "tasks_create_file",
    "tasks_create_url",
    "tasks_create_dlnexec",
    "tasks_create_download_service",
    "tasks_create_static",
)


def _web_authentication_enabled() -> bool:
    try:
        from django.conf import settings

        if settings.configured:
            return bool(getattr(settings, "WEB_AUTHENTICATION", False))
    except Exception:
        pass
    return False


def _resolve_policy_tenant_id(group: Any, policy: Any) -> Optional[int]:
    """Return effective integer `tenant_id` for a `(group, sandbox_policy)` pair."""
    if policy is not None:
        if not bool(getattr(policy, "active", True)):
            return None
        if not bool(getattr(policy, "is_tenant_boundary", True)):
            return None
        explicit_tid = getattr(policy, "tenant_id", None)
        if explicit_tid is not None:
            return int(explicit_tid)
        pol_gid = getattr(policy, "group_id", None)
        if pol_gid is not None:
            return int(pol_gid)
    gid = getattr(group, "id", None)
    if gid is not None:
        return int(gid)
    return None


def _resolve_tenant_from_user(
    user: Any,
) -> tuple[Optional[int], bool, tuple[int, ...], tuple[int, ...]]:
    """Resolve `(primary_tenant_id, is_tenant_admin, tenant_ids, admin_tenant_ids)` from user."""
    try:
        profile = getattr(user, "userprofile", None)
        if profile is not None and getattr(profile, "tenant_id", None) is not None:
            tid = int(profile.tenant_id)
            is_adm = bool(getattr(profile, "is_tenant_admin", False))
            return tid, is_adm, (tid,), ((tid,) if is_adm else ())
    except Exception:
        return None, False, (), ()

    try:
        membership = getattr(user, "tenant_membership", None)
        if membership is not None and getattr(membership, "tenant_id", None) is not None:
            tid = int(membership.tenant_id)
            is_adm = bool(getattr(membership, "is_tenant_admin", False))
            return tid, is_adm, (tid,), ((tid,) if is_adm else ())
    except Exception:
        return None, False, (), ()

    try:
        groups_rel = getattr(user, "groups", None)
        if groups_rel is not None:
            if hasattr(groups_rel, "all"):
                try:
                    qs = list(groups_rel.select_related("sandbox_policy").all())
                except Exception:
                    qs = list(groups_rel.all())
            elif isinstance(groups_rel, (list, tuple, set)):
                qs = list(groups_rel)
            else:
                qs = []

            candidates: list[tuple[int, int, int, bool, Any]] = []
            for idx, g in enumerate(qs):
                pol = getattr(g, "sandbox_policy", None)
                tid = _resolve_policy_tenant_id(g, pol)
                if tid is None:
                    continue
                prio = int(getattr(pol, "priority", 0) or 0) if pol is not None else 0
                order_id = int(getattr(pol, "id", 0) or getattr(g, "id", 0) or idx)
                is_adm = bool(getattr(pol, "is_tenant_admin_group", False)) if pol is not None else False
                candidates.append((-prio, order_id, tid, is_adm, pol))

            if candidates:
                candidates.sort(key=lambda item: (item[0], item[1]))
                primary_tid = candidates[0][2]
                all_tids: list[int] = []
                admin_tids: list[int] = []
                for _, _, tid, is_adm, _ in candidates:
                    if tid not in all_tids:
                        all_tids.append(tid)
                    if is_adm and tid not in admin_tids:
                        admin_tids.append(tid)

                visited_pols: set[int] = set()
                for _, _, _, _, pol in candidates:
                    curr = pol
                    while curr is not None and bool(getattr(curr, "inherit_parent_tasks", True)):
                        pol_key = int(getattr(curr, "id", 0) or id(curr))
                        if pol_key in visited_pols:
                            break
                        visited_pols.add(pol_key)
                        parent_grp = getattr(curr, "parent_group", None)
                        if parent_grp is None:
                            break
                        parent_pol = getattr(parent_grp, "sandbox_policy", None)
                        parent_tid = _resolve_policy_tenant_id(parent_grp, parent_pol)
                        if parent_tid is not None and parent_tid not in all_tids:
                            all_tids.append(parent_tid)
                        curr = parent_pol

                is_primary_admin = primary_tid in admin_tids
                return primary_tid, is_primary_admin, tuple(all_tids), tuple(admin_tids)
    except Exception:
        return None, False, (), ()

    return None, False, (), ()


def default_viewer_resolver(user: Any) -> ViewerContext:
    """Resolve a `ViewerContext` from a Django `request.user` object."""
    cfg = multitenancy_config()
    is_super = bool(getattr(user, "is_superuser", False))
    if not cfg.enabled:
        is_staff = bool(getattr(user, "is_staff", False))
        is_local = (not _web_authentication_enabled()) or is_super or is_staff
        return ViewerContext(
            user_id=getattr(user, "id", None),
            tenant_id=None,
            is_superuser=is_super,
            is_tenant_admin=False,
            is_local_admin=is_local,
            is_authenticated=True,
        )

    if user is None or not getattr(user, "is_authenticated", False):
        return ViewerContext.anonymous()

    is_super = bool(getattr(user, "is_superuser", False))
    is_local_admin = is_super and bool(cfg.allow_superuser_all)

    tenant_id, is_tenant_admin, tenant_ids, admin_tenant_ids = _resolve_tenant_from_user(user)

    return ViewerContext(
        user_id=getattr(user, "id", None),
        tenant_id=tenant_id,
        is_superuser=is_super,
        is_tenant_admin=is_tenant_admin,
        is_local_admin=is_local_admin,
        is_authenticated=True,
        tenant_ids=tenant_ids,
        admin_tenant_ids=admin_tenant_ids,
    )


def classify_view_action(request_path: str, view_func: Callable[..., Any]) -> str:
    """Classify a view invocation as `'read'`, `'manage'`, or `'delete'`."""
    view_name = getattr(view_func, "__name__", "").lower()
    path_lower = (request_path or "").lower()
    combined = f"{view_name} {path_lower}"

    if any(kw in combined for kw in _DELETE_KEYWORDS):
        return "delete"
    if any(kw in combined for kw in _MANAGE_KEYWORDS):
        return "manage"
    return "read"


def _is_submission_post(request: Any, view_func: Callable[..., Any]) -> bool:
    method = str(getattr(request, "method", "") or "").upper()
    if method != "POST":
        return False
    path = str(getattr(request, "path", "") or "").lower()
    view_name = getattr(view_func, "__name__", "").lower()
    if view_name in _SUBMISSION_VIEW_NAMES:
        return True
    if path.startswith("/submit") or path.startswith("/apiv2/tasks/create/"):
        return True
    return False


def _is_direct_vnc_view(view_func: Callable[..., Any]) -> bool:
    return getattr(view_func, "__name__", "").startswith("direct_vnc_")


def _is_machine_view(request: Any, view_func: Callable[..., Any], view_kwargs: Dict[str, Any]) -> bool:
    if "name" not in view_kwargs or view_kwargs.get("name") is None:
        return False
    view_name = getattr(view_func, "__name__", "").lower()
    path = str(getattr(request, "path", "") or "").lower()
    return view_name == "machines_view" or "/machines/view/" in path


def _extract_submission_params(request: Any) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    for attr in ("POST", "data"):
        store = getattr(request, attr, None)
        if isinstance(store, MutableMapping) or hasattr(store, "keys"):
            try:
                for k in store.keys():
                    params[str(k)] = store.get(k)
            except Exception:
                pass
    return params


def _apply_normalized_submission_params(request: Any, normalized: Dict[str, Any]) -> None:
    for attr in ("POST", "data"):
        store = getattr(request, attr, None)
        if store is None:
            continue
        was_immutable = False
        if hasattr(store, "_mutable") and not getattr(store, "_mutable", True):
            try:
                store._mutable = True
                was_immutable = True
            except Exception:
                pass
        try:
            if isinstance(store, MutableMapping) or hasattr(store, "__setitem__"):
                for k in ("route", "tags", "timeout"):
                    if k in normalized:
                        store[k] = normalized[k]
        except Exception:
            pass
        finally:
            if was_immutable:
                try:
                    store._mutable = False
                except Exception:
                    pass


def resolve_submission_visibility(
    raw_params: Dict[str, Any],
    viewer: Optional[ViewerContext],
    entitlements: Optional[ResourceEntitlements] = None,
) -> tuple[bool, Optional[str], str]:
    """Validate and resolve the initial task visibility (`'private'`, `'tenant'`, `'public'`) on submission."""
    cfg = multitenancy_config()
    requested = str(raw_params.get("visibility") or "").strip().lower()
    has_tenant = viewer is not None and getattr(viewer, "tenant_id", None) is not None

    if requested:
        if requested not in VISIBILITIES:
            return False, f"Invalid visibility '{requested}' (expected private, tenant, or public)", PRIVATE
        if requested == TENANT and not has_tenant and not getattr(viewer, "is_local_admin", False):
            return False, "Cannot submit with visibility='tenant' without belonging to a tenant group", PRIVATE
        return True, None, requested

    group_default = getattr(entitlements, "default_visibility", None) if entitlements is not None else None
    if group_default in VISIBILITIES:
        eff = group_default
    elif cfg.enabled:
        eff = resolve_default_visibility(cfg)
    else:
        eff = PRIVATE if (viewer is not None and getattr(viewer, "user_id", None) is not None) else PUBLIC

    if eff == TENANT and not has_tenant:
        eff = PRIVATE
    return True, None, eff


class TenancyMiddleware:
    """Django middleware that binds `ViewerContext` + `ResourceEntitlements` and gates routes in `process_view`."""

    def __init__(
        self,
        get_response: Callable[[Any], Any],
        *,
        viewer_resolver: Callable[[Any], ViewerContext] = default_viewer_resolver,
        entitlements_resolver: Callable[[Any], ResourceEntitlements] = resolve_user_entitlements,
        task_scope_resolver: Optional[Callable[[int], Optional[ResourceScope]]] = None,
        sample_access_checker: Optional[Callable[[ViewerContext, Dict[str, Any]], bool]] = None,
        deny_response_factory: Optional[Callable[[Any, str], Any]] = None,
        forbidden_response_factory: Optional[Callable[[Any, str], Any]] = None,
    ) -> None:
        self.get_response = get_response
        self.viewer_resolver = viewer_resolver
        self.entitlements_resolver = entitlements_resolver
        # Django instantiates MIDDLEWARE entries with get_response only, so the production
        # defaults must live here; leaving them None would skip every per-task check.
        self.task_scope_resolver = task_scope_resolver or default_task_scope_resolver
        self.sample_access_checker = sample_access_checker or default_sample_access_checker
        self.deny_response_factory = deny_response_factory or self._default_deny_response
        self.forbidden_response_factory = forbidden_response_factory or self._default_forbidden_response

    def __call__(self, request: Any) -> Any:
        user = getattr(request, "user", None)
        viewer = self.viewer_resolver(user)
        entitlements = self.entitlements_resolver(user)
        request.viewer = viewer
        request.entitlements = entitlements
        v_token = set_current_viewer(viewer)
        e_token = set_current_entitlements(entitlements)
        s_token = set_current_submission_visibility(getattr(request, "submission_visibility", None))
        try:
            from lib.tenancy.urls import match_visibility_task_id

            vis_task_id = match_visibility_task_id(getattr(request, "path", "") or "")
            if vis_task_id is not None:
                from lib.tenancy.views import tasks_set_visibility

                return tasks_set_visibility(request, vis_task_id, viewer_resolver=self.viewer_resolver)
            return self.get_response(request)
        finally:
            reset_current_submission_visibility(s_token)
            reset_current_entitlements(e_token)
            reset_current_viewer(v_token)

    def process_view(
        self,
        request: Any,
        view_func: Callable[..., Any],
        view_args: Sequence[Any],
        view_kwargs: Dict[str, Any],
    ) -> Optional[Any]:
        """Automatically enforce task, sample, machine, and submission resource policies before the view runs."""
        if getattr(view_func, "tenancy_exempt", False):
            return None

        user = getattr(request, "user", None)
        viewer: Optional[ViewerContext] = getattr(request, "viewer", None)
        if viewer is None:
            viewer = self.viewer_resolver(user)
            request.viewer = viewer

        entitlements: Optional[ResourceEntitlements] = getattr(request, "entitlements", None)
        if entitlements is None:
            entitlements = self.entitlements_resolver(user)
            request.entitlements = entitlements

        if _is_direct_vnc_view(view_func) and not viewer.see_all:
            # Direct VNC addresses VMs and host:port pairs outside any task scope.
            return self.forbidden_response_factory(request, "VNC Console is restricted to administrators")

        if _is_machine_view(request, view_func, view_kwargs):
            if entitlements is not None and not entitlements.unrestricted:
                machine_name = str(view_kwargs.get("name") or "")
                if not entitlements.can_use_machine(machine_name):
                    return self.deny_response_factory(request, "Machine not found")

        if _is_submission_post(request, view_func):
            raw_params = _extract_submission_params(request)
            vis_ok, vis_err, resolved_vis = resolve_submission_visibility(raw_params, viewer, entitlements)
            if not vis_ok:
                return self.forbidden_response_factory(request, vis_err or "Invalid submission visibility")
            set_current_submission_visibility(resolved_vis)
            request.submission_visibility = resolved_vis
            if entitlements is not None and not entitlements.unrestricted:
                allowed, err_msg, normalized = validate_and_normalize_submission(raw_params, entitlements)
                if not allowed:
                    return self.forbidden_response_factory(request, err_msg or "Submission denied by group policy")
                _apply_normalized_submission_params(request, normalized)

        if not viewer.see_all:
            raw_task_ids = _task_ids_from_kwargs(view_kwargs) + _task_ids_from_body(request, view_func)
            if raw_task_ids:
                action = classify_view_action(getattr(request, "path", ""), view_func)
            for raw in raw_task_ids:
                try:
                    task_id = int(raw)
                except (TypeError, ValueError):
                    return self.deny_response_factory(request, "Task not found")
                try:
                    scope = self.task_scope_resolver(task_id)
                except Exception:
                    scope = None  # fail closed: an unresolvable scope is indistinguishable from a hidden task
                if scope is None or not self._check_action(viewer, scope, action):
                    return self.deny_response_factory(request, "Task not found")

            # Routes that address a task are covered by the task check above; their hash kwargs
            # (e.g. on_demand/<task>/<category>/<sha256>) name files of that task, not samples.
            sample_filter = {} if raw_task_ids else _sample_filter_from_kwargs(view_kwargs)
            if sample_filter:
                try:
                    visible = bool(self.sample_access_checker(viewer, sample_filter))
                except Exception:
                    visible = False
                if not visible:
                    return self.deny_response_factory(request, "Sample not found in database")

        from lib.tenancy.views import dispatch_object_storage_view

        return dispatch_object_storage_view(request, view_func, view_args, view_kwargs)

    @staticmethod
    def _check_action(viewer: ViewerContext, scope: ResourceScope, action: str) -> bool:
        if action == "delete":
            return can_delete(viewer, scope)
        if action == "manage":
            return can_toggle(viewer, scope)
        return can_read(viewer, scope)

    @staticmethod
    def _default_deny_response(request: Any, message: str) -> Any:
        path = getattr(request, "path", "") or ""
        is_api = path.startswith("/apiv2/") or path.startswith("/api/")
        try:
            from django.conf import settings
            from django.http import HttpResponseNotFound, JsonResponse

            if settings.configured:
                if is_api:
                    return JsonResponse({"error": True, "error_value": message}, status=404)
                return HttpResponseNotFound(message)
        except Exception:
            pass
        return {"status_code": 404, "error": True, "error_value": message}

    @staticmethod
    def _default_forbidden_response(request: Any, message: str) -> Any:
        path = getattr(request, "path", "") or ""
        is_api = path.startswith("/apiv2/") or path.startswith("/api/")
        try:
            from django.conf import settings
            from django.http import HttpResponseForbidden, JsonResponse

            if settings.configured:
                if is_api:
                    return JsonResponse({"error": True, "error_value": message}, status=403)
                return HttpResponseForbidden(message)
        except Exception:
            pass
        return {"status_code": 403, "error": True, "error_value": message}


def _task_ids_from_kwargs(view_kwargs: Dict[str, Any]) -> list:
    """Every task id a route addresses; compare views carry two, files/get/task/<id> uses stype/value."""
    ids = []
    for key in _TASK_ID_KWARGS:
        if view_kwargs.get(key) is not None:
            ids.extend(_expand_task_ids(view_kwargs[key]))
    if view_kwargs.get("stype") == "task" and view_kwargs.get("value") is not None:
        ids.append(view_kwargs["value"])
    return ids


def _expand_task_ids(raw: Any) -> list:
    """Expand "1,2" and "1-5" id lists; anything unparseable is returned as-is and denied later."""
    text = str(raw)
    if "," in text:
        return [part.strip() for part in text.split(",") if part.strip()]
    if "-" in text:
        try:
            start, end = (int(part) for part in text.split("-"))
        except ValueError:
            return [raw]
        if start > end or end - start >= _MAX_TASK_ID_RANGE:
            return [raw]
        return list(range(start, end + 1))
    return [raw]


def _task_ids_from_body(request: Any, view_func: Callable[..., Any]) -> list:
    field = _BODY_TASK_ID_FIELDS.get(getattr(view_func, "__name__", ""))
    if not field:
        return []
    post = getattr(request, "POST", None)
    raw = post.get(field, "") if post is not None and hasattr(post, "get") else ""
    return [part.strip() for part in str(raw).split(",") if part.strip()]


def _sample_filter_from_kwargs(view_kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Sample-identifying kwargs, including files/get/<hashtype>/<value> and untyped hash kwargs."""
    flt = {k: view_kwargs[k] for k in _SAMPLE_HASH_KWARGS if view_kwargs.get(k) is not None}
    stype, value = view_kwargs.get("stype"), view_kwargs.get("value")
    if stype in ("md5", "sha1", "sha256") and value:
        flt[stype] = str(value).lower()
    for key in _UNTYPED_HASH_KWARGS:
        value = view_kwargs.get(key)
        field = _HASH_FIELD_BY_LEN.get(len(str(value))) if value else None
        if field:
            flt[field] = str(value).lower()
    return flt


def default_task_scope_resolver(task_id: int) -> Optional[ResourceScope]:
    """Production task resolver: the task's `TaskAcl` scope, or None when the task does not exist."""
    from lib.tenancy.views import _default_session_and_task_scope

    return _default_session_and_task_scope(task_id)[1]


def default_sample_access_checker(viewer: ViewerContext, sample_filter: Dict[str, Any]) -> bool:
    """A sample is visible when the viewer can read at least one task that analysed it."""
    from sqlalchemy import and_, select

    from lib.cuckoo.core.data.samples import Sample
    from lib.cuckoo.core.data.task import Task
    from lib.cuckoo.core.database import Database
    from lib.tenancy.acl import resolve_task_scope

    conds = []
    for key, value in sample_filter.items():
        if key == "sample_id":
            try:
                conds.append(Sample.id == int(value))
            except (TypeError, ValueError):
                return False
        elif key in ("md5", "sha1", "sha256"):
            conds.append(getattr(Sample, key) == str(value).lower())
    if not conds:
        return False
    session = Database().session
    rows = session.execute(select(Task.id, Task.user_id).join(Sample, Task.sample_id == Sample.id).where(and_(*conds)))
    # Stops at the first readable task; most lookups are by the sample's own submitter.
    return any(can_read(viewer, resolve_task_scope(session, tid, fallback_user_id=uid)) for tid, uid in rows)


def tenancy_exempt(view_func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to mark a view as exempt from automatic `TenancyMiddleware` gating."""
    view_func.tenancy_exempt = True  # type: ignore[attr-defined]
    return view_func
