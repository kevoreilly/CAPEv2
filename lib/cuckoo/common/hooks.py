"""Lightweight plugin hook registry for external CAPEv2 extensions (e.g. CAPE-tenancy).

All hooks are zero-overhead no-ops when no external plugin is installed.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any, Callable, Mapping, MutableMapping, Optional

MongoFilterHook = Callable[[str, dict[str, Any]], dict[str, Any]]
SqlTaskFilterHook = Callable[[Any], Any]
EsFilterHook = Callable[[dict[str, Any]], dict[str, Any]]
ReportHook = Callable[[dict[str, Any]], None]
MachineFilterHook = Callable[[list[Any]], list[Any]]
TagFilterHook = Callable[[list[Any]], list[Any]]
RouteFilterHook = Callable[[list[Any], str | None], list[Any]]
SubmissionContextFilterHook = Callable[[MutableMapping[str, Any]], MutableMapping[str, Any]]
LoginGroupsHook = Callable[[Any, set], None]
TaskCopyScopeHook = Callable[[Any, int], contextlib.AbstractContextManager[Any]]
TaskReportQueryHook = Callable[[int, str], Optional[dict[str, Any]]]
ReportRetrievedHook = Callable[[int], None]
CacheScopeHook = Callable[[], Any]

_mongo_filters: list[MongoFilterHook] = []
_sql_task_filters: list[SqlTaskFilterHook] = []
_es_filters: list[EsFilterHook] = []
_report_hooks: list[ReportHook] = []
_machine_filters: list[MachineFilterHook] = []
_tag_filters: list[TagFilterHook] = []
_route_filters: list[RouteFilterHook] = []
_submission_context_filters: list[SubmissionContextFilterHook] = []
_login_groups_hooks: list[LoginGroupsHook] = []
_task_copy_scope_hooks: list[TaskCopyScopeHook] = []
_task_report_query_hooks: list[TaskReportQueryHook] = []
_report_retrieved_hooks: list[ReportRetrievedHook] = []
_cache_scope_hooks: list[CacheScopeHook] = []
_cleanup_hooks: list[Callable[[], None]] = []


def register_mongo_filter(fn: MongoFilterHook) -> None:
    if fn not in _mongo_filters:
        _mongo_filters.append(fn)


def register_sql_task_filter(fn: SqlTaskFilterHook) -> None:
    if fn not in _sql_task_filters:
        _sql_task_filters.append(fn)


def register_es_filter(fn: EsFilterHook) -> None:
    if fn not in _es_filters:
        _es_filters.append(fn)


def register_report_hook(fn: ReportHook) -> None:
    if fn not in _report_hooks:
        _report_hooks.append(fn)


def register_machine_filter(fn: MachineFilterHook) -> None:
    if fn not in _machine_filters:
        _machine_filters.append(fn)


def register_tag_filter(fn: TagFilterHook) -> None:
    if fn not in _tag_filters:
        _tag_filters.append(fn)


def register_route_filter(fn: RouteFilterHook) -> None:
    if fn not in _route_filters:
        _route_filters.append(fn)


def register_submission_context_filter(fn: SubmissionContextFilterHook) -> None:
    if fn not in _submission_context_filters:
        _submission_context_filters.append(fn)


def has_mongo_filters() -> bool:
    return bool(_mongo_filters)


def apply_mongo_filter(collection: str, query: dict[str, Any] | None) -> dict[str, Any]:
    if not _mongo_filters:
        return query if query is not None else {}
    out = dict(query) if query else {}
    for fn in _mongo_filters:
        out = fn(collection, out)
    return out


def apply_sql_task_filter(query: Any) -> Any:
    for fn in _sql_task_filters:
        query = fn(query)
    return query


def apply_es_filter(body: dict[str, Any]) -> dict[str, Any]:
    if not _es_filters:
        return body
    out = dict(body)
    for fn in _es_filters:
        out = fn(out)
    return out


def register_login_groups_hook(fn: LoginGroupsHook) -> None:
    if fn not in _login_groups_hooks:
        _login_groups_hooks.append(fn)


def run_login_groups_hooks(user: Any, idp_groups: set) -> None:
    """Called on SSO login with the user's IdP group claim (only when the claim is present)."""
    for fn in _login_groups_hooks:
        fn(user, idp_groups)


def register_task_copy_scope_hook(fn: TaskCopyScopeHook) -> None:
    if fn not in _task_copy_scope_hooks:
        _task_copy_scope_hooks.append(fn)


@contextlib.contextmanager
def task_copy_scope(db: Any, source_task_id: int):
    """Wrap re-adding an existing task (reschedule, refetch) so plugins can carry its ownership over."""
    with contextlib.ExitStack() as stack:
        for fn in _task_copy_scope_hooks:
            stack.enter_context(fn(db, source_task_id))
        yield


def register_task_report_query_hook(fn: TaskReportQueryHook) -> None:
    if fn not in _task_report_query_hooks:
        _task_report_query_hooks.append(fn)


def task_report_query(task_id: int, store: str = "mongo") -> Optional[dict[str, Any]]:
    """A plugin's query for task_id's own report doc ("mongo" filter or "es" query), or None.

    Views that write into a task's report use it to pick that task's own report rather than another
    one sharing its info.id (e.g. a broker job's). Plugins return None to keep the stock lookup.
    """
    for fn in _task_report_query_hooks:
        query = fn(int(task_id), store)
        if query is not None:
            return query
    return None


def is_task_own_report(task_id: int, doc_or_source: Optional[Mapping[str, Any]]) -> bool:
    """Verify that an Elasticsearch `_source` (or Mongo doc) belongs to `task_id`'s own report.

    In Elasticsearch `info.job_id` is mapped as `text`, so `match_phrase: {"info.job_id": "ui-5"}`
    also matches `"ui-5-extra"`. When `task_report_query` is active, callers that mutate or delete
    returned hits check this predicate so another broker report sharing `info.id` is never touched.
    """
    if task_report_query(int(task_id), "es") is None:
        return True
    if not isinstance(doc_or_source, Mapping):
        return False
    info = doc_or_source.get("info")
    if not isinstance(info, Mapping):
        return True
    tid = int(task_id)
    job_id = info.get("job_id")
    return job_id is None or job_id in (f"ui-{tid}", f"local-{tid}")


def register_cache_scope_hook(fn: CacheScopeHook) -> None:
    if fn not in _cache_scope_hooks:
        _cache_scope_hooks.append(fn)


def get_cache_scope_key() -> Any:
    for fn in _cache_scope_hooks:
        key = fn()
        if key is not None:
            return key
    return None


def register_report_retrieved_hook(fn: ReportRetrievedHook) -> None:
    if fn not in _report_retrieved_hooks:
        _report_retrieved_hooks.append(fn)


def register_cleanup_hook(fn: Callable[[], None]) -> None:
    if fn not in _cleanup_hooks:
        _cleanup_hooks.append(fn)


def run_report_retrieved_hooks(task_id: int) -> None:
    """Another node's report for task_id has landed in this server's stores (e.g. dist fetched it)."""
    for fn in _report_retrieved_hooks:
        try:
            fn(int(task_id))
        except Exception:
            logging.getLogger(__name__).exception("report-retrieved hook failed for task %s", task_id)


def run_report_hooks(results: dict[str, Any]) -> None:
    for fn in _report_hooks:
        fn(results)


def apply_machine_filter(machines: list[Any]) -> list[Any]:
    if not _machine_filters:
        return machines
    out = list(machines)
    for fn in _machine_filters:
        out = fn(out)
    return out


def apply_tag_filter(tags: list[Any]) -> list[Any]:
    if not _tag_filters:
        return tags
    out = list(tags)
    for fn in _tag_filters:
        out = fn(out)
    return out


def apply_route_filter(routes: list[Any], route_type: str | None = None) -> list[Any]:
    if not _route_filters:
        return routes
    out = list(routes)
    for fn in _route_filters:
        out = fn(out, route_type)
    return out


def apply_submission_context_filter(context: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    if not _submission_context_filters:
        return context
    out = context
    for fn in _submission_context_filters:
        out = fn(out)
    return out


def clear_all_hooks() -> None:
    for fn in list(reversed(_cleanup_hooks)):
        try:
            fn()
        except Exception:
            logging.getLogger(__name__).exception("cleanup hook failed")
    _cleanup_hooks.clear()
    _mongo_filters.clear()
    _sql_task_filters.clear()
    _es_filters.clear()
    _report_hooks.clear()
    _machine_filters.clear()
    _tag_filters.clear()
    _route_filters.clear()
    _submission_context_filters.clear()
    _login_groups_hooks.clear()
    _task_copy_scope_hooks.clear()
    _task_report_query_hooks.clear()
    _report_retrieved_hooks.clear()
    _cache_scope_hooks.clear()


# --- Plugin activation -------------------------------------------------------------------------
# One entry point for CAPE processes (web settings, guac-web settings, scheduler, dist), so the
# enablement check and error policy live in one place. lib.tenancy is imported only when enabled.


def _section_enabled(cfg: Any, name: str) -> bool:
    section = getattr(cfg, name, None) or {}
    try:
        return bool(section.get("enabled", False))
    except AttributeError:
        return bool(getattr(section, "enabled", False))


def bootstrap_tenancy(cfg: Any, settings_globals: Optional[MutableMapping[str, Any]] = None) -> bool:
    """Activate tenancy hooks (and, given Django settings globals, the web integration).

    Returns True when activated. When `[multitenancy]` is enabled a failure raises: serving
    with isolation silently off is worse than not starting. Object storage alone (including the
    legacy `[central_mode]` section) keeps the log-and-continue behaviour.
    """
    multitenancy = _section_enabled(cfg, "multitenancy")
    storage = _section_enabled(cfg, "object_storage") or _section_enabled(cfg, "central_mode")
    if not (multitenancy or storage):
        return False
    try:
        if settings_globals is not None:
            import lib.tenancy

            lib.tenancy.install(settings_globals)
        else:
            from lib.tenancy.hooks import register_core_hooks

            register_core_hooks()
    except Exception as e:
        if multitenancy:
            raise RuntimeError(f"[multitenancy] is enabled but lib.tenancy failed to initialize: {e}") from e
        logging.getLogger(__name__).exception("Failed to initialize lib.tenancy: %s", e)
        return False
    return True
