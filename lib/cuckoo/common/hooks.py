"""Lightweight plugin hook registry for external CAPEv2 extensions (e.g. CAPE-tenancy).

All hooks are zero-overhead no-ops when no external plugin is installed.
"""

from __future__ import annotations

from typing import Any, Callable, MutableMapping

MongoFilterHook = Callable[[str, dict[str, Any]], dict[str, Any]]
SqlTaskFilterHook = Callable[[Any], Any]
EsFilterHook = Callable[[dict[str, Any]], dict[str, Any]]
ReportHook = Callable[[dict[str, Any]], None]
MachineFilterHook = Callable[[list[Any]], list[Any]]
TagFilterHook = Callable[[list[Any]], list[Any]]
RouteFilterHook = Callable[[list[Any], str | None], list[Any]]
SubmissionContextFilterHook = Callable[[MutableMapping[str, Any]], MutableMapping[str, Any]]

_mongo_filters: list[MongoFilterHook] = []
_sql_task_filters: list[SqlTaskFilterHook] = []
_es_filters: list[EsFilterHook] = []
_report_hooks: list[ReportHook] = []
_machine_filters: list[MachineFilterHook] = []
_tag_filters: list[TagFilterHook] = []
_route_filters: list[RouteFilterHook] = []
_submission_context_filters: list[SubmissionContextFilterHook] = []


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
    _mongo_filters.clear()
    _sql_task_filters.clear()
    _es_filters.clear()
    _report_hooks.clear()
    _machine_filters.clear()
    _tag_filters.clear()
    _route_filters.clear()
    _submission_context_filters.clear()
