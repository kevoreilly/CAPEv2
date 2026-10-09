"""Lightweight plugin hook registry for external CAPEv2 extensions (e.g. CAPE-tenancy).

All hooks are zero-overhead no-ops when no external plugin is installed.
"""

from __future__ import annotations

from typing import Any, Callable

MongoFilterHook = Callable[[str, dict[str, Any]], dict[str, Any]]
SqlTaskFilterHook = Callable[[Any], Any]
EsFilterHook = Callable[[dict[str, Any]], dict[str, Any]]
ReportHook = Callable[[dict[str, Any]], None]

_mongo_filters: list[MongoFilterHook] = []
_sql_task_filters: list[SqlTaskFilterHook] = []
_es_filters: list[EsFilterHook] = []
_report_hooks: list[ReportHook] = []


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


def clear_all_hooks() -> None:
    _mongo_filters.clear()
    _sql_task_filters.clear()
    _es_filters.clear()
    _report_hooks.clear()
