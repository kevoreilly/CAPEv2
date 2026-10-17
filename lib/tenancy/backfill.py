"""Batched MongoDB tenancy backfill utility."""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Sequence, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from lib.tenancy.acl import TaskAcl
from lib.tenancy.policy import PRIVATE, PUBLIC, VISIBILITIES


def backfill_legacy_uniform(
    mongo_update_many: Callable[[str, Dict[str, Any], Dict[str, Any]], Any],
    *,
    default_visibility: str = PUBLIC,
    collection: str = "analysis",
) -> Any:
    """Single-query fast path: stamp all legacy analysis docs lacking `info.visibility`."""
    if default_visibility not in VISIBILITIES:
        raise ValueError(f"Invalid default_visibility: {default_visibility!r}")

    query = {
        "$or": [
            {"info.visibility": {"$exists": False}},
            {"info.visibility": None},
        ]
    }
    update = {
        "$set": {
            "info.visibility": default_visibility,
            "info.tenant_id": None,
            "info.visibility_seq": 1,
        }
    }
    return mongo_update_many(collection, query, update)


def _chunked(items: Sequence[int], chunk_size: int) -> Iterable[Sequence[int]]:
    for idx in range(0, len(items), chunk_size):
        yield items[idx : idx + chunk_size]


def backfill_from_task_acl_batched(
    session: Session,
    task_ids: Sequence[int],
    mongo_bulk_updater: Callable[[List[Tuple[Dict[str, Any], Dict[str, Any]]]], int],
    *,
    chunk_size: int = 500,
    fallback_visibility: str = PRIVATE,
) -> int:
    """Batch-resolve `TaskAcl` in chunks of `chunk_size` and invoke `mongo_bulk_updater` once per chunk."""
    if fallback_visibility not in VISIBILITIES:
        raise ValueError(f"Invalid fallback_visibility: {fallback_visibility!r}")

    total_updated = 0
    for batch_ids in _chunked([int(x) for x in task_ids], max(1, chunk_size)):
        stmt = select(TaskAcl).where(TaskAcl.task_id.in_(batch_ids))
        rows_by_id: Dict[int, TaskAcl] = {row.task_id: row for row in session.scalars(stmt).all()}

        ops: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        for tid in batch_ids:
            acl = rows_by_id.get(tid)
            if acl is not None:
                stamp = {
                    "info.user_id": acl.user_id,
                    "info.tenant_id": acl.tenant_id,
                    "info.visibility": acl.visibility,
                    "info.visibility_seq": acl.visibility_seq,
                }
            else:
                stamp = {
                    "info.user_id": None,
                    "info.tenant_id": None,
                    "info.visibility": fallback_visibility,
                    "info.visibility_seq": 1,
                }
            flt = {
                "info.id": tid,
                "$or": [
                    {"info.visibility": {"$exists": False}},
                    {"info.visibility": None},
                ],
            }
            ops.append((flt, {"$set": stamp}))

        if ops:
            total_updated += int(mongo_bulk_updater(ops) or 0)

    return total_updated
