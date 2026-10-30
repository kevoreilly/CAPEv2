"""Batched MongoDB tenancy backfill utility."""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

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


_STAMP_FIELDS = ("user_id", "tenant_id", "visibility", "visibility_seq")


def _acl_stamp(acl: TaskAcl) -> Dict[str, Any]:
    return {
        "user_id": acl.user_id,
        "tenant_id": acl.tenant_id,
        "visibility": acl.visibility,
        "visibility_seq": int(acl.visibility_seq or 1),
    }


def plan_reconcile_stamps(
    session: Session,
    docs: Iterable[Dict[str, Any]],
    *,
    chunk_size: int = 500,
    fallback_visibility: str = PRIVATE,
) -> Iterable[List[Tuple[Any, Dict[str, Any]]]]:
    """Yield batches of `(doc key, stamp)` for report docs whose stamp differs from `task_acl`.

    Each doc is `{"key", "id", "job_id", <stamp fields>}`. Unlike the backfills above, this
    overwrites existing stamps: pre-stack installs stamped `info.tenant_id` from their own Tenant
    ids, which collide with the Group ids used now. A doc carrying a job id is matched to the ACL
    row with that `external_job_id`, else to its task id's row when that row has no other external
    job; a doc no row accounts for is stamped `fallback_visibility` with no owner or tenant.
    """
    if fallback_visibility not in VISIBILITIES:
        raise ValueError(f"Invalid fallback_visibility: {fallback_visibility!r}")
    fallback = {"user_id": None, "tenant_id": None, "visibility": fallback_visibility, "visibility_seq": 1}

    def _flush(batch: List[Dict[str, Any]]) -> List[Tuple[Any, Dict[str, Any]]]:
        task_ids = {int(d["id"]) for d in batch if isinstance(d.get("id"), int)}
        job_ids = {str(d["job_id"]) for d in batch if d.get("job_id")}
        by_task: Dict[int, TaskAcl] = {}
        by_job: Dict[str, TaskAcl] = {}
        if task_ids:
            by_task = {r.task_id: r for r in session.scalars(select(TaskAcl).where(TaskAcl.task_id.in_(task_ids)))}
        if job_ids:
            by_job = {r.external_job_id: r for r in session.scalars(select(TaskAcl).where(TaskAcl.external_job_id.in_(job_ids)))}
        ops = []
        for doc in batch:
            job_id = str(doc["job_id"]) if doc.get("job_id") else None
            acl = by_job.get(job_id) if job_id else None
            if acl is None:
                row = by_task.get(doc.get("id")) if isinstance(doc.get("id"), int) else None
                if row is not None and (not row.external_job_id or row.external_job_id == job_id):
                    acl = row
            stamp = _acl_stamp(acl) if acl is not None else dict(fallback)
            if any(doc.get(field) != stamp[field] for field in _STAMP_FIELDS):
                ops.append((doc["key"], stamp))
        return ops

    batch: List[Dict[str, Any]] = []
    for doc in docs:
        batch.append(doc)
        if len(batch) >= max(1, chunk_size):
            ops = _flush(batch)
            batch = []
            if ops:
                yield ops
    if batch:
        ops = _flush(batch)
        if ops:
            yield ops


def _doc_from_info(key: Any, info: Any) -> Dict[str, Any]:
    info = info if isinstance(info, dict) else {}
    doc = {"key": key, "id": info.get("id"), "job_id": info.get("job_id")}
    for field in _STAMP_FIELDS:
        doc[field] = info.get(field)
    return doc


_INFO_PROJECTION = ["info.id", "info.job_id"] + [f"info.{field}" for field in _STAMP_FIELDS]


def reconcile_mongo_stamps(
    session: Session,
    *,
    find: Callable[[str, Dict[str, Any], Dict[str, Any]], Iterable[Dict[str, Any]]],
    bulk_update: Callable[[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]], Any],
    collection: str = "analysis",
    chunk_size: int = 500,
    dry_run: bool = False,
) -> int:
    """Restamp every Mongo report doc from `task_acl` (see `plan_reconcile_stamps`); returns docs changed."""
    raw = find(collection, {}, {field: 1 for field in _INFO_PROJECTION})
    docs = (_doc_from_info(d["_id"], d.get("info")) for d in raw)
    changed = 0
    for ops in plan_reconcile_stamps(session, docs, chunk_size=chunk_size):
        changed += len(ops)
        if not dry_run:
            bulk_update(
                collection,
                [({"_id": key}, {"$set": {f"info.{k}": v for k, v in stamp.items()}}) for key, stamp in ops],
            )
    return changed


def reconcile_es_stamps(
    session: Session,
    *,
    scan: Callable[[], Iterable[Dict[str, Any]]],
    update: Callable[[str, str, Dict[str, Any]], Any],
    chunk_size: int = 500,
    dry_run: bool = False,
) -> int:
    """Restamp every Elasticsearch analysis doc from `task_acl`; `scan` yields hits with `_source.info`."""
    docs = (_doc_from_info((h["_index"], h["_id"]), (h.get("_source") or {}).get("info")) for h in scan())
    changed = 0
    for ops in plan_reconcile_stamps(session, docs, chunk_size=chunk_size):
        changed += len(ops)
        if not dry_run:
            for (index, doc_id), stamp in ops:
                update(index, doc_id, stamp)
    return changed


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`python -m lib.tenancy.backfill reconcile [--dry-run]`: restamp Mongo/ES report docs from `task_acl`.

    Run it once after upgrading a pre-stack install, with the web and processing services stopped
    (the restamp overwrites, so a visibility toggle racing it can be undone).
    """
    import argparse

    from lib.cuckoo.common.config import Config
    from lib.cuckoo.core.database import Database
    from lib.tenancy.acl import ensure_acl_schema_once

    parser = argparse.ArgumentParser(prog="python -m lib.tenancy.backfill")
    parser.add_argument("command", choices=["reconcile"])
    parser.add_argument("--dry-run", action="store_true", help="count docs that would change, write nothing")
    args = parser.parse_args(argv)

    db = Database()
    ensure_acl_schema_once(db.engine)
    reporting = Config("reporting")
    with Session(db.engine) as session:
        if reporting.mongodb.enabled:
            from pymongo import UpdateOne

            from dev_utils.mongodb import results_db

            def _find(collection: str, query: Dict[str, Any], projection: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
                # The raw collection: the tenancy-scoped mongo_find would hide other tenants' docs.
                return getattr(results_db, collection).find(query, projection)

            def _bulk(collection: str, ops: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> Any:
                return getattr(results_db, collection).bulk_write([UpdateOne(f, u) for f, u in ops], ordered=False)

            n = reconcile_mongo_stamps(session, find=_find, bulk_update=_bulk, dry_run=args.dry_run)
            print(f"mongodb: {n} analysis docs {'would be ' if args.dry_run else ''}restamped")
        if reporting.elasticsearchdb.enabled:
            from elasticsearch.helpers import scan

            from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index

            def _scan() -> Iterable[Dict[str, Any]]:
                return scan(
                    elastic_handler, index=get_analysis_index(), query={"query": {"match_all": {}}}, _source=_INFO_PROJECTION
                )

            def _update(index: str, doc_id: str, stamp: Dict[str, Any]) -> Any:
                # body=: CAPE's client is elasticsearch-py 7.x (see dev_utils.elasticsearchdb).
                return elastic_handler.update(index=index, id=doc_id, body={"doc": {"info": stamp}})

            n = reconcile_es_stamps(session, scan=_scan, update=_update, dry_run=args.dry_run)
            print(f"elasticsearch: {n} analysis docs {'would be ' if args.dry_run else ''}restamped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
