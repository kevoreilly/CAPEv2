"""Batched MongoDB tenancy backfill utility."""

from __future__ import annotations

import sys
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import String, cast, select
from sqlalchemy.orm import Session

from lib.tenancy.acl import TaskAcl, own_report_job_ids
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
    preserve_public_without_acl: bool = False,
    task_owners: Optional[Callable[[Iterable[int]], Dict[int, Any]]] = None,
    skipped: Optional[List[Any]] = None,
) -> Iterable[List[Tuple[Any, Dict[str, Any]]]]:
    """Yield batches of `(doc key, stamp)` for report docs whose stamp differs from `task_acl`.

    Each doc is `{"key", "id", "job_id", <stamp fields>}`. Unlike the backfills above, this
    overwrites existing stamps: pre-stack installs stamped `info.tenant_id` from their own Tenant
    ids, which collide with the Group ids used now.

    A doc is matched to the ACL row whose `external_job_id` is its job id. Otherwise it is matched
    by `info.id` only when it is the task's own report (see `own_report_job_ids`): no job id,
    `ui-<info.id>` or `local-<info.id>`. Any other doc (a broker job's) is left alone and its key
    appended to `skipped`. A matched doc without an ACL row is
    stamped `fallback_visibility` with no tenant, owned (as `resolve_task_scope` resolves it) by
    its task's `tasks.user_id` (unless `preserve_public_without_acl` is True and the doc already
    carries `visibility='public'` with `tenant_id=None`).
    """
    if fallback_visibility not in VISIBILITIES:
        raise ValueError(f"Invalid fallback_visibility: {fallback_visibility!r}")
    fallback = {"user_id": None, "tenant_id": None, "visibility": fallback_visibility, "visibility_seq": 1}
    owners_of = task_owners or (lambda ids: _task_owners(session, ids))

    def _flush(batch: List[Dict[str, Any]]) -> List[Tuple[Any, Dict[str, Any]]]:
        task_ids = {int(d["id"]) for d in batch if isinstance(d.get("id"), int)}
        job_ids = {str(d["job_id"]) for d in batch if d.get("job_id")}
        by_task: Dict[int, TaskAcl] = {}
        by_job: Dict[str, TaskAcl] = {}
        if task_ids:
            by_task = {r.task_id: r for r in session.scalars(select(TaskAcl).where(TaskAcl.task_id.in_(task_ids)))}
        if job_ids:
            by_job = {r.external_job_id: r for r in session.scalars(select(TaskAcl).where(TaskAcl.external_job_id.in_(job_ids)))}
        unmatched = {i for i in task_ids if i not in by_task}
        owners = owners_of(unmatched) if unmatched else {}
        ops = []
        for doc in batch:
            job_id = str(doc["job_id"]) if doc.get("job_id") else None
            tid = doc.get("id") if isinstance(doc.get("id"), int) else None
            acl = by_job.get(job_id) if job_id else None
            if acl is None:
                own_jobs = {None} | (set(own_report_job_ids(tid)) if tid is not None else set())
                row = by_task.get(tid) if tid is not None else None
                if tid is None or job_id not in own_jobs or (row is not None and row.external_job_id not in ({None, ""} | own_jobs)):
                    if skipped is not None:
                        skipped.append(doc["key"])
                    continue
                acl = row
            if acl is not None:
                stamp = _acl_stamp(acl)
            else:
                stamp = dict(fallback)
                stamp["user_id"] = owners.get(tid) or None  # tasks.user_id 0 is add()'s "no owner"
                if preserve_public_without_acl and doc.get("visibility") == PUBLIC and doc.get("tenant_id") is None:
                    stamp["visibility"] = PUBLIC
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


def _task_owners(session: Session, task_ids: Iterable[int]) -> Dict[int, Any]:
    from lib.cuckoo.core.data.task import Task

    return dict(session.execute(select(Task.id, Task.user_id).where(Task.id.in_(list(task_ids)))).all())


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
    preserve_public_without_acl: bool = False,
    task_owners: Optional[Callable[[Iterable[int]], Dict[int, Any]]] = None,
    skipped: Optional[List[Any]] = None,
) -> int:
    """Restamp every Mongo report doc from `task_acl` (see `plan_reconcile_stamps`); returns docs changed."""
    raw = find(collection, {}, {field: 1 for field in _INFO_PROJECTION})
    docs = (_doc_from_info(d["_id"], d.get("info")) for d in raw)
    changed = 0
    for ops in plan_reconcile_stamps(
        session,
        docs,
        chunk_size=chunk_size,
        preserve_public_without_acl=preserve_public_without_acl,
        task_owners=task_owners,
        skipped=skipped,
    ):
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
    update: Optional[Callable[[str, str, Dict[str, Any]], Any]] = None,
    bulk_update: Optional[Callable[[List[Tuple[Tuple[str, str], Dict[str, Any]]]], Any]] = None,
    chunk_size: int = 500,
    dry_run: bool = False,
    preserve_public_without_acl: bool = False,
    task_owners: Optional[Callable[[Iterable[int]], Dict[int, Any]]] = None,
    skipped: Optional[List[Any]] = None,
) -> int:
    """Restamp every Elasticsearch analysis doc from `task_acl`; `scan` yields hits with `_source.info`."""
    docs = (_doc_from_info((h["_index"], h["_id"]), (h.get("_source") or {}).get("info")) for h in scan())
    changed = 0
    for ops in plan_reconcile_stamps(
        session,
        docs,
        chunk_size=chunk_size,
        preserve_public_without_acl=preserve_public_without_acl,
        task_owners=task_owners,
        skipped=skipped,
    ):
        if dry_run:
            changed += len(ops)
            continue
        if bulk_update is not None:
            res = bulk_update(ops)
            if isinstance(res, tuple) and len(res) == 2:
                ok_count, errors = res
                if errors:
                    raise RuntimeError(f"Elasticsearch bulk restamp failed for {len(errors)} item(s): {errors[:3]!r}")
                changed += int(ok_count) if isinstance(ok_count, int) else len(ops)
            elif isinstance(res, int):
                changed += res
            else:
                changed += len(ops)
        elif update is not None:
            for (index, doc_id), stamp in ops:
                update(index, doc_id, stamp)
            changed += len(ops)
        else:
            changed += len(ops)
    return changed


def _resync_one(session: Session, task_id: int) -> bool:
    """Re-apply task_id's task_acl to its Mongo/ES report (whichever reporting enables); False for an
    unknown task. A task without a row is stamped private to its submitter, as the full reconcile does."""
    from lib.cuckoo.common.config import Config
    from lib.tenancy.acl import resync_report_stamp
    from lib.tenancy.views import _default_es_update_by_query, _default_mongo_update_one

    owners = _task_owners(session, [int(task_id)])
    if int(task_id) not in owners:
        return False
    reporting = Config("reporting")
    stamp = resync_report_stamp(
        session,
        task_id,
        owner_if_no_row=owners[int(task_id)],
        mongo_update_one=_default_mongo_update_one if reporting.mongodb.enabled else None,
        es_update_by_query=_default_es_update_by_query() if reporting.elasticsearchdb.enabled else None,
    )
    return stamp is not None


def runs_dist_tasks(session: Session) -> Optional[int]:
    """The id of a task this node runs for another server, or None: a dist `main_task_id`, or a
    bridged `job_id=ui-<central id>` from an object-storage broker. Their reports carry that
    server's ids."""
    from lib.cuckoo.core.data.task import Task
    from lib.tenancy.storage.artifact_storage import job_id_from_custom

    for tid, custom in session.execute(select(Task.id, Task.custom).where(Task.custom.like("%job_id=ui-%"))):
        if str(job_id_from_custom(custom) or "").startswith("ui-"):
            return tid
    attr_stmt = select(Task.id, Task.attributes).where(
        Task.attributes.is_not(None),
        cast(Task.attributes, String).like('%"main_task_id"%'),
    )
    for tid, attributes in session.execute(attr_stmt).yield_per(1000):
        if isinstance(attributes, dict) and attributes.get("main_task_id"):
            return tid
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`utils/tenancy_reconcile.py [--dry-run]`: restamp Mongo/ES report docs from `task_acl`.

    Run it once after upgrading a pre-stack install, with the web and processing services stopped
    (the restamp overwrites, so a visibility toggle racing it can be undone).
    """
    import argparse

    from lib.cuckoo.common.config import Config
    from lib.cuckoo.core.database import Database, init_database
    from lib.tenancy.acl import ensure_acl_schema_once

    parser = argparse.ArgumentParser(prog="utils/tenancy_reconcile.py")
    parser.add_argument("--dry-run", action="store_true", help="count docs that would change, write nothing")
    parser.add_argument(
        "--task", type=int, help="only re-apply this task's current task_acl to its report (e.g. after a worker reprocess)"
    )
    parser.add_argument(
        "--preserve-public",
        action="store_true",
        help="preserve visibility='public' on tenantless legacy docs that have no task_acl row",
    )
    parser.add_argument(
        "--force", action="store_true", help="run although this node looks like a worker (only on the main/central server)"
    )
    args = parser.parse_args(argv)
    verb = "would be restamped" if args.dry_run else "restamped"

    def _report(store: str, changed: int, skipped: List[Any]) -> None:
        print(f"{store}: {changed} analysis docs {verb}; {len(skipped)} left alone (a broker job's report)")

    init_database()
    db = Database()
    ensure_acl_schema_once(db.engine)
    reporting = Config("reporting")
    with Session(db.engine) as session:
        foreign = None if args.force else runs_dist_tasks(session)
        if args.task is not None and foreign is None:
            if args.dry_run:
                print(f"task {args.task}: would restamp its report from task_acl")
                return 0
            if not _resync_one(session, args.task):
                print(f"task {args.task} not found", file=sys.stderr)
                return 1
            print(f"task {args.task}: report restamped from task_acl")
            return 0
        if foreign is not None:
            # A worker files those reports under the other server's task ids: its own task_acl rows
            # (worker-local ids) would restamp unrelated reports.
            print(
                f"this node runs tasks for a main/central server (e.g. task {foreign}); run utils/tenancy_reconcile.py "
                "there, or pass --force if this is that server",
                file=sys.stderr,
            )
            return 2
        if reporting.mongodb.enabled:
            from pymongo import UpdateOne

            from dev_utils.mongodb import results_db

            def _find(collection: str, query: Dict[str, Any], projection: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
                # The raw collection: the tenancy-scoped mongo_find would hide other tenants' docs.
                return getattr(results_db, collection).find(query, projection)

            def _bulk(collection: str, ops: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> Any:
                return getattr(results_db, collection).bulk_write([UpdateOne(f, u) for f, u in ops], ordered=False)

            skipped: List[Any] = []
            n = reconcile_mongo_stamps(
                session,
                find=_find,
                bulk_update=_bulk,
                dry_run=args.dry_run,
                preserve_public_without_acl=args.preserve_public,
                skipped=skipped,
            )
            _report("mongodb", n, skipped)
        if reporting.elasticsearchdb.enabled:
            from elasticsearch.helpers import bulk, scan

            from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index

            def _scan() -> Iterable[Dict[str, Any]]:
                return scan(
                    elastic_handler, index=get_analysis_index(), query={"query": {"match_all": {}}}, _source=_INFO_PROJECTION
                )

            def _es_bulk(ops: List[Tuple[Tuple[str, str], Dict[str, Any]]]) -> Any:
                actions = [
                    {"_op_type": "update", "_index": index, "_id": doc_id, "doc": {"info": stamp}}
                    for (index, doc_id), stamp in ops
                ]
                ok_count, errors = bulk(elastic_handler, actions, raise_on_error=False)
                if errors:
                    raise RuntimeError(f"Elasticsearch bulk restamp failed for {len(errors)} document(s): {errors[:3]!r}")
                return ok_count

            skipped = []
            n = reconcile_es_stamps(
                session,
                scan=_scan,
                bulk_update=_es_bulk,
                dry_run=args.dry_run,
                preserve_public_without_acl=args.preserve_public,
                skipped=skipped,
            )
            _report("elasticsearch", n, skipped)
    return 0
