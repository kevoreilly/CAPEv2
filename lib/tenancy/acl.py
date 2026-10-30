"""Side-table TaskAcl model and monotonic visibility_seq CAS synchronization.

Replaces two invasive constructs from the inline implementation:
1. Moves `tenant_id` and `visibility` out of core `tasks` into `task_acl`
   (leaving CAPEv2's `tasks` table and `Task.to_dict()` untouched).
2. Replaces cross-datastore PostgreSQL `pg_advisory_lock` + `pg_is_in_recovery()`
   probes held across network MongoDB writes with a monotonic `visibility_seq`
   compare-and-swap (CAS) predicate in MongoDB.
"""

from __future__ import annotations

import logging
import weakref
from dataclasses import dataclass, replace
from typing import Any, Callable, Dict, Optional

from sqlalchemy import Column, Index, Integer, String, inspect
from sqlalchemy.orm import DeclarativeBase, Session

from lib.tenancy.policy import PRIVATE, PUBLIC, TENANT, VISIBILITIES, ResourceScope

log = logging.getLogger(__name__)


class AclBase(DeclarativeBase):
    pass


class TaskAcl(AclBase):
    """Per-task tenancy and visibility record stored in a dedicated side table."""

    __tablename__ = "task_acl"

    task_id = Column(Integer, primary_key=True, autoincrement=False)
    user_id = Column(Integer, nullable=True, index=True)
    tenant_id = Column(Integer, nullable=True)
    visibility = Column(String(16), nullable=False, default=PRIVATE, server_default=PRIVATE)
    visibility_seq = Column(Integer, nullable=False, default=1, server_default="1")
    external_job_id = Column(String(128), nullable=True, index=True)

    __table_args__ = (Index("ix_task_acl_tenant_vis", "tenant_id", "visibility"),)

    def to_scope(self) -> ResourceScope:
        return ResourceScope(
            owner_id=self.user_id,
            tenant_id=self.tenant_id,
            visibility=self.visibility or PRIVATE,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "visibility": self.visibility,
            "visibility_seq": self.visibility_seq,
            "external_job_id": self.external_job_id,
        }


class VisibilityConflictError(RuntimeError):
    """Raised when an optimistic visibility toggle detects a concurrent state change."""


@dataclass(frozen=True)
class VisibilityStamp:
    task_id: int
    user_id: Optional[int]
    tenant_id: Optional[int]
    visibility: str
    visibility_seq: int
    external_job_id: Optional[str] = None


def ensure_acl_schema(engine) -> None:
    """Create the `task_acl` table if it does not already exist."""
    AclBase.metadata.create_all(engine, tables=[TaskAcl.__table__], checkfirst=True)


# Weakly keyed: an id() would be reused by a later engine once this one is collected.
_acl_schema_ready: "weakref.WeakSet[Any]" = weakref.WeakSet()


def ensure_acl_schema_once(engine) -> None:
    """`ensure_acl_schema` at most once per engine per process.

    The table is otherwise created only on the first submission, but task listing and per-task
    authorization read it from the first request after an install or upgrade.
    """
    if engine in _acl_schema_ready:
        return
    try:
        ensure_acl_schema(engine)
    except Exception:
        # create_all(checkfirst=True) is check-then-create: another worker may have won the race.
        if "task_acl" not in inspect(engine).get_table_names():
            raise
    _acl_schema_ready.add(engine)


def get_task_acl(session: Session, task_id: int) -> Optional[TaskAcl]:
    """Fetch the `TaskAcl` row for `task_id`, or None if absent."""
    return session.get(TaskAcl, int(task_id))


def resolve_task_scope(session: Session, task_id: int, fallback_user_id: Optional[int] = None) -> ResourceScope:
    """Resolve `ResourceScope` for `task_id`; defaults to fail-closed PRIVATE when absent.

    When multitenancy is disabled, ownerless legacy tasks (`owner_id is None`) resolve
    to `PUBLIC` so `WEB_AUTHENTICATION`-enabled single-tenant deployments preserve access
    to legacy tasks while enforcing owner/staff-only access on user-owned private tasks.
    """
    from lib.tenancy.policy import PUBLIC, multitenancy_config

    fallback_user_id = fallback_user_id or None  # tasks.user_id 0 is add()'s "no owner"
    row = get_task_acl(session, task_id)
    if row is not None:
        scope = row.to_scope()
        if not multitenancy_config().enabled and scope.owner_id is None:
            return ResourceScope(owner_id=None, tenant_id=scope.tenant_id, visibility=PUBLIC)
        return scope

    default_vis = PUBLIC if (not multitenancy_config().enabled and fallback_user_id is None) else PRIVATE
    return ResourceScope(owner_id=fallback_user_id, tenant_id=None, visibility=default_vis)


def set_task_acl(
    session: Session,
    task_id: int,
    *,
    user_id: Optional[int] = None,
    tenant_id: Optional[int] = None,
    visibility: Optional[str] = PRIVATE,
    external_job_id: Optional[str] = None,
) -> TaskAcl:
    """Create or update the initial ACL record for a newly submitted task.

    `visibility=None` keeps an existing row's visibility (a new row is private).
    """
    if visibility is not None and visibility not in VISIBILITIES:
        raise ValueError(f"Invalid visibility: {visibility!r}")
    row = session.get(TaskAcl, int(task_id))
    if row is None:
        row = TaskAcl(
            task_id=int(task_id),
            user_id=user_id,
            tenant_id=tenant_id,
            visibility=visibility or PRIVATE,
            visibility_seq=1,
            external_job_id=external_job_id,
        )
        session.add(row)
    else:
        if user_id is not None:
            row.user_id = user_id
        if tenant_id is not None:
            row.tenant_id = tenant_id
        if visibility is not None:
            row.visibility = visibility
        row.visibility_seq = int(row.visibility_seq or 0) + 1
        if external_job_id is not None:
            row.external_job_id = external_job_id
    session.flush()
    return row


def toggle_task_visibility_cas(
    session: Session,
    task_id: int,
    new_visibility: str,
    *,
    expected_prior: Optional[str] = None,
    mongo_update_one: Optional[Callable[[str, dict, dict], Any]] = None,
    owner_id: Optional[int] = None,
    tenant_id: Optional[int] = None,
    es_update_by_query: Optional[Callable[[dict, dict], Any]] = None,
) -> VisibilityStamp:
    """Advance `visibility_seq` in SQL and apply a monotonic CAS update to MongoDB/Elasticsearch.

    `owner_id`/`tenant_id` seed the row when the task has none yet (upgraded or unstamped tasks,
    whose scope fell back to tasks.user_id), so the toggle does not orphan the task.

    The row is held `FOR UPDATE` while the report stores are written and SQL commits last. If a
    store write fails, every store already written gets the prior visibility back at the new seq
    (which the next successful toggle reuses and so still overrides) while the row is still locked,
    then SQL rolls back and the error propagates: a failed toggle changes nothing. A failed COMMIT
    has already released the lock and may have landed, so the stores get the stricter of the two
    visibilities instead: never more visible than SQL, and the reconcile settles it.
    """
    if new_visibility not in VISIBILITIES:
        raise ValueError(f"Invalid visibility: {new_visibility!r}")

    row = session.get(TaskAcl, int(task_id), with_for_update=True, populate_existing=True)
    if row is None:
        if expected_prior is not None and expected_prior != PRIVATE:
            raise VisibilityConflictError(
                f"Task {task_id} visibility conflict: expected {expected_prior!r}, found {PRIVATE!r}"
            )
        prior_visibility = PRIVATE
        row = TaskAcl(
            task_id=int(task_id),
            user_id=owner_id,
            tenant_id=tenant_id,
            visibility=new_visibility,
            visibility_seq=1,
        )
        session.add(row)
    else:
        if expected_prior is not None and row.visibility != expected_prior:
            raise VisibilityConflictError(
                f"Task {task_id} visibility conflict: expected {expected_prior!r}, found {row.visibility!r}"
            )
        prior_visibility = row.visibility
        row.visibility = new_visibility
        row.visibility_seq = int(row.visibility_seq or 0) + 1

    stamp = VisibilityStamp(
        task_id=row.task_id,
        user_id=row.user_id,
        tenant_id=row.tenant_id,
        visibility=row.visibility,
        visibility_seq=row.visibility_seq,
        external_job_id=row.external_job_id,
    )
    restore = replace(stamp, visibility=prior_visibility)

    written = []

    def _restamp(target: VisibilityStamp) -> None:
        for sync in written:
            try:
                sync(target)
            except Exception:
                log.exception(
                    "Task %s: could not restore the report stamp after a failed visibility toggle; "
                    "run utils/tenancy_reconcile.py",
                    task_id,
                )

    try:
        session.flush()
        if mongo_update_one is not None:
            written.append(lambda s: sync_stamp_to_mongo(s, mongo_update_one=mongo_update_one))
            sync_stamp_to_mongo(stamp, mongo_update_one=mongo_update_one)
        if es_update_by_query is not None:
            written.append(lambda s: sync_stamp_to_es(s, es_update_by_query=es_update_by_query))
            sync_stamp_to_es(stamp, es_update_by_query=es_update_by_query)
    except Exception:
        # Restore while the row is still locked: a toggle blocked on it takes the same seq, which
        # the stores' CAS accepts, so a restore landing after it would undo its stamp.
        _restamp(restore)
        session.rollback()
        raise
    try:
        session.commit()
    except Exception:
        stricter = min(prior_visibility, new_visibility, key=_VISIBILITY_ORDER.index)
        log.error("Task %s: visibility commit failed; report stamped %s, run utils/tenancy_reconcile.py", task_id, stricter)
        _restamp(replace(stamp, visibility=stricter))
        session.rollback()
        raise

    return stamp


_VISIBILITY_ORDER = (PRIVATE, TENANT, PUBLIC)


def own_report_job_ids(task_id: int) -> list:
    """Job ids this node's own report of `task_id` may carry besides none: a bridged `ui-<id>`.

    A shared report store also holds other nodes' `local-<id>` and broker-job reports whose
    info.id collides with local task ids; writes keyed on a bare info.id would hit those.
    """
    return [f"ui-{int(task_id)}"]


def own_report_mongo_query(task_id: int) -> Dict[str, Any]:
    """The Mongo filter for this node's own report of `task_id` (see `own_report_job_ids`)."""
    return {"info.id": int(task_id), "info.job_id": {"$in": [None, *own_report_job_ids(task_id)]}}


def own_report_es_query(task_id: int) -> Dict[str, Any]:
    """The ES query for this node's own report of `task_id`; job_id is text-mapped, so callers that
    write must still compare it exactly (phrase "ui-5" also matches "ui-5-x")."""
    return {
        "bool": {
            "filter": [{"term": {"info.id": int(task_id)}}],
            "should": [{"bool": {"must_not": {"exists": {"field": "info.job_id"}}}}]
            + [{"match_phrase": {"info.job_id": j}} for j in own_report_job_ids(task_id)],
            "minimum_should_match": 1,
        }
    }


def sync_stamp_to_mongo(
    stamp: VisibilityStamp,
    *,
    mongo_update_one: Callable[[str, dict, dict], Any],
    collection: str = "analysis",
) -> Any:
    """Apply a conditional monotonic update to MongoDB so higher `visibility_seq` always wins."""
    id_clause: Dict[str, Any]
    if stamp.external_job_id:
        id_clause = {"info.job_id": stamp.external_job_id}
    else:
        id_clause = own_report_mongo_query(stamp.task_id)

    cas_filter = {
        "$and": [
            id_clause,
            {
                "$or": [
                    {"info.visibility_seq": {"$lte": int(stamp.visibility_seq)}},
                    {"info.visibility_seq": {"$exists": False}},
                ]
            },
        ]
    }
    update_doc = {
        "$set": {
            "info.user_id": stamp.user_id,
            "info.tenant_id": stamp.tenant_id,
            "info.visibility": stamp.visibility,
            "info.visibility_seq": int(stamp.visibility_seq),
        }
    }
    return mongo_update_one(collection, cas_filter, update_doc)


def sync_stamp_to_es(stamp: VisibilityStamp, *, es_update_by_query: Callable[[dict, dict], Any]) -> Any:
    """Restamp the Elasticsearch analysis document, which the ES search filter scopes on, monotonically."""
    # job_id is dynamically mapped as text, so the query only narrows by phrase ("job-7" also hits
    # "job-7-extra"); the script compares it exactly before writing.
    if stamp.external_job_id:
        id_clauses = [{"match_phrase": {"info.job_id": stamp.external_job_id}}]
    else:
        own = own_report_es_query(stamp.task_id)["bool"]
        id_clauses = own["filter"] + [{"bool": {"should": own["should"], "minimum_should_match": 1}}]
    query = {
        "bool": {
            "filter": id_clauses,
            "should": [
                {"range": {"info.visibility_seq": {"lte": int(stamp.visibility_seq)}}},
                {"bool": {"must_not": {"exists": {"field": "info.visibility_seq"}}}},
            ],
            "minimum_should_match": 1,
        }
    }
    script = {
        "lang": "painless",
        "source": (
            "def j = ctx._source.info.job_id;"
            " if (params.job_id != null ? j != params.job_id : (j != null && !params.own_job_ids.contains(j))) { ctx.op = 'noop'; }"
            " else { for (e in params.stamp.entrySet()) { ctx._source.info[e.getKey()] = e.getValue(); } }"
        ),
        "params": {
            "job_id": stamp.external_job_id or None,
            "own_job_ids": [] if stamp.external_job_id else own_report_job_ids(stamp.task_id),
            "stamp": {
                "user_id": stamp.user_id,
                "tenant_id": stamp.tenant_id,
                "visibility": stamp.visibility,
                "visibility_seq": int(stamp.visibility_seq),
            },
        },
    }
    return es_update_by_query(query, script)
