"""Side-table TaskAcl model and monotonic visibility_seq CAS synchronization.

Replaces two invasive constructs from the inline implementation:
1. Moves `tenant_id` and `visibility` out of core `tasks` into `task_acl`
   (leaving CAPEv2's `tasks` table and `Task.to_dict()` untouched).
2. Replaces cross-datastore PostgreSQL `pg_advisory_lock` + `pg_is_in_recovery()`
   probes held across network MongoDB writes with a monotonic `visibility_seq`
   compare-and-swap (CAS) predicate in MongoDB.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from sqlalchemy import Column, Index, Integer, String
from sqlalchemy.orm import DeclarativeBase, Session

from lib.tenancy.policy import PRIVATE, VISIBILITIES, ResourceScope


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
    visibility: str = PRIVATE,
    external_job_id: Optional[str] = None,
) -> TaskAcl:
    """Create or update the initial ACL record for a newly submitted task."""
    if visibility not in VISIBILITIES:
        raise ValueError(f"Invalid visibility: {visibility!r}")
    row = session.get(TaskAcl, int(task_id))
    if row is None:
        row = TaskAcl(
            task_id=int(task_id),
            user_id=user_id,
            tenant_id=tenant_id,
            visibility=visibility,
            visibility_seq=1,
            external_job_id=external_job_id,
        )
        session.add(row)
    else:
        if user_id is not None:
            row.user_id = user_id
        if tenant_id is not None:
            row.tenant_id = tenant_id
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
) -> VisibilityStamp:
    """Atomically advance `visibility_seq` in SQL and apply a monotonic CAS update to MongoDB."""
    if new_visibility not in VISIBILITIES:
        raise ValueError(f"Invalid visibility: {new_visibility!r}")

    row = session.get(TaskAcl, int(task_id))
    if row is None:
        if expected_prior is not None and expected_prior != PRIVATE:
            raise VisibilityConflictError(
                f"Task {task_id} visibility conflict: expected {expected_prior!r}, found {PRIVATE!r}"
            )
        row = TaskAcl(
            task_id=int(task_id),
            visibility=new_visibility,
            visibility_seq=1,
        )
        session.add(row)
    else:
        if expected_prior is not None and row.visibility != expected_prior:
            raise VisibilityConflictError(
                f"Task {task_id} visibility conflict: expected {expected_prior!r}, found {row.visibility!r}"
            )
        row.visibility = new_visibility
        row.visibility_seq = int(row.visibility_seq or 0) + 1

    session.commit()
    stamp = VisibilityStamp(
        task_id=row.task_id,
        user_id=row.user_id,
        tenant_id=row.tenant_id,
        visibility=row.visibility,
        visibility_seq=row.visibility_seq,
        external_job_id=row.external_job_id,
    )

    if mongo_update_one is not None:
        sync_stamp_to_mongo(stamp, mongo_update_one=mongo_update_one)

    return stamp


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
        id_clause = {"info.id": int(stamp.task_id)}

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
