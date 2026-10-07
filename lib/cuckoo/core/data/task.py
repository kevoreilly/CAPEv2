import json
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING
from lib.cuckoo.common.exceptions import CuckooDependencyError
if TYPE_CHECKING:
    from lib.cuckoo.core.data.samples import Sample, SampleAssociation
    from lib.cuckoo.core.data.guests import Guest
    from lib.cuckoo.core.data.db_common import Tag, Error

from .db_common import Base, _utcnow_naive, tasks_tags
try:
    from sqlalchemy.ext.hybrid import hybrid_property
    from sqlalchemy.orm import Mapped, mapped_column, relationship
    from sqlalchemy import (
        Boolean,
        DateTime,
        Enum,
        ForeignKey,
        Index,
        Integer,
        String,
        Text,
        func,
        select,
    )
except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")

TASK_BANNED = "banned"
TASK_PENDING = "pending"
TASK_RUNNING = "running"
TASK_DISTRIBUTED = "distributed"
TASK_COMPLETED = "completed"
TASK_RECOVERED = "recovered"
TASK_REPORTED = "reported"
TASK_FAILED_ANALYSIS = "failed_analysis"
TASK_FAILED_PROCESSING = "failed_processing"
TASK_FAILED_REPORTING = "failed_reporting"
TASK_DISTRIBUTED_COMPLETED = "distributed_completed"


ALL_DB_STATUSES = (
    TASK_BANNED,
    TASK_PENDING,
    TASK_RUNNING,
    TASK_DISTRIBUTED,
    TASK_COMPLETED,
    TASK_RECOVERED,
    TASK_REPORTED,
    TASK_FAILED_ANALYSIS,
    TASK_FAILED_PROCESSING,
    TASK_FAILED_REPORTING,
    TASK_DISTRIBUTED_COMPLETED,
)

# What a task with no task_acl row means. Must stay equal to the fail-closed defaults the
# policy layer (lib/cuckoo/common/tenancy.py) and the mongo stamp assume.
ACL_DEFAULT_VISIBILITY = "private"
_ACL_DEFAULTS = {"tenant_id": None, "visibility": ACL_DEFAULT_VISIBILITY}


class TaskAcl(Base):
    """Per-task multitenancy ACL (tenant owner + visibility). Only populated when a task
    carries non-default tenancy, i.e. in practice only on multitenancy-enabled installs.
    Owner is tasks.user_id, which predates multitenancy and stays on tasks.

    ON DELETE CASCADE: an ACL must never outlive its task. Without it, a reused task id
    (SQLite without AUTOINCREMENT, or an auto-increment reset) could inherit a deleted
    task's grants."""

    __tablename__ = "task_acl"

    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), primary_key=True)
    tenant_id: Mapped[Optional[int]] = mapped_column(nullable=True, index=True)
    visibility: Mapped[str] = mapped_column(String(16), nullable=False, server_default=ACL_DEFAULT_VISIBILITY)

    def __repr__(self):
        return f"<TaskAcl(task={self.task_id}, tenant={self.tenant_id}, visibility={self.visibility!r})>"


class Task(Base):
    """Analysis task queue."""

    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    target: Mapped[str] = mapped_column(Text(), nullable=False)
    category: Mapped[str] = mapped_column(String(255), nullable=False)
    cape: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    timeout: Mapped[int] = mapped_column(Integer(), server_default="0", nullable=False)
    priority: Mapped[int] = mapped_column(Integer(), server_default="1", nullable=False)
    custom: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    machine: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    package: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    route: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, default=False)
    # Task tags
    tags_tasks: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    # Virtual machine tags
    tags: Mapped[List["Tag"]] = relationship(secondary=tasks_tags, back_populates="tasks", passive_deletes=True)
    options: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    platform: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    memory: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enforce_timeout: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    clock: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        default=_utcnow_naive,
        nullable=False,
    )
    added_on: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        default=_utcnow_naive,
        nullable=False,
    )
    started_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    completed_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    status: Mapped[str] = mapped_column(
        Enum(
            TASK_BANNED,
            TASK_PENDING,
            TASK_RUNNING,
            TASK_COMPLETED,
            TASK_DISTRIBUTED,
            TASK_REPORTED,
            TASK_RECOVERED,
            TASK_FAILED_ANALYSIS,
            TASK_FAILED_PROCESSING,
            TASK_FAILED_REPORTING,
            name="status_type",
        ),
        server_default=TASK_PENDING,
        nullable=False,
    )

    # Statistics data to identify broken Cuckoos servers or VMs
    # Also for doing profiling to improve speed
    dropped_files: Mapped[Optional[int]] = mapped_column(nullable=True)
    running_processes: Mapped[Optional[int]] = mapped_column(nullable=True)
    api_calls: Mapped[Optional[int]] = mapped_column(nullable=True)
    domains: Mapped[Optional[int]] = mapped_column(nullable=True)
    signatures_total: Mapped[Optional[int]] = mapped_column(nullable=True)
    signatures_alert: Mapped[Optional[int]] = mapped_column(nullable=True)
    files_written: Mapped[Optional[int]] = mapped_column(nullable=True)
    registry_keys_modified: Mapped[Optional[int]] = mapped_column(nullable=True)
    crash_issues: Mapped[Optional[int]] = mapped_column(nullable=True)
    anti_issues: Mapped[Optional[int]] = mapped_column(nullable=True)
    analysis_started_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    analysis_finished_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    processing_started_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    processing_finished_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    signatures_started_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    signatures_finished_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    reporting_started_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    reporting_finished_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    timedout: Mapped[bool] = mapped_column(nullable=False, default=False)

    sample_id: Mapped[Optional[int]] = mapped_column(ForeignKey("samples.id"), nullable=True)
    sample: Mapped["Sample"] = relationship(back_populates="tasks")  # , lazy="subquery"
    machine_id: Mapped[Optional[int]] = mapped_column(nullable=True)
    guest: Mapped["Guest"] = relationship(
        back_populates="task", uselist=False, cascade="all, delete-orphan"  # This is crucial for a one-to-one relationship
    )
    errors: Mapped[List["Error"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"  # This MUST match the attribute name on the Error model
    )

    tlp: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    user_id: Mapped[Optional[int]] = mapped_column(nullable=True)

    # Multitenancy ACL lives in the task_acl side table, NOT on tasks, so a single-tenant
    # install carries no tenancy columns, no migration rewrite of tasks, and no extra keys in
    # to_dict(). ABSENT ROW == (tenant_id=None, visibility="private"), which is exactly the old
    # column defaults, so policy semantics are unchanged. lazy="joined" so the ACL is loaded
    # with the task: many callers read task.visibility on detached instances (view_task etc.),
    # where a lazy load would raise DetachedInstanceError. On an MT-off install task_acl is
    # empty, so the LEFT OUTER JOIN on its primary key is effectively free.
    acl: Mapped[Optional["TaskAcl"]] = relationship(
        uselist=False, lazy="joined", cascade="all, delete-orphan", passive_deletes=True
    )

    @hybrid_property
    def tenant_id(self) -> Optional[int]:
        return self.acl.tenant_id if self.acl is not None else None

    @tenant_id.inplace.setter
    def _tenant_id_setter(self, value: Optional[int]) -> None:
        self._set_acl("tenant_id", value)

    @tenant_id.inplace.expression
    @classmethod
    def _tenant_id_expression(cls):
        return select(TaskAcl.tenant_id).where(TaskAcl.task_id == cls.id).correlate_except(TaskAcl).scalar_subquery()

    @hybrid_property
    def visibility(self) -> str:
        return self.acl.visibility if self.acl is not None else ACL_DEFAULT_VISIBILITY

    @visibility.inplace.setter
    def _visibility_setter(self, value: str) -> None:
        self._set_acl("visibility", value or ACL_DEFAULT_VISIBILITY)

    @visibility.inplace.expression
    @classmethod
    def _visibility_expression(cls):
        return func.coalesce(
            select(TaskAcl.visibility).where(TaskAcl.task_id == cls.id).correlate_except(TaskAcl).scalar_subquery(),
            ACL_DEFAULT_VISIBILITY,
        )

    def _set_acl(self, field: str, value) -> None:
        """Write one ACL field. Writing the default onto a task with no ACL row is a no-op, so
        the absent-row == default invariant holds and no row is created needlessly."""
        if self.acl is None:
            if value == _ACL_DEFAULTS[field]:
                return
            self.acl = TaskAcl(tenant_id=None, visibility=ACL_DEFAULT_VISIBILITY)
        setattr(self.acl, field, value)

    # The Task is linked to one specific parent/child association event
    association: Mapped[Optional["SampleAssociation"]] = relationship(back_populates="task", cascade="all, delete-orphan")

    __table_args__ = (
        Index("category_index", "category"),
        Index("status_index", "status"),
        Index("added_on_index", "added_on"),
        Index("completed_on_index", "completed_on"),
    )

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                d[column.name] = value.strftime("%Y-%m-%d %H:%M:%S")
            else:
                d[column.name] = value

        # Tags are a relation so no column to iterate.
        d["tags"] = [tag.name for tag in self.tags]
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, target=None):
        self.target = target

    def __repr__(self):
        return f"<Task({self.id},'{self.target}')>"
