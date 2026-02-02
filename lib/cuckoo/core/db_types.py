from typing import Any, List, Optional, Union, Tuple, Dict
from datetime import datetime, timedelta, timezone
import pytz

from lib.cuckoo.common.config import Config
cfg = Config("cuckoo")
tz_name = cfg.cuckoo.get("timezone", "utc")


SCHEMA_VERSION = "2b3c4d5e6f7g"
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

MACHINE_RUNNING = "running"


def _utcnow_naive():
    """Returns the current time in the configured timezone as a naive datetime object."""
    try:
        tz = pytz.timezone(tz_name)
    except pytz.UnknownTimeZoneError:
        tz = timezone.utc
    return datetime.now(tz).replace(tzinfo=None)

try:
    from sqlalchemy.engine import make_url
    from sqlalchemy import (
        Boolean,
        BigInteger,
        Column,
        DateTime,
        Enum,
        ForeignKey,
        Index,
        Integer,
        String,
        Table,
        Text,
        create_engine,
        # event,
        func,
        not_,
        select,
        Select,
        delete,
        update,
    )
    from sqlalchemy.exc import IntegrityError, SQLAlchemyError
    from sqlalchemy.orm import (
        aliased,
        joinedload,
        subqueryload,
        relationship,
        scoped_session,
        sessionmaker,
        DeclarativeBase,
        Mapped,
        mapped_column,
    )

except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")

class Base(DeclarativeBase):
    pass

class SampleAssociation(Base):
    __tablename__ = "sample_associations"

    # Each column is part of a composite primary key
    parent_id: Mapped[int] = mapped_column(ForeignKey("samples.id"), primary_key=True)
    child_id: Mapped[int] = mapped_column(ForeignKey("samples.id"), primary_key=True)

    # This is the crucial column that links to the specific child's task
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), primary_key=True)

    # Relationships from the association object itself
    parent: Mapped["Sample"] = relationship(foreign_keys=[parent_id], back_populates="child_links")
    child: Mapped["Sample"] = relationship(foreign_keys=[child_id], back_populates="parent_links")
    task: Mapped["Task"] = relationship(back_populates="association")


    
# ToDo verify variable declaration in Mapped

# Secondary table used in association Machine - Tag.
machines_tags = Table(
    "machines_tags",
    Base.metadata,
    Column("machine_id", Integer, ForeignKey("machines.id")),
    Column("tag_id", Integer, ForeignKey("tags.id")),
)

# Secondary table used in association Task - Tag.
tasks_tags = Table(
    "tasks_tags",
    Base.metadata,
    Column("task_id", Integer, ForeignKey("tasks.id", ondelete="cascade")),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="cascade")),
)

class Machine(Base):
    """Configured virtual machines to be used as guests."""

    __tablename__ = "machines"

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    arch: Mapped[str] = mapped_column(String(255), nullable=False)
    ip: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[str] = mapped_column(String(255), nullable=False)
    tags: Mapped[List["Tag"]] = relationship(secondary=machines_tags, back_populates="machines")
    interface: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    snapshot: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    locked: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False)
    locked_changed_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status_changed_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    resultserver_ip: Mapped[str] = mapped_column(String(255), nullable=False)
    resultserver_port: Mapped[str] = mapped_column(String(255), nullable=False)
    reserved: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=False)

    def __repr__(self):
        return f"<Machine({self.id},'{self.name}')>"

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

    def __init__(self, name, label, arch, ip, platform, interface, snapshot, resultserver_ip, resultserver_port, reserved):
        self.name = name
        self.label = label
        self.arch = arch
        self.ip = ip
        self.platform = platform
        self.interface = interface
        self.snapshot = snapshot
        self.resultserver_ip = resultserver_ip
        self.resultserver_port = resultserver_port
        self.reserved = reserved


class Tag(Base):
    """Tag describing anything you want."""

    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(nullable=False, unique=True)
    machines: Mapped[List["Machine"]] = relationship(secondary=machines_tags, back_populates="tags")
    tasks: Mapped[List["Task"]] = relationship(secondary=tasks_tags, back_populates="tags")

    def __repr__(self):
        return f"<Tag({self.id},'{self.name}')>"

    def __init__(self, name):
        self.name = name


class Guest(Base):
    """Tracks guest run."""

    __tablename__ = "guests"

    id: Mapped[int] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(nullable=False)
    label: Mapped[str] = mapped_column(nullable=False)
    platform: Mapped[str] = mapped_column(nullable=False)
    manager: Mapped[str] = mapped_column(nullable=False)

    started_on: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), default=_utcnow_naive, nullable=False
    )
    shutdown_on: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id", ondelete="cascade"), nullable=False, unique=True)
    task: Mapped["Task"] = relationship(back_populates="guest")

    def __repr__(self):
        return f"<Guest({self.id}, '{self.name}')>"

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
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, name, label, platform, manager, task_id):
        self.name = name
        self.label = label
        self.platform = platform
        self.manager = manager
        self.task_id = task_id


class Sample(Base):
    """Submitted files details."""

    __tablename__ = "samples"

    id: Mapped[int] = mapped_column(primary_key=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    file_type: Mapped[str] = mapped_column(Text(), nullable=False)
    md5: Mapped[str] = mapped_column(String(32), nullable=False)
    crc32: Mapped[str] = mapped_column(String(8), nullable=False)
    sha1: Mapped[str] = mapped_column(String(40), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sha512: Mapped[str] = mapped_column(String(128), nullable=False)
    ssdeep: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    tasks: Mapped[List["Task"]] = relationship(back_populates="sample", cascade="all, delete-orphan")

    child_links: Mapped[List["SampleAssociation"]] = relationship(
        foreign_keys=[SampleAssociation.parent_id], back_populates="parent"
    )
    # When this Sample is a child, this gives you its association links
    parent_links: Mapped[List["SampleAssociation"]] = relationship(
        foreign_keys=[SampleAssociation.child_id], back_populates="child"
    )

    # ToDo replace with index=True
    __table_args__ = (
        Index("md5_index", "md5"),
        Index("sha1_index", "sha1"),
        Index("sha256_index", "sha256", unique=True),
    )

    def __repr__(self):
        return f"<Sample({self.id},'{self.sha256}')>"

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            d[column.name] = getattr(self, column.name)
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, md5, crc32, sha1, sha256, sha512, file_size, file_type=None, ssdeep=None, parent_sample=None, source_url=None):
        self.md5 = md5
        self.sha1 = sha1
        self.crc32 = crc32
        self.sha256 = sha256
        self.sha512 = sha512
        self.file_size = file_size
        if file_type:
            self.file_type = file_type
        if ssdeep:
            self.ssdeep = ssdeep
        # if parent_sample:
        #    self.parent_sample = parent_sample
        if source_url:
            self.source_url = source_url


class Error(Base):
    """Analysis errors."""

    __tablename__ = "errors"
    MAX_LENGTH = 1024

    id: Mapped[int] = mapped_column(primary_key=True)
    message: Mapped[str] = mapped_column(String(MAX_LENGTH), nullable=False)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), nullable=False)
    task: Mapped["Task"] = relationship(back_populates="errors")

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            d[column.name] = getattr(self, column.name)
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, message, task_id):
        if len(message) > self.MAX_LENGTH:
            # Make sure that we don't try to insert an error message longer than what's allowed
            # in the database. Provide the beginning and the end of the error.
            left_of_ellipses = self.MAX_LENGTH // 2 - 2
            right_of_ellipses = self.MAX_LENGTH - left_of_ellipses - 3
            message = "...".join((message[:left_of_ellipses], message[-right_of_ellipses:]))
        self.message = message
        self.task_id = task_id

    def __repr__(self):
        return f"<Error({self.id},'{self.message}','{self.task_id}')>"


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


class AlembicVersion(Base):
    """Table used to pinpoint actual database schema release."""

    __tablename__ = "alembic_version"

    version_num: Mapped[str] = mapped_column(String(32), nullable=False, primary_key=True)

