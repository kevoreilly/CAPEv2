from datetime import datetime
from typing import List, Optional
from sqlalchemy import (Column, DateTime, ForeignKey, Integer, String, Table, Text, JSON, Boolean)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db_common import _utcnow_naive, Base

TEST_COMPLETE = "complete"
TEST_UNQUEUED = "unqueued"
TEST_QUEUED = "queued"
TEST_RUNNING = "running"
TEST_FAILED = "failed"

class TestSession(Base):
    """Test session table for tracking test runs."""

    __tablename__ = "test_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    added_on: Mapped[datetime] = mapped_column(DateTime(timezone=False), default=_utcnow_naive, nullable=False)
    runs: Mapped[List["TestRun"]] = relationship(back_populates="session", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<TestSession({self.id})>"

    @property
    def unqueued_run_count(self):
        return sum(1 for run in self.runs if run.status == TEST_UNQUEUED)

    @property
    def queued_run_count(self):
        return sum(1 for run in self.runs if run.status == TEST_QUEUED)


class AvailableTest(Base):
    """A test case available for running against a CAPE sandbox
    installation with the test harness"""

    __tablename__ = "available_tests"

    # db ID for the test
    id: Mapped[int] = mapped_column(primary_key=True)

    # unique human readable name for the test
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    # description of test concept, objectives
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # describe the payload (format, arch, malice)
    payload_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # give useful info on what to expect from or how to interpret results
    result_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # password to unwrap the zip, if it is encrypted
    zip_password: Mapped[str | None] = mapped_column(Text, nullable=True)

    # CAPE analysis package to use: exe, archive, doc2016, etc
    package: Mapped[str] = mapped_column(String(64), nullable=False)

    # CAPE timeout parameter
    timeout: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # list of operating systems this test is expected to work on
    targets: Mapped[List[str] | None] = mapped_column(Text, nullable=True)

    # Store absolute paths for execution and verification
    payload_path: Mapped[str] = mapped_column(Text, nullable=False)
    module_path: Mapped[str] = mapped_column(Text, nullable=False)

    # Store 'Task Config' and other metadata as a JSON blob
    # we shouldn't need the details in the web view, just parse it
    # in the test tasking logic
    task_config: Mapped[dict] = mapped_column(JSON, nullable=False)

    objective_templates: Mapped[List["TestObjectiveTemplate"]] = relationship(secondary="test_template_association")
    runs: Mapped[List["TestRun"]] = relationship(back_populates="test_definition")

    is_active: Mapped[str | None] = mapped_column(Boolean, default=True, nullable=False)


test_template_association = Table(
    "test_template_association",
    Base.metadata,
    Column("test_id", ForeignKey("available_tests.id", ondelete="CASCADE"), primary_key=True),
    Column("template_id", ForeignKey("test_objectives_templates.id", ondelete="CASCADE"), primary_key=True),
)


class TestObjectiveTemplate(Base):
    """A measure of success of a single objective of a dynamic analysis
    test run. eg: a certain flag was found in a dropped file."""

    __tablename__ = "test_objectives_templates"

    # metadata true for all instances of this objective over all tests
    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    requirement: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_id: Mapped[Optional[int]] = mapped_column(ForeignKey("test_objectives_templates.id"))
    children: Mapped[List["TestObjectiveTemplate"]] = relationship(back_populates="parent", cascade="all, delete-orphan")
    parent: Mapped[Optional["TestObjectiveTemplate"]] = relationship(back_populates="children", remote_side=[id])


class TestObjectiveInstance(Base):
    """A measure of success of a single objective of a dynamic analysis
    test run. eg: a certain flag was found in a dropped file."""

    __tablename__ = "test_objective_instances"
    id: Mapped[int] = mapped_column(primary_key=True)

    # The Link to the objective template
    template_id: Mapped[int] = mapped_column(ForeignKey("test_objectives_templates.id"))
    template: Mapped["TestObjectiveTemplate"] = relationship()

    # link back to the test run
    run_id: Mapped[int] = mapped_column(ForeignKey("test_runs.id"), nullable=False)
    run: Mapped["TestRun"] = relationship(back_populates="objectives")
    parent_id: Mapped[Optional[int]] = mapped_column(ForeignKey("test_objective_instances.id"))
    children: Mapped[List["TestObjectiveInstance"]] = relationship(
        back_populates="parent",
        cascade="all, delete-orphan",
        lazy="selectin"
    )

    parent: Mapped[Optional["TestObjectiveInstance"]] = relationship(back_populates="children", remote_side=[id])

    # per-run state of this objective
    state: Mapped[str | None] = mapped_column(Text, nullable=True)
    state_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class TestRun(Base):
    """Details of a single run of an AvailableTest within a TestSession."""

    __tablename__ = "test_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("test_sessions.id"))
    test_id: Mapped[int] = mapped_column(ForeignKey("available_tests.id"))

    # CAPE Specifics
    cape_task_id: Mapped[Optional[int]] = mapped_column(nullable=True)  # ID returned by CAPE API
    status: Mapped[str] = mapped_column(String(50), default="unqueued")  # pending, running, completed, failed

    # Results
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    logs: Mapped[Optional[str]] = mapped_column(Text())
    raw_results: Mapped[Optional[dict]] = mapped_column(JSON)  # Store summary JSON from CAPE

    session: Mapped["TestSession"] = relationship(back_populates="runs")
    test_definition: Mapped["AvailableTest"] = relationship(back_populates="runs")
    objectives: Mapped[List["TestObjectiveInstance"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", lazy="joined"  # Performance boost: loads objectives with the run
    )
