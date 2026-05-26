from __future__ import annotations
import json
from typing import TYPE_CHECKING, List
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooDependencyError
if TYPE_CHECKING:
    from .machines import Machine
    from .task import Task

from datetime import datetime, timezone
import pytz
try:
    from sqlalchemy import (
        Column,
        ForeignKey,
        Integer,
        String,
        Table,
    )
    from sqlalchemy.orm import (
        DeclarativeBase,
        Mapped,
        mapped_column,
        relationship,
    )

except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")

# ToDo verify variable declaration in Mapped
class Base(DeclarativeBase):
    pass

cfg = Config("cuckoo")
tz_name = cfg.cuckoo.get("timezone", "utc")

def _utcnow_naive():
    """Returns the current time in the configured timezone as a naive datetime object."""
    try:
        tz = pytz.timezone(tz_name)
    except pytz.UnknownTimeZoneError:
        tz = timezone.utc
    return datetime.now(tz).replace(tzinfo=None)

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
