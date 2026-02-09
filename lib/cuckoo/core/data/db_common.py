
from typing import List
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import (
    CuckooDependencyError
)

from datetime import datetime, timezone
import pytz
try:    
    from sqlalchemy import (
        Column,
        ForeignKey,
        Integer,
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

