from typing import Optional, TYPE_CHECKING
from datetime import datetime
import json
from lib.cuckoo.common.exceptions import CuckooDependencyError
if TYPE_CHECKING:
    from lib.cuckoo.core.data.task import Task
from .db_common import Base, _utcnow_naive

try:
    from sqlalchemy import DateTime, ForeignKey, select
    from sqlalchemy.orm import Mapped, mapped_column, relationship
except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")


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


class GuestsMixIn:
    def guest_get_status(self, task_id: int):
        """Gets the status for a given guest."""
        stmt = select(Guest).where(Guest.task_id == task_id)
        guest = self.session.scalar(stmt)
        return guest.status if guest else None

    def guest_set_status(self, task_id: int, status: str):
        """Sets the status for a given guest."""
        stmt = select(Guest).where(Guest.task_id == task_id)
        guest = self.session.scalar(stmt)
        if guest is not None:
            guest.status = status

    def guest_remove(self, guest_id):
        """Removes a guest start entry."""
        guest = self.session.get(Guest, guest_id)
        if guest:
            self.session.delete(guest)

    def guest_stop(self, guest_id):
        """Logs guest stop.
        @param guest_id: guest log entry id
        """
        guest = self.session.get(Guest, guest_id)
        if guest:
            guest.shutdown_on = _utcnow_naive()
