"""Guacamole session tokens tied to CAPE task lifecycle."""

from datetime import datetime

from .db_common import Base, _utcnow_naive

try:
    from sqlalchemy import DateTime, Integer, String
    from sqlalchemy.orm import Mapped, mapped_column
except ImportError:
    from lib.cuckoo.common.exceptions import CuckooDependencyError
    raise CuckooDependencyError("Unable to import sqlalchemy")


class GuacSession(Base):
    """Ties a guacamole browser session to a CAPE task lifecycle.

    A UUID token is generated when a user opens the guac view for a running
    task.  The WebSocket consumer validates this token before proxying the
    VNC connection.  The row is deleted when the task ends or the WebSocket
    disconnects, preventing session camping.
    """

    __tablename__ = "guac_sessions"

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    token: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    task_id: Mapped[int] = mapped_column(Integer(), index=True, nullable=False)
    vm_label: Mapped[str] = mapped_column(String(128), nullable=False)
    guest_ip: Mapped[str] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=_utcnow_naive, nullable=False)

    def __repr__(self):
        return f"<GuacSession task={self.task_id} vm={self.vm_label}>"
