from __future__ import annotations
import json
import logging
from typing import List, Optional, Union
from datetime import datetime
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooUnserviceableTaskError
from .db_common import Base, machines_tags
from .db_common import Tag
from .db_common import _utcnow_naive
from .task import Task
from .guests import Guest


try:
    from sqlalchemy import (
        Boolean,
        DateTime,
        delete,
        func,
        Integer,
        select,
        Select,
        String,
    )
    from sqlalchemy.orm import (
        Mapped,
        mapped_column,
        relationship,
        subqueryload,
    )

except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")

MACHINE_RUNNING = "running"

log = logging.getLogger(__name__)
web_conf = Config("web")



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

class MachinesMixIn:
    def clean_machines(self):
        """Clean old stored machines and related tables."""
        # Secondary table.
        # TODO: this is better done via cascade delete.
        # self.engine.execute(machines_tags.delete())
        # ToDo : If your ForeignKey has "ON DELETE CASCADE", deleting a Machine
        # would automatically delete its entries in machines_tags.
        # If not, deleting them manually first is correct.
        self.session.execute(delete(machines_tags))
        self.session.execute(delete(Machine))

    def delete_machine(self, name) -> bool:
        """Delete a single machine entry from DB."""

        stmt = select(Machine).where(Machine.name == name)
        machine = self.session.scalar(stmt)

        if machine:
            # Deleting a specific ORM instance remains the same
            self.session.delete(machine)
            return True
        else:
            log.warning("%s does not exist in the database.", name)
            return False

    def add_machine(
        self, name, label, arch, ip, platform, tags, interface, snapshot, resultserver_ip, resultserver_port, reserved, locked=False
    ) -> Machine:
        """Add a guest machine.
        @param name: machine id
        @param label: machine label
        @param arch: machine arch
        @param ip: machine IP address
        @param platform: machine supported platform
        @param tags: list of comma separated tags
        @param interface: sniffing interface for this machine
        @param snapshot: snapshot name to use instead of the current one, if configured
        @param resultserver_ip: IP address of the Result Server
        @param resultserver_port: port of the Result Server
        @param reserved: True if the machine can only be used when specifically requested
        """

        machine = Machine(
            name=name,
            label=label,
            arch=arch,
            ip=ip,
            platform=platform,
            interface=interface,
            snapshot=snapshot,
            resultserver_ip=resultserver_ip,
            resultserver_port=resultserver_port,
            reserved=reserved,
        )

        if tags:
            with self.session.no_autoflush:
                for tag in tags.replace(" ", "").split(","):
                    machine.tags.append(self._get_or_create(Tag, name=tag))
        if locked:
            machine.locked = True

        self.session.add(machine)
        return machine

    def set_machine_interface(self, label, interface):
        stmt = select(Machine).filter_by(label=label)
        machine = self.session.scalar(stmt)

        if machine is None:
            log.debug("Database error setting interface: %s not found", label)
            return

        # This part remains the same
        machine.interface = interface
        return machine

    def create_guest(self, machine: Machine, manager: str, task: Task) -> Guest:
        guest = Guest(machine.name, machine.label, machine.platform, manager, task.id)
        guest.status = "init"
        self.session.add(guest)
        return guest

    def _package_vm_requires_check(self, package: str) -> list:
        """
        We allow to users use their custom tags to tag properly any VM that can run this package
        """
        return [vm_tag.strip() for vm_tag in web_conf.packages.get(package).split(",")] if web_conf.packages.get(package) else []

    def find_machine_to_service_task(self, task: Task) -> Optional[Machine]:
        """Find a machine that is able to service the given task.
        Returns: The Machine if an available machine was found; None if there is at least 1 machine
            that *could* service it, but they are all currently in use.
        Raises: CuckooUnserviceableTaskError if there are no machines in the pool that would be able
            to service it.
        """
        task_archs, task_tags = self._task_arch_tags_helper(task)
        os_version = self._package_vm_requires_check(task.package)

        base_stmt = select(Machine).options(subqueryload(Machine.tags))

        # This helper now encapsulates the final ordering, locking, and execution.
        # It takes a Select statement as input.
        def get_locked_machine(stmt: Select) -> Optional[Machine]:
            final_stmt = stmt.order_by(Machine.locked, Machine.locked_changed_on).with_for_update(of=Machine)
            return self.session.scalars(final_stmt).first()

        filter_kwargs = {
            "statement": base_stmt,
            "label": task.machine,
            "platform": task.platform,
            "tags": task_tags,
            "archs": task_archs,
            "os_version": os_version,
        }

        filtered_stmt = self.filter_machines_to_task(include_reserved=False, **filter_kwargs)
        machine = get_locked_machine(filtered_stmt)

        if machine is None and not task.machine and task_tags:
            # The task was given at least 1 tag, but there are no non-reserved machines
            # that could satisfy the request. So let's check "reserved" machines.
            filtered_stmt = self.filter_machines_to_task(include_reserved=True, **filter_kwargs)
            machine = get_locked_machine(filtered_stmt)

        if machine is None:
            raise CuckooUnserviceableTaskError
        if machine.locked:
            # There aren't any machines that can service the task NOW, but there is at
            # least one in the pool that could service it once it's available.
            return None
        return machine

    @staticmethod
    def filter_machines_by_arch(statement: Select, arch: list) -> Select:
        """Adds a filter to the given select statement for the machine architecture.
        Allows x64 machines to be returned when requesting x86.
        """
        if arch:
            if "x86" in arch:
                # Prefer x86 machines over x64 if x86 is what was requested.
                statement = statement.where(Machine.arch.in_(("x64", "x86"))).order_by(Machine.arch.desc())
            else:
                statement = statement.where(Machine.arch.in_(arch))
        return statement

    def filter_machines_to_task(
        self, statement: Select, label=None, platform=None, tags=None, archs=None, os_version=None, include_reserved=False
    ) -> Select:
        """Adds filters to the given select statement based on the task.

        @param statement: A `select()` statement to add filters to.
        """
        if label:
            statement = statement.where(Machine.label == label)
        elif not include_reserved:
            # Use .is_(False) for boolean checks
            statement = statement.where(Machine.reserved.is_(False))

        if platform:
            statement = statement.where(Machine.platform == platform)

        statement = self.filter_machines_by_arch(statement, archs)

        if tags:
            for tag in tags:
                statement = statement.where(Machine.tags.any(name=tag))

        if os_version:
            statement = statement.where(Machine.tags.any(Tag.name.in_(os_version)))

        return statement

    def list_machines(
        self,
        locked=None,
        label=None,
        platform=None,
        tags=None,
        arch=None,
        include_reserved=False,
        os_version=None,
    ) -> List[Machine]:
        """Lists virtual machines.
        @return: list of virtual machines
        """
        """
        id |  name  | label | arch |
        ----+-------+-------+------+
        77 | cape1  | win7  | x86  |
        78 | cape2  | win10 | x64  |
        """
        # ToDo do we really need it
        with self.session.begin_nested():
            # with self.session.no_autoflush:
            stmt = select(Machine).options(subqueryload(Machine.tags))

            if locked is not None:
                stmt = stmt.where(Machine.locked.is_(locked))

            stmt = self.filter_machines_to_task(
                statement=stmt,
                label=label,
                platform=platform,
                tags=tags,
                archs=arch,
                os_version=os_version,
                include_reserved=include_reserved,
            )
            return self.session.execute(stmt).unique().scalars().all()

    def assign_machine_to_task(self, task: Task, machine: Optional[Machine]) -> Task:
        if machine:
            task.machine = machine.label
            task.machine_id = machine.id
        else:
            task.machine = None
            task.machine_id = None
        self.session.add(task)
        return task

    def lock_machine(self, machine: Machine) -> Machine:
        """Places a lock on a free virtual machine.
        @param machine: the Machine to lock
        @return: locked machine
        """
        machine.locked = True
        machine.locked_changed_on = _utcnow_naive()
        self.set_machine_status(machine, MACHINE_RUNNING)
        self.session.add(machine)

        return machine

    def unlock_machine(self, machine: Machine) -> Machine:
        """Remove lock from a virtual machine.
        @param machine: The Machine to unlock.
        @return: unlocked machine
        """
        machine.locked = False
        machine.locked_changed_on = _utcnow_naive()
        self.session.merge(machine)
        return machine

    def count_machines_available(self, label=None, platform=None, tags=None, arch=None, include_reserved=False, os_version=None):
        """How many (relevant) virtual machines are ready for analysis.
        @param label: machine ID.
        @param platform: machine platform.
        @param tags: machine tags
        @param arch: machine arch
        @param include_reserved: include 'reserved' machines in the result, regardless of whether or not a 'label' was provided.
        @return: free virtual machines count
        """
        stmt = select(func.count(Machine.id)).where(Machine.locked.is_(False))
        stmt = self.filter_machines_to_task(
            statement=stmt,
            label=label,
            platform=platform,
            tags=tags,
            archs=arch,
            os_version=os_version,
            include_reserved=include_reserved,
        )

        return self.session.scalar(stmt)

    def get_available_machines(self) -> List[Machine]:
        """Which machines are available"""
        stmt = select(Machine).options(subqueryload(Machine.tags)).where(Machine.locked.is_(False))
        return self.session.scalars(stmt).all()

    def count_machines_running(self) -> int:
        """Counts how many machines are currently locked (running)."""
        stmt = select(func.count(Machine.id)).where(Machine.locked.is_(True))
        return self.session.scalar(stmt)

    def set_machine_status(self, machine_or_label: Union[str, Machine], status):
        """Set status for a virtual machine."""
        if isinstance(machine_or_label, str):
            stmt = select(Machine).where(Machine.label == machine_or_label)
            machine = self.session.scalar(stmt)
        else:
            machine = machine_or_label

        if machine:
            machine.status = status
            machine.status_changed_on = _utcnow_naive()
            # No need for session.add() here; the ORM tracks changes to loaded objects.

    def view_machine(self, name: str) -> Optional[Machine]:
        """Shows virtual machine details by name."""
        stmt = select(Machine).options(subqueryload(Machine.tags)).where(Machine.name == name)
        return self.session.scalar(stmt)

    def view_machine_by_label(self, label: str) -> Optional[Machine]:
        """Shows virtual machine details by label."""
        stmt = select(Machine).options(subqueryload(Machine.tags)).where(Machine.label == label)
        return self.session.scalar(stmt)
