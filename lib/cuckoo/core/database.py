# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# https://blog.miguelgrinberg.com/post/what-s-new-in-sqlalchemy-2-0
# https://docs.sqlalchemy.org/en/20/changelog/migration_20.html#

import hashlib
import json
import logging
import os
import sys
from contextlib import suppress
from datetime import datetime, timedelta
from typing import Any, List, Optional, Union, cast

# Sflock does a good filetype recon
from sflock.abstracts import File as SflockFile
from sflock.ident import identify as sflock_identify

from lib.cuckoo.common.cape_utils import static_config_lookup, static_extraction
from lib.cuckoo.common.colors import red
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.demux import demux_sample
from lib.cuckoo.common.exceptions import (
    CuckooDatabaseError,
    CuckooDatabaseInitializationError,
    CuckooDependencyError,
    CuckooOperationalError,
    CuckooUnserviceableTaskError,
)
from lib.cuckoo.common.integrations.parse_pe import PortableExecutable
from lib.cuckoo.common.objects import PCAP, URL, File, Static
from lib.cuckoo.common.path_utils import path_delete, path_exists
from lib.cuckoo.common.utils import bytes2str, create_folder, get_options

try:
    from sqlalchemy import (
        Boolean,
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
        event,
        func,
        not_,
        select,
    )
    from sqlalchemy.exc import IntegrityError, SQLAlchemyError
    from sqlalchemy.orm import Query, backref, declarative_base, joinedload, relationship, scoped_session, sessionmaker

    Base = declarative_base()
except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry run pip install sqlalchemy`)")


sandbox_packages = (
    "access",
    "archive",
    "nsis",
    "cpl",
    "reg",
    "regsvr",
    "dll",
    "exe",
    "pdf",
    "pub",
    "doc",
    "xls",
    "ppt",
    "jar",
    "zip",
    "rar",
    "swf",
    "python",
    "msi",
    "msix",
    "ps1",
    "msg",
    "eml",
    "js",
    "html",
    "hta",
    "xps",
    "wsf",
    "mht",
    "doc",
    "vbs",
    "lnk",
    "chm",
    "hwp",
    "inp",
    "vbs",
    "js",
    "vbejse",
    "msbuild",
    "sct",
    "xslt",
    "shellcode",
    "shellcode_x64",
    "generic",
    "iso",
    "vhd",
    "udf",
    "one",
    "inf",
)

log = logging.getLogger(__name__)
conf = Config("cuckoo")
repconf = Config("reporting")
distconf = Config("distributed")
web_conf = Config("web")
LINUX_ENABLED = web_conf.linux.enabled
LINUX_STATIC = web_conf.linux.static_only
DYNAMIC_ARCH_DETERMINATION = web_conf.general.dynamic_arch_determination

if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_find
if repconf.elasticsearchdb.enabled:
    from dev_utils.elasticsearchdb import elastic_handler  # , get_analysis_index

    es = elastic_handler

SCHEMA_VERSION = "4e000e02a409"
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


def get_count(q, property):
    count_q = q.statement.with_only_columns(func.count(property)).order_by(None)
    count = q.session.execute(count_q).scalar()
    return count


class Machine(Base):
    """Configured virtual machines to be used as guests."""

    __tablename__ = "machines"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    label = Column(String(255), nullable=False, unique=True)
    arch = Column(String(255), nullable=False)
    ip = Column(String(255), nullable=False)
    platform = Column(String(255), nullable=False)
    tags = relationship("Tag", secondary=machines_tags, backref=backref("machines"))  # lazy="subquery"
    interface = Column(String(255), nullable=True)
    snapshot = Column(String(255), nullable=True)
    locked = Column(Boolean(), nullable=False, default=False)
    locked_changed_on = Column(DateTime(timezone=False), nullable=True)
    status = Column(String(255), nullable=True)
    status_changed_on = Column(DateTime(timezone=False), nullable=True)
    resultserver_ip = Column(String(255), nullable=False)
    resultserver_port = Column(String(255), nullable=False)
    reserved = Column(Boolean(), nullable=False, default=False)

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

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False, unique=True)

    def __repr__(self):
        return f"<Tag({self.id},'{self.name}')>"

    def __init__(self, name):
        self.name = name


class Guest(Base):
    """Tracks guest run."""

    __tablename__ = "guests"

    id = Column(Integer(), primary_key=True)
    status = Column(String(16), nullable=False)
    name = Column(String(255), nullable=False)
    label = Column(String(255), nullable=False)
    platform = Column(String(255), nullable=False)
    manager = Column(String(255), nullable=False)
    started_on = Column(DateTime(timezone=False), default=datetime.now, nullable=False)
    shutdown_on = Column(DateTime(timezone=False), nullable=True)
    task_id = Column(Integer, ForeignKey("tasks.id", ondelete="cascade"), nullable=False, unique=True)

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

    id = Column(Integer(), primary_key=True)
    file_size = Column(Integer(), nullable=False)
    file_type = Column(Text(), nullable=False)
    md5 = Column(String(32), nullable=False)
    crc32 = Column(String(8), nullable=False)
    sha1 = Column(String(40), nullable=False)
    sha256 = Column(String(64), nullable=False)
    sha512 = Column(String(128), nullable=False)
    ssdeep = Column(String(255), nullable=True)
    parent = Column(Integer(), nullable=True)
    source_url = Column(String(2000), nullable=True)
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

    def __init__(self, md5, crc32, sha1, sha256, sha512, file_size, file_type=None, ssdeep=None, parent=None, source_url=None):
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
        if parent:
            self.parent = parent
        if source_url:
            self.source_url = source_url


class Error(Base):
    """Analysis errors."""

    __tablename__ = "errors"
    MAX_LENGTH = 1024

    id = Column(Integer(), primary_key=True)
    message = Column(String(MAX_LENGTH), nullable=False)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False)

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

    id = Column(Integer(), primary_key=True)
    target = Column(Text(), nullable=False)
    category = Column(String(255), nullable=False)
    cape = Column(String(2048), nullable=True)
    timeout = Column(Integer(), server_default="0", nullable=False)
    priority = Column(Integer(), server_default="1", nullable=False)
    custom = Column(String(255), nullable=True)
    machine = Column(String(255), nullable=True)
    package = Column(String(255), nullable=True)
    route = Column(String(128), nullable=True, default=False)
    # Task tags
    tags_tasks = Column(String(256), nullable=True)
    # Virtual machine tags
    tags = relationship("Tag", secondary=tasks_tags, backref=backref("tasks"), lazy="subquery", cascade="save-update, delete")
    options = Column(Text(), nullable=True)
    platform = Column(String(255), nullable=True)
    memory = Column(Boolean, nullable=False, default=False)
    enforce_timeout = Column(Boolean, nullable=False, default=False)
    clock = Column(DateTime(timezone=False), default=datetime.now(), nullable=False)
    added_on = Column(DateTime(timezone=False), default=datetime.now, nullable=False)
    started_on = Column(DateTime(timezone=False), nullable=True)
    completed_on = Column(DateTime(timezone=False), nullable=True)
    status = Column(
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
    dropped_files = Column(Integer(), nullable=True)
    running_processes = Column(Integer(), nullable=True)
    api_calls = Column(Integer(), nullable=True)
    domains = Column(Integer(), nullable=True)
    signatures_total = Column(Integer(), nullable=True)
    signatures_alert = Column(Integer(), nullable=True)
    files_written = Column(Integer(), nullable=True)
    registry_keys_modified = Column(Integer(), nullable=True)
    crash_issues = Column(Integer(), nullable=True)
    anti_issues = Column(Integer(), nullable=True)
    analysis_started_on = Column(DateTime(timezone=False), nullable=True)
    analysis_finished_on = Column(DateTime(timezone=False), nullable=True)
    processing_started_on = Column(DateTime(timezone=False), nullable=True)
    processing_finished_on = Column(DateTime(timezone=False), nullable=True)
    signatures_started_on = Column(DateTime(timezone=False), nullable=True)
    signatures_finished_on = Column(DateTime(timezone=False), nullable=True)
    reporting_started_on = Column(DateTime(timezone=False), nullable=True)
    reporting_finished_on = Column(DateTime(timezone=False), nullable=True)
    timedout = Column(Boolean, nullable=False, default=False)

    sample_id = Column(Integer, ForeignKey("samples.id"), nullable=True)
    sample = relationship("Sample", backref=backref("tasks", lazy="subquery", cascade="save-update, delete"))
    machine_id = Column(Integer, nullable=True)
    guest = relationship("Guest", uselist=False, backref=backref("tasks"), cascade="save-update, delete")
    errors = relationship("Error", backref=backref("tasks"), cascade="save-update, delete")

    shrike_url = Column(String(4096), nullable=True)
    shrike_refer = Column(String(4096), nullable=True)
    shrike_msg = Column(String(4096), nullable=True)
    shrike_sid = Column(Integer(), nullable=True)

    # To be removed - Deprecate soon, not used anymore
    parent_id = Column(Integer(), nullable=True)
    tlp = Column(String(255), nullable=True)

    user_id = Column(Integer(), nullable=True)
    username = Column(String(256), nullable=True)

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

    version_num = Column(String(32), nullable=False, primary_key=True)


class _Database:
    """Analysis queue database.

    This class handles the creation of the database user for internal queue
    management. It also provides some functions for interacting with it.
    """

    def __init__(self, dsn=None, schema_check=True):
        """@param dsn: database connection string.
        @param schema_check: disable or enable the db schema version check
        """
        self.cfg = conf

        if dsn:
            self._connect_database(dsn)
        elif self.cfg.database.connection:
            self._connect_database(self.cfg.database.connection)
        else:
            file_path = os.path.join(CUCKOO_ROOT, "db", "cuckoo.db")
            if not path_exists(file_path):  # pragma: no cover
                db_dir = os.path.dirname(file_path)
                if not path_exists(db_dir):
                    try:
                        create_folder(folder=db_dir)
                    except CuckooOperationalError as e:
                        raise CuckooDatabaseError(f"Unable to create database directory: {e}")

            self._connect_database(f"sqlite:///{file_path}")

        # Disable SQL logging. Turn it on for debugging.
        self.engine.echo = self.cfg.database.log_statements
        # Connection timeout.
        if self.cfg.database.timeout:
            self.engine.pool_timeout = self.cfg.database.timeout
        else:
            self.engine.pool_timeout = 60
        # Create schema.
        try:
            Base.metadata.create_all(self.engine)
        except SQLAlchemyError as e:  # pragma: no cover
            raise CuckooDatabaseError(f"Unable to create or connect to database: {e}")

        # Get db session.
        self.session = scoped_session(sessionmaker(bind=self.engine, expire_on_commit=False))

        # There should be a better way to clean up orphans. This runs after every flush, which is crazy.
        @event.listens_for(self.session, "after_flush")
        def delete_tag_orphans(session, ctx):
            session.query(Tag).filter(~Tag.tasks.any()).filter(~Tag.machines.any()).delete(synchronize_session=False)

        # Deal with schema versioning.
        # TODO: it's a little bit dirty, needs refactoring.
        with self.session() as tmp_session:
            last = tmp_session.query(AlembicVersion).first()
            if last is None:
                # Set database schema version.
                tmp_session.add(AlembicVersion(version_num=SCHEMA_VERSION))
                try:
                    tmp_session.commit()
                except SQLAlchemyError as e:  # pragma: no cover
                    tmp_session.rollback()
                    raise CuckooDatabaseError(f"Unable to set schema version: {e}")
            else:
                # Check if db version is the expected one.
                if last.version_num != SCHEMA_VERSION and schema_check:  # pragma: no cover
                    print(
                        f"DB schema version mismatch: found {last.version_num}, expected {SCHEMA_VERSION}. Try to apply all migrations"
                    )
                    print(red("cd utils/db_migration/ && poetry run alembic upgrade head"))
                    sys.exit()

    def __del__(self):
        """Disconnects pool."""
        with suppress(KeyError, AttributeError):
            self.engine.dispose()

    def _connect_database(self, connection_string):
        """Connect to a Database.
        @param connection_string: Connection string specifying the database
        """
        try:
            # TODO: this is quite ugly, should improve.
            if connection_string.startswith("sqlite"):
                # Using "check_same_thread" to disable sqlite safety check on multiple threads.
                self.engine = create_engine(connection_string, connect_args={"check_same_thread": False})
            elif connection_string.startswith("postgres"):
                # Disabling SSL mode to avoid some errors using sqlalchemy and multiprocesing.
                # See: http://www.postgresql.org/docs/9.0/static/libpq-ssl.html#LIBPQ-SSL-SSLMODE-STATEMENTS
                self.engine = create_engine(
                    connection_string, connect_args={"sslmode": self.cfg.database.psql_ssl_mode}, pool_pre_ping=True
                )
            else:
                self.engine = create_engine(connection_string)
        except ImportError as e:  # pragma: no cover
            lib = e.message.rsplit(maxsplit=1)[-1]
            raise CuckooDependencyError(f"Missing database driver, unable to import {lib} (install with `pip install {lib}`)")

    def _get_or_create(self, model, **kwargs):
        """Get an ORM instance or create it if not exist.
        @param session: SQLAlchemy session object
        @param model: model to query
        @return: row instance
        """
        instance = self.session.query(model).filter_by(**kwargs).first()
        if instance:
            return instance
        else:
            instance = model(**kwargs)
            self.session.add(instance)
            return instance

    def drop(self):
        """Drop all tables."""
        try:
            Base.metadata.drop_all(self.engine)
        except SQLAlchemyError as e:
            raise CuckooDatabaseError(f"Unable to create or connect to database: {e}")

    def clean_machines(self):
        """Clean old stored machines and related tables."""
        # Secondary table.
        # TODO: this is better done via cascade delete.
        # self.engine.execute(machines_tags.delete())

        self.session.execute(machines_tags.delete())
        self.session.query(Machine).delete()

    def delete_machine(self, name) -> bool:
        """Delete a single machine entry from DB."""

        machine = self.session.query(Machine).filter_by(name=name).first()
        if machine:
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
        # Deal with tags format (i.e., foo,bar,baz)
        if tags:
            for tag in tags.replace(" ", "").split(","):
                machine.tags.append(self._get_or_create(Tag, name=tag))
        if locked:
            machine.locked = True
        self.session.add(machine)
        return machine

    def set_machine_interface(self, label, interface):
        machine = self.session.query(Machine).filter_by(label=label).first()
        if machine is None:
            log.debug("Database error setting interface: %s not found", label)
            return
        machine.interface = interface
        return machine

    def set_vnc_port(self, task_id: int, port: int):
        task = self.session.query(Task).filter_by(id=task_id).first()
        if task is None:
            log.debug("Database error setting VPN port: For task %s", task_id)
            return
        if task.options:
            task.options += f",vnc_port={port}"
        else:
            task.options = f"vnc_port={port}"

    def update_clock(self, task_id):
        row = self.session.get(Task, task_id)

        if not row:
            return

        if row.clock == datetime.utcfromtimestamp(0):
            if row.category == "file":
                row.clock = datetime.utcnow() + timedelta(days=self.cfg.cuckoo.daydelta)
            else:
                row.clock = datetime.utcnow()
        return row.clock

    def set_task_status(self, task: Task, status) -> Task:
        if status != TASK_DISTRIBUTED_COMPLETED:
            task.status = status

        if status in (TASK_RUNNING, TASK_DISTRIBUTED):
            task.started_on = datetime.now()
        elif status in (TASK_COMPLETED, TASK_DISTRIBUTED_COMPLETED):
            task.completed_on = datetime.now()

        self.session.add(task)
        return task

    def set_status(self, task_id: int, status) -> Optional[Task]:
        """Set task status.
        @param task_id: task identifier
        @param status: status string
        @return: operation status
        """
        task = self.session.get(Task, task_id)

        if not task:
            return None

        return self.set_task_status(task, status)

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

    def _task_arch_tags_helper(self, task: Task):
        # Are there available machines that match up with a task?
        task_archs = [tag.name for tag in task.tags if tag.name in ("x86", "x64")]
        task_tags = [tag.name for tag in task.tags if tag.name not in task_archs]

        return task_archs, task_tags

    def find_machine_to_service_task(self, task: Task) -> Optional[Machine]:
        """Find a machine that is able to service the given task.
        Returns: The Machine if an available machine was found; None if there is at least 1 machine
            that *could* service it, but they are all currently in use.
        Raises: CuckooUnserviceableTaskError if there are no machines in the pool that would be able
            to service it.
        """
        task_archs, task_tags = self._task_arch_tags_helper(task)
        os_version = self._package_vm_requires_check(task.package)

        def get_first_machine(query: Query) -> Optional[Machine]:
            # Select for update a machine, preferring one that is available and was the one that was used the
            # longest time ago. This will give us a machine that can get locked or, if there are none that are
            # currently available, we'll at least know that the task is serviceable.
            return cast(
                Optional[Machine], query.order_by(Machine.locked, Machine.locked_changed_on).with_for_update(of=Machine).first()
            )

        machines = self.session.query(Machine).options(joinedload(Machine.tags))
        filter_kwargs = {
            "machines": machines,
            "label": task.machine,
            "platform": task.platform,
            "tags": task_tags,
            "archs": task_archs,
            "os_version": os_version,
        }
        filtered_machines = self.filter_machines_to_task(include_reserved=False, **filter_kwargs)
        machine = get_first_machine(filtered_machines)
        if machine is None and not task.machine and task_tags:
            # The task was given at least 1 tag, but there are no non-reserved machines
            # that could satisfy the request. So let's see if there are any "reserved"
            # machines that can satisfy it.
            filtered_machines = self.filter_machines_to_task(include_reserved=True, **filter_kwargs)
            machine = get_first_machine(filtered_machines)

        if machine is None:
            raise CuckooUnserviceableTaskError
        if machine.locked:
            # There aren't any machines that can service the task NOW, but there is at least one in the pool
            # that could service it once it's available.
            return None
        return machine

    def fetch_task(self, categories: list = None):
        """Fetches a task waiting to be processed and locks it for running.
        @return: None or task
        """
        row = (
            self.session.query(Task)
            .filter_by(status=TASK_PENDING)
            .order_by(Task.priority.desc(), Task.added_on)
            # distributed cape
            .filter(not_(Task.options.contains("node=")))
        )

        if categories:
            row = row.filter(Task.category.in_(categories))
        row = row.first()

        if not row:
            return None

        self.set_status(task_id=row.id, status=TASK_RUNNING)

        return row

    def guest_get_status(self, task_id):
        """Log guest start.
        @param task_id: task id
        @return: guest status
        """
        guest = self.session.query(Guest).filter_by(task_id=task_id).first()
        return guest.status if guest else None

    def guest_set_status(self, task_id, status):
        """Log guest start.
        @param task_id: task identifier
        @param status: status
        """
        guest = self.session.query(Guest).filter_by(task_id=task_id).first()
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
            guest.shutdown_on = datetime.now()

    @staticmethod
    def filter_machines_by_arch(machines, arch):
        """Add a filter to the given query for the architecture of the machines.
        Allow x64 machines to be returned when requesting x86.
        """
        if arch:
            if "x86" in arch:
                # Prefer x86 machines over x64 if x86 is what was requested.
                machines = machines.filter(Machine.arch.in_(("x64", "x86"))).order_by(Machine.arch.desc())
            else:
                machines = machines.filter(Machine.arch.in_(arch))
        return machines

    def filter_machines_to_task(
        self, machines: Query, label=None, platform=None, tags=None, archs=None, os_version=None, include_reserved=False
    ) -> Query:
        """Add filters to the given query based on the task
        @param machines: Query object for the machines
        @param label: label of the machine(s) expected for the task
        @param platform: platform of the machine(s) expected for the task
        @param tags: tags of the machine(s) expected for the task
        @param archs: architectures of the machine(s) expected for the task
        @param os_version: Version of the OSs of the machine(s) expected for the task
        @param include_reserved: Flag to indicate if the list of machines returned should include reserved machines
        @return: list of machines after filtering the inputed one
        """
        if label:
            machines = machines.filter_by(label=label)
        elif not include_reserved:
            machines = machines.filter_by(reserved=False)
        if platform:
            machines = machines.filter_by(platform=platform)
        machines = self.filter_machines_by_arch(machines, archs)
        if tags:
            for tag in tags:
                machines = machines.filter(Machine.tags.any(name=tag))
        if os_version:
            machines = machines.filter(Machine.tags.any(Tag.name.in_(os_version)))
        return machines

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
        machines = self.session.query(Machine).options(joinedload(Machine.tags))
        if locked is not None and isinstance(locked, bool):
            machines = machines.filter_by(locked=locked)
        machines = self.filter_machines_to_task(
            machines=machines,
            label=label,
            platform=platform,
            tags=tags,
            archs=arch,
            os_version=os_version,
            include_reserved=include_reserved,
        )
        return machines.all()

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
        machine.locked_changed_on = datetime.now()
        self.set_machine_status(machine, MACHINE_RUNNING)
        self.session.add(machine)

        return machine

    def unlock_machine(self, machine: Machine) -> Machine:
        """Remove lock from a virtual machine.
        @param machine: The Machine to unlock.
        @return: unlocked machine
        """
        machine.locked = False
        machine.locked_changed_on = datetime.now()
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
        machines = self.session.query(Machine).filter_by(locked=False)
        machines = self.filter_machines_to_task(
            machines=machines,
            label=label,
            platform=platform,
            tags=tags,
            archs=arch,
            os_version=os_version,
            include_reserved=include_reserved,
        )
        return machines.count()

    def get_available_machines(self) -> List[Machine]:
        """Which machines are available
        @return: free virtual machines
        """
        machines = self.session.query(Machine).options(joinedload(Machine.tags)).filter_by(locked=False).all()
        return machines

    def count_machines_running(self) -> int:
        machines = self.session.query(Machine)
        machines = machines.filter_by(locked=True)
        return machines.count()

    def set_machine_status(self, machine_or_label: Union[str, Machine], status):
        """Set status for a virtual machine.
        @param label: virtual machine label
        @param status: new virtual machine status
        """
        if isinstance(machine_or_label, str):
            machine = self.session.query(Machine).filter_by(label=machine_or_label).first()
        else:
            machine = machine_or_label
        if machine:
            machine.status = status
            machine.status_changed_on = datetime.now()
            self.session.add(machine)

    def add_error(self, message, task_id):
        """Add an error related to a task.
        @param message: error message
        @param task_id: ID of the related task
        """
        error = Error(message=message, task_id=task_id)
        # Use a separate session so that, regardless of the state of a transaction going on
        # outside of this function, the error will always be committed to the database.
        with self.session.session_factory() as sess, sess.begin():
            sess.add(error)

    # The following functions are mostly used by external utils.

    def register_sample(self, obj, source_url=False):
        if isinstance(obj, (File, PCAP, Static)):
            fileobj = File(obj.file_path)
            file_type = fileobj.get_type()
            file_md5 = fileobj.get_md5()
            sample = None
            # check if hash is known already
            try:
                with self.session.begin_nested():
                    sample = Sample(
                        md5=file_md5,
                        crc32=fileobj.get_crc32(),
                        sha1=fileobj.get_sha1(),
                        sha256=fileobj.get_sha256(),
                        sha512=fileobj.get_sha512(),
                        file_size=fileobj.get_size(),
                        file_type=file_type,
                        ssdeep=fileobj.get_ssdeep(),
                        # parent=sample_parent_id,
                        source_url=source_url,
                    )
                    self.session.add(sample)
            except IntegrityError:
                sample = self.session.query(Sample).filter_by(md5=file_md5).first()

            return sample.id
        return None

    def add(
        self,
        obj,
        *,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        shrike_url=None,
        shrike_msg=None,
        shrike_sid=None,
        shrike_refer=None,
        parent_id=None,
        sample_parent_id=None,
        tlp=None,
        static=False,
        source_url=False,
        route=None,
        cape=False,
        tags_tasks=False,
        user_id=0,
        username=False,
    ):
        """Add a task to database.
        @param obj: object to add (File or URL).
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: optional tags that must be set for machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @param parent_id: parent task id
        @param sample_parent_id: original sample in case of archive
        @param static: try static extraction first
        @param tlp: TLP sharing designation
        @param source_url: url from where it was downloaded
        @param route: Routing route
        @param cape: CAPE options
        @param tags_tasks: Task tags so users can tag their jobs
        @param user_id: Link task to user if auth enabled
        @param username: username for custom auth
        @return: cursor or None.
        """
        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1

        if isinstance(obj, (File, PCAP, Static)):
            fileobj = File(obj.file_path)
            file_type = fileobj.get_type()
            file_md5 = fileobj.get_md5()
            # check if hash is known already
            try:
                with self.session.begin_nested():
                    sample = Sample(
                        md5=file_md5,
                        crc32=fileobj.get_crc32(),
                        sha1=fileobj.get_sha1(),
                        sha256=fileobj.get_sha256(),
                        sha512=fileobj.get_sha512(),
                        file_size=fileobj.get_size(),
                        file_type=file_type,
                        ssdeep=fileobj.get_ssdeep(),
                        parent=sample_parent_id,
                        source_url=source_url,
                    )
                    self.session.add(sample)
            except IntegrityError:
                sample = self.session.query(Sample).filter_by(md5=file_md5).first()

            if DYNAMIC_ARCH_DETERMINATION:
                # Assign architecture to task to fetch correct VM type

                # This isn't 100% fool proof
                _tags = tags.split(",") if isinstance(tags, str) else []
                arch_tag = fileobj.predict_arch()
                if package.endswith("_x64"):
                    _tags.append("x64")
                elif arch_tag:
                    _tags.append(arch_tag)
                tags = ",".join(set(_tags))
            task = Task(obj.file_path)
            task.sample_id = sample.id

            if isinstance(obj, (PCAP, Static)):
                # since no VM will operate on this PCAP
                task.started_on = datetime.now()

        elif isinstance(obj, URL):
            task = Task(obj.url)
            _tags = tags.split(",") if isinstance(tags, str) else []
            _tags.append("x64")
            _tags.append("x86")
            tags = ",".join(set(_tags))

        else:
            return None

        task.category = obj.__class__.__name__.lower()
        task.timeout = timeout
        task.package = package
        task.options = options
        task.priority = priority
        task.custom = custom
        task.machine = machine
        task.platform = platform
        task.memory = bool(memory)
        task.enforce_timeout = enforce_timeout
        task.shrike_url = shrike_url
        task.shrike_msg = shrike_msg
        task.shrike_sid = shrike_sid
        task.shrike_refer = shrike_refer
        task.parent_id = parent_id
        task.tlp = tlp
        task.route = route
        task.cape = cape
        task.tags_tasks = tags_tasks
        # Deal with tags format (i.e., foo,bar,baz)
        if tags:
            for tag in tags.split(","):
                tag_name = tag.strip()
                if tag_name and tag_name not in [tag.name for tag in task.tags]:
                    # "Task" object is being merged into a Session along the backref cascade path for relationship "Tag.tasks"; in SQLAlchemy 2.0, this reverse cascade will not take place.
                    # Set cascade_backrefs to False in either the relationship() or backref() function for the 2.0 behavior; or to set globally for the whole Session, set the future=True flag
                    # (Background on this error at: https://sqlalche.me/e/14/s9r1) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)
                    task.tags.append(self._get_or_create(Tag, name=tag_name))

        if clock:
            if isinstance(clock, str):
                try:
                    task.clock = datetime.strptime(clock, "%m-%d-%Y %H:%M:%S")
                except ValueError:
                    log.warning("The date you specified has an invalid format, using current timestamp")
                    task.clock = datetime.utcfromtimestamp(0)

            else:
                task.clock = clock
        else:
            task.clock = datetime.utcfromtimestamp(0)

        task.user_id = user_id
        task.username = username

        # Use a nested transaction so that we can return an ID.
        with self.session.begin_nested():
            self.session.add(task)

        return task.id

    def add_path(
        self,
        file_path,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        shrike_url=None,
        shrike_msg=None,
        shrike_sid=None,
        shrike_refer=None,
        parent_id=None,
        sample_parent_id=None,
        tlp=None,
        static=False,
        source_url=False,
        route=None,
        cape=False,
        tags_tasks=False,
        user_id=0,
        username=False,
    ):
        """Add a task to database from file path.
        @param file_path: sample path.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: Tags required in machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @param parent_id: parent analysis id
        @param sample_parent_id: sample parent id, if archive
        @param static: try static extraction first
        @param tlp: TLP sharing designation
        @param route: Routing route
        @param cape: CAPE options
        @param tags_tasks: Task tags so users can tag their jobs
        @user_id: Allow link task to user if auth enabled
        @username: username from custom auth
        @return: cursor or None.
        """
        if not file_path or not path_exists(file_path):
            log.warning("File does not exist: %s", file_path)
            return None

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1
        if file_path.endswith((".htm", ".html")) and not package:
            package = web_conf.url_analysis.package

        return self.add(
            File(file_path),
            timeout=timeout,
            package=package,
            options=options,
            priority=priority,
            custom=custom,
            machine=machine,
            platform=platform,
            tags=tags,
            memory=memory,
            enforce_timeout=enforce_timeout,
            clock=clock,
            shrike_url=shrike_url,
            shrike_msg=shrike_msg,
            shrike_sid=shrike_sid,
            shrike_refer=shrike_refer,
            parent_id=parent_id,
            sample_parent_id=sample_parent_id,
            tlp=tlp,
            source_url=source_url,
            route=route,
            cape=cape,
            tags_tasks=tags_tasks,
            user_id=user_id,
            username=username,
        )

    def _identify_aux_func(self, file: bytes, package: str, check_shellcode: bool = True) -> tuple:
        # before demux we need to check as msix has zip mime and we don't want it to be extracted:
        tmp_package = False
        if not package:
            f = SflockFile.from_path(file)
            try:
                tmp_package = sflock_identify(f, check_shellcode=check_shellcode)
            except Exception as e:
                log.error("Failed to sflock_ident due to %s", str(e))
                tmp_package = "generic"

        if tmp_package and tmp_package in sandbox_packages:
            # This probably should be way much bigger list of formats
            if tmp_package in ("iso", "udf", "vhd"):
                package = "archive"
            elif tmp_package in ("zip", "rar"):
                package = ""
            elif tmp_package in ("html",):
                package = web_conf.url_analysis.package
            else:
                package = tmp_package

        return package, tmp_package

    # Submission hooks to manipulate arguments of tasks execution
    def recon(
        self,
        filename,
        orig_options,
        timeout=0,
        enforce_timeout=False,
        package="",
        tags=None,
        static=False,
        priority=1,
        machine="",
        platform="",
        custom="",
        memory=False,
        clock=None,
        unique=False,
        referrer=None,
        tlp=None,
        tags_tasks=False,
        route=None,
        cape=False,
        category=None,
    ):
        # Get file filetype to ensure self extracting archives run longer
        if not isinstance(filename, str):
            filename = bytes2str(filename)

        lowered_filename = filename.lower()

        # sfx = File(filename).is_sfx()

        if "malware_name" in lowered_filename:
            orig_options += "<options_here>"
        # if sfx:
        #    orig_options += ",timeout=500,enforce_timeout=1,procmemdump=1,procdump=1"
        #    timeout = 500
        #    enforce_timeout = True

        if web_conf.general.yara_recon:
            hits = File(filename).get_yara("binaries")
            for hit in hits:
                cape_name = hit["meta"].get("cape_type", "")
                if not cape_name.endswith(("Crypter", "Packer", "Obfuscator", "Loader", "Payload")):
                    continue

                orig_options_parsed = get_options(orig_options)
                parsed_options = get_options(hit["meta"].get("cape_options", ""))
                if "tags" in parsed_options:
                    tags = "," + parsed_options["tags"] if tags else parsed_options["tags"]
                    del parsed_options["tags"]
                # custom packages should be added to lib/cuckoo/core/database.py -> sandbox_packages list
                # Do not overwrite user provided package
                if not package and "package" in parsed_options:
                    package = parsed_options["package"]
                    del parsed_options["package"]

                if "category" in parsed_options:
                    category = parsed_options["category"]
                    del parsed_options["category"]

                orig_options_parsed.update(parsed_options)
                orig_options = ",".join([f"{k}={v}" for k, v in orig_options_parsed.items()])

        return (
            static,
            priority,
            machine,
            platform,
            custom,
            memory,
            clock,
            unique,
            referrer,
            tlp,
            tags_tasks,
            route,
            cape,
            orig_options,
            timeout,
            enforce_timeout,
            package,
            tags,
            category,
        )

    def demux_sample_and_add_to_db(
        self,
        file_path,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        shrike_url=None,
        shrike_msg=None,
        shrike_sid=None,
        shrike_refer=None,
        parent_id=None,
        tlp=None,
        static=False,
        source_url=False,
        only_extraction=False,
        tags_tasks=False,
        route=None,
        cape=False,
        user_id=0,
        username=False,
        category=None,
    ):
        """
        Handles ZIP file submissions, submitting each extracted file to the database
        Returns a list of added task IDs
        """
        task_id = False
        task_ids = []
        config = {}
        details = {}
        sample_parent_id = None

        if not isinstance(file_path, bytes):
            file_path = file_path.encode()

        (
            static,
            priority,
            machine,
            platform,
            custom,
            memory,
            clock,
            unique,
            referrer,
            tlp,
            tags_tasks,
            route,
            cape,
            options,
            timeout,
            enforce_timeout,
            package,
            tags,
            category,
        ) = self.recon(
            file_path,
            options,
            timeout=timeout,
            enforce_timeout=enforce_timeout,
            package=package,
            tags=tags,
            static=static,
            priority=priority,
            machine=machine,
            platform=platform,
            custom=custom,
            memory=memory,
            clock=clock,
            tlp=tlp,
            tags_tasks=tags_tasks,
            route=route,
            cape=cape,
            category=category,
        )

        if category == "static":
            # force change of category
            task_ids += self.add_static(
                file_path=file_path,
                priority=priority,
                tlp=tlp,
                user_id=user_id,
                username=username,
                options=options,
                package=package,
            )
            return task_ids, details

        check_shellcode = True
        if options and "check_shellcode=0" in options:
            check_shellcode = False

        if not package:
            if "file=" in options:
                # set zip as package when specifying file= in options
                package = "zip"
            else:
                # Checking original file as some filetypes doesn't require demux
                package, _ = self._identify_aux_func(file_path, package, check_shellcode=check_shellcode)

        # extract files from the (potential) archive
        extracted_files, demux_error_msgs = demux_sample(file_path, package, options, platform=platform)
        # check if len is 1 and the same file, if diff register file, and set parent
        if extracted_files and (file_path, platform) not in extracted_files:
            sample_parent_id = self.register_sample(File(file_path), source_url=source_url)
            if conf.cuckoo.delete_archive:
                path_delete(file_path.decode())

        # create tasks for each file in the archive
        for file, platform in extracted_files:
            if not path_exists(file):
                log.error("Extracted file doesn't exist: %s", file)
                continue
            # ToDo we lose package here and send APKs to windows
            if platform in ("linux", "darwin") and LINUX_STATIC:
                task_ids += self.add_static(
                    file_path=file_path,
                    priority=priority,
                    tlp=tlp,
                    user_id=user_id,
                    username=username,
                    options=options,
                    package=package,
                )
                continue
            if static:
                # On huge loads this just become a bottleneck
                config = False
                if web_conf.general.check_config_exists:
                    config = static_config_lookup(file)
                    if config:
                        task_ids.append(config["id"])
                    else:
                        config = static_extraction(file)
                if config or only_extraction:
                    task_ids += self.add_static(
                        file_path=file, priority=priority, tlp=tlp, user_id=user_id, username=username, options=options
                    )

            if not config and not only_extraction:
                if not package:
                    package, tmp_package = self._identify_aux_func(file, "", check_shellcode=check_shellcode)

                    if not tmp_package:
                        log.info("Do sandbox packages need an update? Sflock identifies as: %s - %s", tmp_package, file)

                if package == "dll" and "function" not in options:
                    dll_export = PortableExecutable(file.decode()).choose_dll_export()
                    if dll_export == "DllRegisterServer":
                        package = "regsvr"
                    elif dll_export == "xlAutoOpen":
                        package = "xls"
                    elif dll_export:
                        if options:
                            options += f",function={dll_export}"
                        else:
                            options = f"function={dll_export}"

                # ToDo better solution? - Distributed mode here:
                # Main node is storage so try to extract before submit to vm isn't propagated to workers
                if static and not config and distconf.distributed.enabled:
                    if options:
                        options += ",dist_extract=1"
                    else:
                        options = "dist_extract=1"

                task_id = self.add_path(
                    file_path=file.decode(),
                    timeout=timeout,
                    priority=priority,
                    options=options,
                    package=package,
                    machine=machine,
                    platform=platform,
                    memory=memory,
                    custom=custom,
                    enforce_timeout=enforce_timeout,
                    tags=tags,
                    clock=clock,
                    shrike_url=shrike_url,
                    shrike_msg=shrike_msg,
                    shrike_sid=shrike_sid,
                    shrike_refer=shrike_refer,
                    parent_id=parent_id,
                    sample_parent_id=sample_parent_id,
                    tlp=tlp,
                    source_url=source_url,
                    route=route,
                    tags_tasks=tags_tasks,
                    cape=cape,
                    user_id=user_id,
                    username=username,
                )
                package = None
            if task_id:
                task_ids.append(task_id)

        if config and isinstance(config, dict):
            details = {"config": config.get("cape_config", {})}
        if demux_error_msgs:
            details["errors"] = demux_error_msgs
        # this is aim to return custom data, think of this as kwargs
        return task_ids, details

    def add_pcap(
        self,
        file_path,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        shrike_url=None,
        shrike_msg=None,
        shrike_sid=None,
        shrike_refer=None,
        parent_id=None,
        tlp=None,
        user_id=0,
        username=False,
    ):
        return self.add(
            PCAP(file_path.decode()),
            timeout=timeout,
            package=package,
            options=options,
            priority=priority,
            custom=custom,
            machine=machine,
            platform=platform,
            tags=tags,
            memory=memory,
            enforce_timeout=enforce_timeout,
            clock=clock,
            shrike_url=shrike_url,
            shrike_msg=shrike_msg,
            shrike_sid=shrike_sid,
            shrike_refer=shrike_refer,
            parent_id=parent_id,
            tlp=tlp,
            user_id=user_id,
            username=username,
        )

    def add_static(
        self,
        file_path,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        shrike_url=None,
        shrike_msg=None,
        shrike_sid=None,
        shrike_refer=None,
        parent_id=None,
        tlp=None,
        static=True,
        user_id=0,
        username=False,
    ):
        extracted_files, demux_error_msgs = demux_sample(file_path, package, options)
        sample_parent_id = None
        # check if len is 1 and the same file, if diff register file, and set parent
        if not isinstance(file_path, bytes):
            file_path = file_path.encode()

        if extracted_files and ((file_path, platform) not in extracted_files and (file_path, "") not in extracted_files):
            sample_parent_id = self.register_sample(File(file_path))
            if conf.cuckoo.delete_archive:
                # ToDo keep as info for now
                log.info("Deleting archive: %s. conf.cuckoo.delete_archive is enabled. %s", file_path, str(extracted_files))
                path_delete(file_path)

        task_ids = []
        # create tasks for each file in the archive
        for file, platform in extracted_files:
            task_id = self.add(
                Static(file.decode()),
                timeout=timeout,
                package=package,
                options=options,
                priority=priority,
                custom=custom,
                machine=machine,
                platform=platform,
                tags=tags,
                memory=memory,
                enforce_timeout=enforce_timeout,
                clock=clock,
                shrike_url=shrike_url,
                shrike_msg=shrike_msg,
                shrike_sid=shrike_sid,
                shrike_refer=shrike_refer,
                tlp=tlp,
                static=static,
                sample_parent_id=sample_parent_id,
                user_id=user_id,
                username=username,
            )
            if task_id:
                task_ids.append(task_id)

        return task_ids

    def add_url(
        self,
        url,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        shrike_url=None,
        shrike_msg=None,
        shrike_sid=None,
        shrike_refer=None,
        parent_id=None,
        tlp=None,
        route=None,
        cape=False,
        tags_tasks=False,
        user_id=0,
        username=False,
    ):
        """Add a task to database from url.
        @param url: url.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: tags for machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @param tlp: TLP sharing designation
        @param route: Routing route
        @param cape: CAPE options
        @param tags_tasks: Task tags so users can tag their jobs
        @param user_id: Link task to user
        @param username: username for custom auth
        @return: cursor or None.
        """

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1
        if not package:
            package = web_conf.url_analysis.package

        return self.add(
            URL(url),
            timeout=timeout,
            package=package,
            options=options,
            priority=priority,
            custom=custom,
            machine=machine,
            platform=platform,
            tags=tags,
            memory=memory,
            enforce_timeout=enforce_timeout,
            clock=clock,
            shrike_url=shrike_url,
            shrike_msg=shrike_msg,
            shrike_sid=shrike_sid,
            shrike_refer=shrike_refer,
            parent_id=parent_id,
            tlp=tlp,
            route=route,
            cape=cape,
            tags_tasks=tags_tasks,
            user_id=user_id,
            username=username,
        )

    def reschedule(self, task_id):
        """Reschedule a task.
        @param task_id: ID of the task to reschedule.
        @return: ID of the newly created task.
        """
        task = self.view_task(task_id)

        if not task:
            return None

        if task.category == "file":
            add = self.add_path
        elif task.category == "url":
            add = self.add_url
        elif task.category == "pcap":
            add = self.add_pcap
        elif task.category == "static":
            add = self.add_static

        # Change status to recovered.
        self.session.get(Task, task_id).status = TASK_RECOVERED

        # Normalize tags.
        if task.tags:
            tags = ",".join(tag.name for tag in task.tags)
        else:
            tags = task.tags

        def _ensure_valid_target(task):
            if task.category == "url":
                # URL tasks always have valid targets, return it as-is.
                return task.target

            # All other task types have a "target" pointing to a temp location,
            # so get a stable path "target" based on the sample hash.
            paths = self.sample_path_by_hash(task.sample.sha256, task_id)
            paths = [file_path for file_path in paths if path_exists(file_path)]
            if not paths:
                return None

            if task.category == "pcap":
                # PCAP task paths are represented as bytes
                return paths[0].encode()
            return paths[0]

        task_target = _ensure_valid_target(task)
        if not task_target:
            log.warning("Unable to find valid target for task: %s", task_id)
            return

        new_task_id = None
        if task.category in ("file", "url"):
            new_task_id = add(
                task_target,
                task.timeout,
                task.package,
                task.options,
                task.priority,
                task.custom,
                task.machine,
                task.platform,
                tags,
                task.memory,
                task.enforce_timeout,
                task.clock,
                tlp=task.tlp,
                route=task.route,
            )
        elif task.category in ("pcap", "static"):
            new_task_id = add(
                task_target,
                task.timeout,
                task.package,
                task.options,
                task.priority,
                task.custom,
                task.machine,
                task.platform,
                tags,
                task.memory,
                task.enforce_timeout,
                task.clock,
                tlp=task.tlp,
            )

        self.session.get(Task, task_id).custom = f"Recovery_{new_task_id}"

        return new_task_id

    def count_matching_tasks(self, category=None, status=None, not_status=None):
        """Retrieve list of task.
        @param category: filter by category
        @param status: filter by task status
        @param not_status: exclude this task status from filter
        @return: number of tasks.
        """
        search = self.session.query(Task)

        if status:
            search = search.filter_by(status=status)
        if not_status:
            search = search.filter(Task.status != not_status)
        if category:
            search = search.filter_by(category=category)

        tasks = search.count()
        return tasks

    def check_file_uniq(self, sha256: str, hours: int = 0):
        # TODO This function is poorly named. It returns True if a sample with the given
        # sha256 already exists in the database, rather than returning True if the given
        # sha256 is unique.
        uniq = False
        if hours and sha256:
            date_since = datetime.now() - timedelta(hours=hours)
            date_till = datetime.now()
            uniq = (
                self.session.query(Task)
                .join(Sample, Task.sample_id == Sample.id)
                .filter(Sample.sha256 == sha256, Task.added_on.between(date_since, date_till))
                .first()
            )
        else:
            if not self.find_sample(sha256=sha256):
                uniq = False
            else:
                uniq = True

        return uniq

    def list_sample_parent(self, sample_id=False, task_id=False):
        """
        Retrieve parent sample details by sample_id or task_id
        @param sample_id: Sample id
        @param task_id: Task id
        """
        # This function appears to only be used in one specific case, and task_id is
        # the only parameter that gets passed--sample_id is never provided.
        # TODO Pull sample_id as an argument. It's dead code.
        parent_sample = {}
        parent = False
        if sample_id:  # pragma: no cover
            parent = self.session.query(Sample.parent).filter(Sample.id == int(sample_id)).first()
            if parent:
                parent = parent[0]
        elif task_id:
            result = (
                self.session.query(Task.sample_id, Sample.parent)
                .join(Sample, Sample.id == Task.sample_id)
                .filter(Task.id == task_id)
                .first()
            )
            if result is not None:
                parent = result[1]

        if parent:
            parent_sample = self.session.query(Sample).filter(Sample.id == parent).first().to_dict()

        return parent_sample

    def list_tasks(
        self,
        limit=None,
        details=False,
        category=None,
        offset=None,
        status=None,
        sample_id=None,
        not_status=None,
        completed_after=None,
        order_by=None,
        added_before=None,
        id_before=None,
        id_after=None,
        options_like=False,
        options_not_like=False,
        tags_tasks_like=False,
        task_ids=False,
        include_hashes=False,
        user_id=None,
        for_update=False,
    ) -> List[Task]:
        """Retrieve list of task.
        @param limit: specify a limit of entries.
        @param details: if details about must be included
        @param category: filter by category
        @param offset: list offset
        @param status: filter by task status
        @param sample_id: filter tasks for a sample
        @param not_status: exclude this task status from filter
        @param completed_after: only list tasks completed after this timestamp
        @param order_by: definition which field to sort by
        @param added_before: tasks added before a specific timestamp
        @param id_before: filter by tasks which is less than this value
        @param id_after filter by tasks which is greater than this value
        @param options_like: filter tasks by specific option inside of the options
        @param options_not_like: filter tasks by specific option not inside of the options
        @param tags_tasks_like: filter tasks by specific tag
        @param task_ids: list of task_id
        @param include_hashes: return task+samples details
        @param user_id: list of tasks submitted by user X
        @param for_update: If True, use "SELECT FOR UPDATE" in order to create a row-level lock on the selected tasks.
        @return: list of tasks.
        """
        tasks: List[Task] = []
        # Can we remove "options(joinedload)" it is here due to next error
        # sqlalchemy.orm.exc.DetachedInstanceError: Parent instance <Task at X> is not bound to a Session; lazy load operation of attribute 'tags' cannot proceed
        # ToDo this is inefficient but it fails if we don't join. Need to fix this
        search = self.session.query(Task).options(joinedload(Task.guest), joinedload(Task.errors), joinedload(Task.tags))
        if include_hashes:  # pragma: no cover
            # This doesn't work, but doesn't seem to get used anywhere.
            search = search.options(joinedload(Sample))
        if status:
            if "|" in status:
                search = search.filter(Task.status.in_(status.split("|")))
            else:
                search = search.filter(Task.status == status)
        if not_status:
            search = search.filter(Task.status != not_status)
        if category:
            search = search.filter(Task.category.in_([category] if isinstance(category, str) else category))
        # We're currently always returning details. See the comment at the top of this 'try' block.
        # if details:
        #    search = search.options(joinedload(Task.guest), joinedload(Task.errors), joinedload(Task.tags))
        if sample_id is not None:
            search = search.filter(Task.sample_id == sample_id)
        if id_before is not None:
            search = search.filter(Task.id < id_before)
        if id_after is not None:
            search = search.filter(Task.id > id_after)
        if completed_after:
            search = search.filter(Task.completed_on > completed_after)
        if added_before:
            search = search.filter(Task.added_on < added_before)
        if options_like:
            # Replace '*' wildcards with wildcard for sql
            options_like = options_like.replace("*", "%")
            search = search.filter(Task.options.like(f"%{options_like}%"))
        if options_not_like:
            # Replace '*' wildcards with wildcard for sql
            options_not_like = options_not_like.replace("*", "%")
            search = search.filter(Task.options.notlike(f"%{options_not_like}%"))
        if tags_tasks_like:
            search = search.filter(Task.tags_tasks.like(f"%{tags_tasks_like}%"))
        if task_ids:
            search = search.filter(Task.id.in_(task_ids))
        if user_id is not None:
            search = search.filter(Task.user_id == user_id)

        if order_by is not None and isinstance(order_by, tuple):
            search = search.order_by(*order_by)
        elif order_by is not None:
            search = search.order_by(order_by)
        else:
            search = search.order_by(Task.added_on.desc())

        search = search.limit(limit).offset(offset)
        if for_update:
            search = search.with_for_update(of=Task)
        tasks = search.all()

        return tasks

    def delete_task(self, task_id):
        """Delete information on a task.
        @param task_id: ID of the task to query.
        @return: operation status.
        """
        task = self.session.get(Task, task_id)
        if task is None:
            return False
        self.session.delete(task)
        return True

    def delete_tasks(
        self,
        category=None,
        status=None,
        sample_id=None,
        not_status=None,
        completed_after=None,
        added_before=None,
        id_before=None,
        id_after=None,
        options_like=False,
        options_not_like=False,
        tags_tasks_like=False,
        task_ids=False,
        user_id=None,
    ):
        """Delete tasks based on parameters. If no filters are provided, no tasks will be deleted.

        Args:
            category: filter by category
            status: filter by task status
            sample_id: filter tasks for a sample
            not_status: exclude this task status from filter
            completed_after: only list tasks completed after this timestamp
            added_before: tasks added before a specific timestamp
            id_before: filter by tasks which is less than this value
            id_after: filter by tasks which is greater than this value
            options_like: filter tasks by specific option inside of the options
            options_not_like: filter tasks by specific option not inside of the options
            tags_tasks_like: filter tasks by specific tag
            task_ids: list of task_id
            user_id: list of tasks submitted by user X

        Returns:
            bool: True if the operation was successful (including no tasks to delete), False otherwise.
        """
        filters_applied = False
        search = self.session.query(Task)

        if status:
            if "|" in status:
                search = search.filter(Task.status.in_(status.split("|")))
            else:
                search = search.filter(Task.status == status)
            filters_applied = True
        if not_status:
            search = search.filter(Task.status != not_status)
            filters_applied = True
        if category:
            search = search.filter(Task.category.in_([category] if isinstance(category, str) else category))
            filters_applied = True
        if sample_id is not None:
            search = search.filter(Task.sample_id == sample_id)
            filters_applied = True
        if id_before is not None:
            search = search.filter(Task.id < id_before)
            filters_applied = True
        if id_after is not None:
            search = search.filter(Task.id > id_after)
            filters_applied = True
        if completed_after:
            search = search.filter(Task.completed_on > completed_after)
            filters_applied = True
        if added_before:
            search = search.filter(Task.added_on < added_before)
            filters_applied = True
        if options_like:
            # Replace '*' wildcards with wildcard for sql
            options_like = options_like.replace("*", "%")
            search = search.filter(Task.options.like(f"%{options_like}%"))
            filters_applied = True
        if options_not_like:
            # Replace '*' wildcards with wildcard for sql
            options_not_like = options_not_like.replace("*", "%")
            search = search.filter(Task.options.notlike(f"%{options_not_like}%"))
            filters_applied = True
        if tags_tasks_like:
            search = search.filter(Task.tags_tasks.like(f"%{tags_tasks_like}%"))
            filters_applied = True
        if task_ids:
            search = search.filter(Task.id.in_(task_ids))
            filters_applied = True
        if user_id is not None:
            search = search.filter(Task.user_id == user_id)
            filters_applied = True

        if not filters_applied:
            log.warning("No filters provided for delete_tasks. No tasks will be deleted.")
            return True  # Indicate success as no deletion was requested/needed

        try:
            # Perform the deletion and get the count of deleted rows
            deleted_count = search.delete(synchronize_session=False)
            log.info("Deleted %d tasks matching the criteria.", deleted_count)
            self.session.commit()
            return True
        except Exception as e:
            log.error("Error deleting tasks: %s", str(e))
            # Rollback might be needed if this function is called outside a `with db.session.begin():`
            # but typically it should be called within one.
            self.session.rollback()
            return False


    def check_tasks_timeout(self, timeout):
        """Find tasks which were added_on more than timeout ago and clean"""
        tasks: List[Task] = []
        ids_to_delete = []
        if timeout == 0:
            return
        search = self.session.query(Task).filter(Task.status == TASK_PENDING).order_by(Task.added_on.desc())
        tasks = search.all()
        for task in tasks:
            if task.added_on + timedelta(seconds=timeout) < datetime.now():
                ids_to_delete.append(task.id)
        if len(ids_to_delete) > 0:
            self.session.query(Task).filter(Task.id.in_(ids_to_delete)).delete(synchronize_session=False)

    def minmax_tasks(self):
        """Find tasks minimum and maximum
        @return: unix timestamps of minimum and maximum
        """
        _min = self.session.query(func.min(Task.started_on).label("min")).first()
        _max = self.session.query(func.max(Task.completed_on).label("max")).first()
        if _min and _max and _min[0] and _max[0]:
            return int(_min[0].strftime("%s")), int(_max[0].strftime("%s"))

        return 0, 0

    def get_tlp_tasks(self):
        """
        Retrieve tasks with TLP
        """
        tasks = self.session.query(Task).filter(Task.tlp == "true").all()
        if tasks:
            return [task.id for task in tasks]
        else:
            return []

    def get_file_types(self):
        """Get sample filetypes

        @return: A list of all available file types
        """
        unfiltered = self.session.query(Sample.file_type).group_by(Sample.file_type)
        res = [asample[0] for asample in unfiltered.all()]
        res.sort()
        return res

    def get_tasks_status_count(self):
        """Count all tasks in the database
        @return: dict with status and number of tasks found example: {'failed_analysis': 2, 'running': 100, 'reported': 400}
        """
        tasks_dict_count = self.session.query(Task.status, func.count(Task.status)).group_by(Task.status).all()
        return dict(tasks_dict_count)

    def count_tasks(self, status=None, mid=None):
        """Count tasks in the database
        @param status: apply a filter according to the task status
        @param mid: Machine id to filter for
        @return: number of tasks found
        """
        unfiltered = self.session.query(Task)
        # It doesn't look like "mid" ever gets passed to this function.
        if mid:  # pragma: no cover
            unfiltered = unfiltered.filter_by(machine_id=mid)
        if status:
            unfiltered = unfiltered.filter_by(status=status)
        tasks_count = get_count(unfiltered, Task.id)
        return tasks_count

    def view_task(self, task_id, details=False) -> Optional[Task]:
        """Retrieve information on a task.
        @param task_id: ID of the task to query.
        @return: details on the task.
        """
        query = select(Task).where(Task.id == task_id)
        if details:
            query = query.options(joinedload(Task.guest), joinedload(Task.errors), joinedload(Task.tags), joinedload(Task.sample))
        else:
            query = query.options(joinedload(Task.tags), joinedload(Task.sample))
        task = self.session.execute(query).first()
        if task:
            task = task[0]

        return task

    # This function is used by the runstatistics community module.
    def add_statistics_to_task(self, task_id, details):  # pragma: no cover
        """add statistic to task
        @param task_id: ID of the task to query.
        @param: details statistic.
        @return true of false.
        """
        task = self.session.get(Task, task_id)
        if task:
            task.dropped_files = details["dropped_files"]
            task.running_processes = details["running_processes"]
            task.api_calls = details["api_calls"]
            task.domains = details["domains"]
            task.signatures_total = details["signatures_total"]
            task.signatures_alert = details["signatures_alert"]
            task.files_written = details["files_written"]
            task.registry_keys_modified = details["registry_keys_modified"]
            task.crash_issues = details["crash_issues"]
            task.anti_issues = details["anti_issues"]
        return True

    def view_sample(self, sample_id):
        """Retrieve information on a sample given a sample id.
        @param sample_id: ID of the sample to query.
        @return: details on the sample used in sample: sample_id.
        """
        return self.session.get(Sample, sample_id)

    def find_sample(self, md5=None, sha1=None, sha256=None, parent=None, task_id: int = None, sample_id: int = None):
        """Search samples by MD5, SHA1, or SHA256.
        @param md5: md5 string
        @param sha1: sha1 string
        @param sha256: sha256 string
        @param parent: sample_id int
        @param task_id: task_id int
        @param sample_id: sample_id int
        @return: matches list
        """
        sample = False
        if md5:
            sample = self.session.query(Sample).filter_by(md5=md5).first()
        elif sha1:
            sample = self.session.query(Sample).filter_by(sha1=sha1).first()
        elif sha256:
            sample = self.session.query(Sample).filter_by(sha256=sha256).first()
        elif parent:
            sample = self.session.query(Sample).filter_by(parent=parent).all()
        elif sample_id:
            sample = self.session.query(Sample).filter_by(id=sample_id).all()
        elif task_id:
            # If task_id is passed, then a list of Task objects is returned--not Samples.
            sample = (
                self.session.query(Task)
                .options(joinedload(Task.sample))
                .filter(Task.id == task_id)
                .filter(Sample.id == Task.sample_id)
                .all()
            )
        return sample

    def sample_still_used(self, sample_hash: str, task_id: int):
        """Retrieve information if sample is used by another task(s).
        @param sample_hash: sha256.
        @param task_id: task_id
        @return: bool
        """
        db_sample = (
            self.session.query(Sample)
            # .options(joinedload(Task.sample))
            .filter(Sample.sha256 == sample_hash)
            .filter(Task.id != task_id)
            .filter(Sample.id == Task.sample_id)
            .filter(Task.status.in_((TASK_PENDING, TASK_RUNNING, TASK_DISTRIBUTED)))
            .first()
        )
        still_used = bool(db_sample)
        return still_used

    def sample_path_by_hash(self, sample_hash: str = False, task_id: int = False):
        """Retrieve information on a sample location by given hash.
        @param hash: md5/sha1/sha256/sha256.
        @param task_id: task_id
        @return: samples path(s) as list.
        """
        sizes = {
            32: Sample.md5,
            40: Sample.sha1,
            64: Sample.sha256,
            128: Sample.sha512,
        }

        hashlib_sizes = {
            32: hashlib.md5,
            40: hashlib.sha1,
            64: hashlib.sha256,
            128: hashlib.sha512,
        }

        sizes_mongo = {
            32: "md5",
            40: "sha1",
            64: "sha256",
            128: "sha512",
        }

        if task_id:
            file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "binary")
            if path_exists(file_path):
                return [file_path]

        # binary also not stored in binaries, perform hash lookup
        if task_id and not sample_hash:
            db_sample = (
                self.session.query(Sample)
                # .options(joinedload(Task.sample))
                .filter(Task.id == task_id)
                .filter(Sample.id == Task.sample_id)
                .first()
            )
            if db_sample:
                path = os.path.join(CUCKOO_ROOT, "storage", "binaries", db_sample.sha256)
                if path_exists(path):
                    return [path]

                sample_hash = db_sample.sha256

        if not sample_hash:
            return []

        query_filter = sizes.get(len(sample_hash), "")
        sample = []
        # check storage/binaries
        if query_filter:
            db_sample = self.session.query(Sample).filter(query_filter == sample_hash).first()
            if db_sample is not None:
                path = os.path.join(CUCKOO_ROOT, "storage", "binaries", db_sample.sha256)
                if path_exists(path):
                    sample = [path]

            if not sample:
                tasks = []
                if repconf.mongodb.enabled and web_conf.general.check_sample_in_mongodb:
                    tasks = mongo_find(
                        "files",
                        {sizes_mongo.get(len(sample_hash), ""): sample_hash},
                        {"_info_ids": 1, "sha256": 1},
                    )
                """ deprecated code
                elif repconf.elasticsearchdb.enabled:
                    tasks = [
                        d["_source"]
                        for d in es.search(
                            index=get_analysis_index(),
                            body={"query": {"match": {f"CAPE.payloads.{sizes_mongo.get(len(sample_hash), '')}": sample_hash}}},
                            _source=["CAPE.payloads", "info.id"],
                        )["hits"]["hits"]
                    ]
                """
                if tasks:
                    for task in tasks:
                        for id in task.get("_task_ids", []):
                            # ToDo suricata path - "suricata.files.file_info.path
                            for category in ("files", "procdump", "CAPE"):
                                file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(id), category, task["sha256"])
                                if path_exists(file_path):
                                    sample = [file_path]
                                    break
                        if sample:
                            break

            if not sample:
                # search in temp folder if not found in binaries
                db_sample = (
                    self.session.query(Task).join(Sample, Task.sample_id == Sample.id).filter(query_filter == sample_hash).all()
                )

                if db_sample is not None:
                    samples = [_f for _f in [tmp_sample.to_dict().get("target", "") for tmp_sample in db_sample] if _f]
                    # hash validation and if exist
                    samples = [file_path for file_path in samples if path_exists(file_path)]
                    for path in samples:
                        with open(path, "rb") as f:
                            if sample_hash == hashlib_sizes[len(sample_hash)](f.read()).hexdigest():
                                sample = [path]
                                break
        return sample

    def count_samples(self) -> int:
        """Counts the amount of samples in the database."""
        sample_count = self.session.query(Sample).count()
        return sample_count

    def view_machine(self, name) -> Optional[Machine]:
        """Show virtual machine.
        @params name: virtual machine name
        @return: virtual machine's details
        """
        machine = self.session.query(Machine).options(joinedload(Machine.tags)).filter(Machine.name == name).first()
        return machine

    def view_machine_by_label(self, label) -> Optional[Machine]:
        """Show virtual machine.
        @params label: virtual machine label
        @return: virtual machine's details
        """
        machine = self.session.query(Machine).options(joinedload(Machine.tags)).filter(Machine.label == label).first()
        return machine

    def view_errors(self, task_id):
        """Get all errors related to a task.
        @param task_id: ID of task associated to the errors
        @return: list of errors.
        """
        errors = self.session.query(Error).filter_by(task_id=task_id).all()
        return errors

    def get_source_url(self, sample_id=False):
        """
        Retrieve url from where sample was downloaded
        @param sample_id: Sample id
        @param task_id: Task id
        """
        source_url = False
        try:
            if sample_id:
                source_url = self.session.query(Sample.source_url).filter(Sample.id == int(sample_id)).first()
                if source_url:
                    source_url = source_url[0]
        except TypeError:
            pass

        return source_url

    def ban_user_tasks(self, user_id: int):
        """
        Ban all tasks submitted by user_id
        @param user_id: user id
        """

        self.session.query(Task).filter(Task.user_id == user_id).filter(Task.status == TASK_PENDING).update(
            {Task.status: TASK_BANNED}, synchronize_session=False
        )

    def tasks_reprocess(self, task_id: int):
        """common func for api and views"""
        task = self.view_task(task_id)
        if not task:
            return True, "Task ID does not exist in the database", ""

        if task.status not in {
            # task status suitable for reprocessing
            # allow reprocessing of tasks already processed (maybe detections changed)
            TASK_REPORTED,
            # allow reprocessing of tasks that were rescheduled
            TASK_RECOVERED,
            # allow reprocessing of tasks that previously failed the processing stage
            TASK_FAILED_PROCESSING,
            # allow reprocessing of tasks that previously failed the reporting stage
            TASK_FAILED_REPORTING,
            # TASK_COMPLETED,
        }:
            return True, f"Task ID {task_id} cannot be reprocessed in status {task.status}", task.status

        # Save the old_status, because otherwise, in the call to set_status(),
        # sqlalchemy will use the cached Task object that `task` is already a reference
        # to and update that in place. That would result in `task.status` in this
        # function being set to TASK_COMPLETED and we don't want to return that.
        old_status = task.status
        self.set_status(task_id, TASK_COMPLETED)
        return False, "", old_status


_DATABASE: Optional[_Database] = None


class Database:
    def __getattr__(self, attr: str) -> Any:
        if _DATABASE is None:
            raise CuckooDatabaseInitializationError
        return getattr(_DATABASE, attr)


def init_database(*args, exists_ok=False, **kwargs) -> _Database:
    global _DATABASE
    if _DATABASE is not None:
        if exists_ok:
            return _DATABASE
        raise RuntimeError("The database has already been initialized!")
    _DATABASE = _Database(*args, **kwargs)
    return _DATABASE


def reset_database_FOR_TESTING_ONLY():
    """Used for testing."""
    global _DATABASE
    _DATABASE = None
