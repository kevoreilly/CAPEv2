# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# https://blog.miguelgrinberg.com/post/what-s-new-in-sqlalchemy-2-0
# https://docs.sqlalchemy.org/en/20/changelog/migration_20.html#
# ToDO with session.begin():

import json
import logging
import os
import sys
from contextlib import suppress
from datetime import datetime, timedelta

# Sflock does a good filetype recon
from sflock.abstracts import File as SflockFile
from sflock.ident import identify as sflock_identify

from lib.cuckoo.common.cape_utils import static_config_lookup, static_extraction
from lib.cuckoo.common.colors import red
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.demux import demux_sample
from lib.cuckoo.common.exceptions import CuckooDatabaseError, CuckooDependencyError, CuckooOperationalError
from lib.cuckoo.common.integrations.parse_pe import PortableExecutable
from lib.cuckoo.common.objects import PCAP, URL, File, Static
from lib.cuckoo.common.path_utils import path_delete, path_exists
from lib.cuckoo.common.utils import Singleton, SuperLock, classlock, create_folder

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
    from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
    from sqlalchemy.orm import backref, declarative_base, joinedload, relationship, sessionmaker

    Base = declarative_base()
except ImportError:
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
    "Shellcode",
    "Shellcode_x64",
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
DYNAMIC_ARCH_DETERMINATION = web_conf.general.dynamic_arch_determination

if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_find
if repconf.elasticsearchdb.enabled:
    from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index

    es = elastic_handler

SCHEMA_VERSION = "a8441ab0fd0f"
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
    Column("task_id", Integer, ForeignKey("tasks.id")),
    Column("tag_id", Integer, ForeignKey("tags.id")),
)


VALID_LINUX_TYPES = ("Bourne-Again", "POSIX shell script", "ELF", "Python")


def _get_linux_vm_tag(mgtype):
    mgtype = mgtype.lower()
    if mgtype.startswith(VALID_LINUX_TYPES) and "motorola" not in mgtype and "renesas" not in mgtype:
        return False
    if "mipsel" in mgtype:
        return "mipsel"
    elif "mips" in mgtype:
        return "mips"
    elif "arm" in mgtype:
        return "arm"
    # elif "armhl" in mgtype:
    #    return {"tags":"armhl"}
    elif "sparc" in mgtype:
        return "sparc"
    # elif "motorola" in mgtype:
    #    return "motorola"
    # elif "renesas sh" in mgtype:
    #    return "renesassh"
    elif "powerpc" in mgtype:
        return "powerpc"
    elif "32-bit" in mgtype:
        return "x32"
    elif "elf 64-bit" in mgtype and "x86-64" in mgtype:
        return "x64"
    return "x64"


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
        return f"<Machine('{self.id}','{self.name}')>"

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
        return f"<Tag('{self.id}','{self.name}')>"

    def __init__(self, name):
        self.name = name


class Guest(Base):
    """Tracks guest run."""

    __tablename__ = "guests"

    id = Column(Integer(), primary_key=True)
    status = Column(String(16), nullable=False)
    name = Column(String(255), nullable=False)
    label = Column(String(255), nullable=False)
    manager = Column(String(255), nullable=False)
    started_on = Column(DateTime(timezone=False), default=datetime.now, nullable=False)
    shutdown_on = Column(DateTime(timezone=False), nullable=True)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False, unique=True)

    def __repr__(self):
        return f"<Guest('{self.id}','{self.name}')>"

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

    def __init__(self, name, label, manager):
        self.name = name
        self.label = label
        self.manager = manager


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
        return f"<Sample('{self.id}','{self.sha256}')>"

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

    id = Column(Integer(), primary_key=True)
    message = Column(String(1024), nullable=False)
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
        self.message = message
        self.task_id = task_id

    def __repr__(self):
        return f"<Error('{self.id}','{self.message}','{self.task_id}')>"


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
    tags = relationship("Tag", secondary=tasks_tags, backref=backref("tasks"), lazy="subquery")
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
    sample = relationship("Sample", backref=backref("tasks", lazy="subquery"))
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
        return f"<Task('{self.id}','{self.target}')>"


class AlembicVersion(Base):
    """Table used to pinpoint actual database schema release."""

    __tablename__ = "alembic_version"

    version_num = Column(String(32), nullable=False, primary_key=True)


class Database(object, metaclass=Singleton):
    """Analysis queue database.

    This class handles the creation of the database user for internal queue
    management. It also provides some functions for interacting with it.
    """

    def __init__(self, dsn=None, schema_check=True):
        """@param dsn: database connection string.
        @param schema_check: disable or enable the db schema version check
        """
        self._lock = SuperLock()
        self.cfg = conf

        if dsn:
            self._connect_database(dsn)
        elif self.cfg.database.connection:
            self._connect_database(self.cfg.database.connection)
        else:
            file_path = os.path.join(CUCKOO_ROOT, "db", "cuckoo.db")
            if not path_exists(file_path):
                db_dir = os.path.dirname(file_path)
                if not path_exists(db_dir):
                    try:
                        create_folder(folder=db_dir)
                    except CuckooOperationalError as e:
                        raise CuckooDatabaseError(f"Unable to create database directory: {e}")

            self._connect_database(f"sqlite:///{file_path}")

        # Disable SQL logging. Turn it on for debugging.
        self.engine.echo = False
        # Connection timeout.
        if self.cfg.database.timeout:
            self.engine.pool_timeout = self.cfg.database.timeout
        else:
            self.engine.pool_timeout = 60
        # Create schema.
        try:
            Base.metadata.create_all(self.engine)
        except SQLAlchemyError as e:
            raise CuckooDatabaseError(f"Unable to create or connect to database: {e}")

        # Get db session.
        self.Session = sessionmaker(bind=self.engine)

        @event.listens_for(self.Session, "after_flush")
        def delete_tag_orphans(session, ctx):
            session.query(Tag).filter(~Tag.tasks.any()).filter(~Tag.machines.any()).delete(synchronize_session=False)

        # Deal with schema versioning.
        # TODO: it's a little bit dirty, needs refactoring.
        tmp_session = self.Session()
        if not tmp_session.query(AlembicVersion).count():
            # Set database schema version.
            tmp_session.add(AlembicVersion(version_num=SCHEMA_VERSION))
            try:
                tmp_session.commit()
            except SQLAlchemyError as e:
                tmp_session.rollback()
                raise CuckooDatabaseError(f"Unable to set schema version: {e}")
            finally:
                tmp_session.close()
        else:
            # Check if db version is the expected one.
            last = tmp_session.query(AlembicVersion).first()
            tmp_session.close()
            if last.version_num != SCHEMA_VERSION and schema_check:
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
        except ImportError as e:
            lib = e.message.rsplit(maxsplit=1)[-1]
            raise CuckooDependencyError(f"Missing database driver, unable to import {lib} (install with `pip install {lib}`)")

    def _get_or_create(self, session, model, **kwargs):
        """Get an ORM instance or create it if not exist.
        @param session: SQLAlchemy session object
        @param model: model to query
        @return: row instance
        """
        instance = session.query(model).filter_by(**kwargs).first()
        if instance:
            return instance
        else:
            instance = model(**kwargs)
            return instance

    @classlock
    def drop(self):
        """Drop all tables."""
        try:
            Base.metadata.drop_all(self.engine)
        except SQLAlchemyError as e:
            raise CuckooDatabaseError(f"Unable to create or connect to database: {e}")

    @classlock
    def clean_machines(self):
        """Clean old stored machines and related tables."""
        # Secondary table.
        # TODO: this is better done via cascade delete.
        # self.engine.execute(machines_tags.delete())

        with self.Session() as session:
            session.execute(machines_tags.delete())
            try:
                session.query(Machine).delete()
                session.commit()
            except SQLAlchemyError as e:
                log.debug("Database error cleaning machines: %s", e)
                session.rollback()

    @classlock
    def delete_machine(self, name) -> bool:
        """Delete a single machine entry from DB."""

        with self.Session() as session:
            try:
                machine = session.query(Machine).filter_by(name=name).first()
                if machine:
                    session.delete(machine)
                    session.commit()
                    return True
                else:
                    log.warning(f"{name} does not exist in the database.")
                    return False
            except SQLAlchemyError as e:
                log.debug("Database error deleting machine: %s", e)
                session.rollback()

    @classlock
    def add_machine(self, name, label, arch, ip, platform, tags, interface, snapshot, resultserver_ip, resultserver_port, reserved):
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
        with self.Session() as session:
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
                    machine.tags.append(self._get_or_create(session, Tag, name=tag))
            session.add(machine)
            try:
                session.commit()
            except SQLAlchemyError as e:
                print(e)
                log.debug("Database error adding machine: %s", e)
                session.rollback()

    @classlock
    def set_machine_interface(self, label, interface):
        with self.Session() as session:
            try:
                machine = session.query(Machine).filter_by(label=label).first()
                if machine is None:
                    log.debug("Database error setting interface: %s not found", label)
                    return None
                machine.interface = interface
                session.commit()

            except SQLAlchemyError as e:
                log.debug("Database error setting interface: %s", e)
                session.rollback()

    @classlock
    def update_clock(self, task_id):
        with self.Session() as session:
            try:
                row = session.get(Task, task_id)

                if not row:
                    return

                if row.clock == datetime.utcfromtimestamp(0):
                    if row.category == "file":
                        row.clock = datetime.utcnow() + timedelta(days=self.cfg.cuckoo.daydelta)
                    else:
                        row.clock = datetime.utcnow()
                    session.commit()
                return row.clock
            except SQLAlchemyError as e:
                log.debug("Database error setting clock: %s", e)
                session.rollback()

    @classlock
    def set_status(self, task_id, status):
        """Set task status.
        @param task_id: task identifier
        @param status: status string
        @return: operation status
        """
        with self.Session() as session:
            try:
                row = session.get(Task, task_id)

                if not row:
                    return

                if status != TASK_DISTRIBUTED_COMPLETED:
                    row.status = status

                if status in (TASK_RUNNING, TASK_DISTRIBUTED):
                    row.started_on = datetime.now()
                elif status in (TASK_COMPLETED, TASK_DISTRIBUTED_COMPLETED):
                    row.completed_on = datetime.now()

                session.commit()
            except SQLAlchemyError as e:
                log.debug("Database error setting status: %s", e)
                session.rollback()

    @classlock
    def set_task_vm_and_guest_start(self, task_id, vmname, vmlabel, vm_id, manager):
        """Set task status and logs guest start.
        @param task_id: task identifier
        @param vmname: virtual vm name
        @param label: vm label
        @param manager: vm manager
        @return: guest row id
        """
        with self.Session() as session:
            guest = Guest(vmname, vmlabel, manager)
            try:
                guest.status = "init"
                row = session.get(Task, task_id)

                if not row:
                    return

                row.guest = guest
                row.machine = vmname
                row.machine_id = vm_id
                session.commit()
                session.refresh(guest)
                return guest.id
            except SQLAlchemyError as e:
                log.debug("Database error setting task vm and logging guest start: %s", e)
                session.rollback()
                return None

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

    @classlock
    def is_relevant_machine_available(self, task: Task) -> bool:
        """Checks if a machine that is relevant to the given task is available
        @return: boolean indicating if a relevant machine is available
        """
        task_archs, task_tags = self._task_arch_tags_helper(task)
        os_version = self._package_vm_requires_check(task.package)
        vms = self.list_machines(
            locked=False, label=task.machine, platform=task.platform, tags=task_tags, arch=task_archs, os_version=os_version
        )
        if len(vms) > 0:
            # There are? Awesome!
            self.set_status(task_id=task.id, status=TASK_RUNNING)
            return True
        return False

    @classlock
    def is_serviceable(self, task: Task) -> bool:
        """Checks if the task is serviceable.

        This method is useful when there are tasks that will never be serviced
        by any of the machines available. This allows callers to decide what to
        do when tasks like this are created.

        @return: boolean indicating if any machine could service the task in the future
        """
        task_archs, task_tags = self._task_arch_tags_helper(task)
        os_version = self._package_vm_requires_check(task.package)
        vms = self.list_machines(label=task.machine, platform=task.platform, tags=task_tags, arch=task_archs, os_version=os_version)
        if len(vms) > 0:
            return True
        return False

    @classlock
    def fetch_task(self, categories: list = []):
        """Fetches a task waiting to be processed and locks it for running.
        @return: None or task
        """
        with self.Session() as session:
            row = None
            try:
                row = (
                    session.query(Task)
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
                session.refresh(row)

                return row
            except SQLAlchemyError as e:
                log.debug("Database error fetching task: %s", e)
                log.debug(red("Ensure that your database schema version is correct"))
                session.rollback()

    @classlock
    def guest_get_status(self, task_id):
        """Log guest start.
        @param task_id: task id
        @return: guest status
        """
        with self.Session() as session:
            try:
                guest = session.query(Guest).filter_by(task_id=task_id).first()
                return guest.status if guest else None
            except SQLAlchemyError as e:
                log.exception("Database error logging guest start: %s", e)
                session.rollback()
                return

    @classlock
    def guest_set_status(self, task_id, status):
        """Log guest start.
        @param task_id: task identifier
        @param status: status
        """
        with self.Session() as session:
            try:
                guest = session.query(Guest).filter_by(task_id=task_id).first()
                if guest is not None:
                    guest.status = status
                    session.commit()
                    session.refresh(guest)
            except SQLAlchemyError as e:
                log.exception("Database error logging guest start: %s", e)
                session.rollback()
                return None

    @classlock
    def guest_remove(self, guest_id):
        """Removes a guest start entry."""
        with self.Session() as session:
            try:
                guest = session.get(Guest, guest_id)
                session.delete(guest)
                session.commit()
            except SQLAlchemyError as e:
                log.debug("Database error logging guest remove: %s", e)
                session.rollback()
                return None

    @classlock
    def guest_stop(self, guest_id):
        """Logs guest stop.
        @param guest_id: guest log entry id
        """
        with self.Session() as session:
            try:
                guest = session.get(Guest, guest_id)
                if guest:
                    guest.shutdown_on = datetime.now()
                    session.commit()
            except SQLAlchemyError as e:
                log.debug("Database error logging guest stop: %s", e)
                session.rollback()
            except TypeError:
                log.warning("Data inconsistency in guests table detected, it might be a crash leftover. Continue")
                session.rollback()

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

    @classlock
    def list_machines(self, locked=None, label=None, platform=None, tags=[], arch=None, include_reserved=False, os_version=[]):
        """Lists virtual machines.
        @return: list of virtual machines
        """
        """
        id |  name  | label | arch |
        ----+-------+-------+------+
        77 | cape1  | win7  | x86  |
        78 | cape2  | win10 | x64  |
        """
        with self.Session() as session:
            try:
                machines = session.query(Machine).options(joinedload(Machine.tags))
                if locked is not None and isinstance(locked, bool):
                    machines = machines.filter_by(locked=locked)
                if label:
                    machines = machines.filter_by(label=label)
                elif not include_reserved:
                    machines = machines.filter_by(reserved=False)
                if platform:
                    machines = machines.filter_by(platform=platform)
                machines = self.filter_machines_by_arch(machines, arch)
                if os_version:
                    machines = machines.filter(Machine.tags.any(Tag.name.in_(os_version)))
                # We can't check os version in tags due to that all tags should be satisfied
                if tags:
                    # machines = machines.filter(Machine.tags.all(Tag.name.in_(tags)))
                    for tag in tags:
                        machines = machines.filter(Machine.tags.any(name=tag))
                return machines.all()
            except SQLAlchemyError as e:
                print(e)
                log.debug("Database error listing machines: %s", e)
                return []

    @classlock
    def lock_machine(self, label=None, platform=None, tags=None, arch=None, os_version=[]):
        """Places a lock on a free virtual machine.
        @param label: optional virtual machine label
        @param platform: optional virtual machine platform
        @param tags: optional tags required (list)
        @param arch: optional virtual machine arch
        @os_version: tags to filter per OS version. Ex: winxp, win7, win10, win11
        @return: locked machine
        """
        with self.Session() as session:

            # Preventive checks.
            if label and platform:
                # Wrong usage.
                log.error("You can select machine only by label or by platform")
                session.close()
                return None
            elif label and tags:
                # Also wrong usage.
                log.error("You can select machine only by label or by tags")
                session.close()
                return None

            try:
                machines = session.query(Machine)
                if label:
                    machines = machines.filter_by(label=label)
                else:
                    machines = machines.filter_by(reserved=False)
                if platform:
                    machines = machines.filter_by(platform=platform)
                machines = self.filter_machines_by_arch(machines, arch)
                if tags:
                    # machines = machines.filter(Machine.tags.all(Tag.name.in_(tags)))
                    for tag in tags:
                        machines = machines.filter(Machine.tags.any(name=tag))
                if os_version:
                    machines = machines.filter(Machine.tags.any(Tag.name.in_(os_version)))
                # Check if there are any machines that satisfy the
                # selection requirements.
                if not machines.count():
                    raise CuckooOperationalError(
                        "No machines match selection criteria of label: '%s', platform: '%s', arch: '%s', tags: '%s'"
                        % (label, platform, arch, tags)
                    )

                # Get the first free machine.
                machine = machines.filter_by(locked=False).first()
            except SQLAlchemyError as e:
                log.debug("Database error locking machine: %s", e)
                return None

            if machine:
                machine.locked = True
                machine.locked_changed_on = datetime.now()
                try:
                    session.commit()
                    session.refresh(machine)
                except SQLAlchemyError as e:
                    log.debug("Database error locking machine: %s", e)
                    session.rollback()
                    return None

        return machine

    @classlock
    def unlock_machine(self, label):
        """Remove lock form a virtual machine.
        @param label: virtual machine label
        @return: unlocked machine
        """
        with self.Session() as session:
            try:
                machine = session.query(Machine).filter_by(label=label).first()
            except SQLAlchemyError as e:
                log.debug("Database error unlocking machine: %s", e)
                return None

            if machine:
                machine.locked = False
                machine.locked_changed_on = datetime.now()
                try:
                    session.commit()
                    session.refresh(machine)
                except SQLAlchemyError as e:
                    log.debug("Database error locking machine: %s", e)
                    session.rollback()
                    return None

        return machine

    @classlock
    def count_machines_available(self, label=None, platform=None, tags=None, arch=None, include_reserved=False, os_version=[]):
        """How many (relevant) virtual machines are ready for analysis.
        @param label: machine ID.
        @param platform: machine platform.
        @param tags: machine tags
        @param arch: machine arch
        @param include_reserved: include 'reserved' machines in the result, regardless of whether or not a 'label' was provided.
        @return: free virtual machines count
        """
        with self.Session() as session:
            try:
                machines = session.query(Machine).filter_by(locked=False)
                if label:
                    machines = machines.filter_by(label=label)
                elif not include_reserved:
                    machines = machines.filter_by(reserved=False)
                if platform:
                    machines = machines.filter_by(platform=platform)
                machines = self.filter_machines_by_arch(machines, arch)
                if tags:
                    # machines = machines.filter(Machine.tags.all(Tag.name.in_(tags)))
                    for tag in tags:
                        machines = machines.filter(Machine.tags.any(name=tag))
                if os_version:
                    machines = machines.filter(Machine.tags.any(Tag.name.in_(os_version)))
                return machines.count()
            except SQLAlchemyError as e:
                log.debug("Database error counting machines: %s", e)
                return 0

    @classlock
    def get_available_machines(self):
        """Which machines are available
        @return: free virtual machines
        """
        with self.Session() as session:
            try:
                machines = session.query(Machine).options(joinedload(Machine.tags)).filter_by(locked=False).all()
                return machines
            except SQLAlchemyError as e:
                log.debug("Database error getting available machines: %s", e)
                return []

    @classlock
    def set_machine_status(self, label, status):
        """Set status for a virtual machine.
        @param label: virtual machine label
        @param status: new virtual machine status
        """
        with self.Session() as session:
            try:
                machine = session.query(Machine).filter_by(label=label).first()
            except SQLAlchemyError as e:
                log.debug("Database error setting machine status: %s", e)
                session.close()
                return

            if machine:
                machine.status = status
                machine.status_changed_on = datetime.now()
                try:
                    session.commit()
                    session.refresh(machine)
                except SQLAlchemyError as e:
                    log.debug("Database error setting machine status: %s", e)
                    session.rollback()

    @classlock
    def add_error(self, message, task_id):
        """Add an error related to a task.
        @param message: error message
        @param task_id: ID of the related task
        """
        with self.Session() as session:
            error = Error(message=message, task_id=task_id)
            session.add(error)
            try:
                session.commit()
            except SQLAlchemyError as e:
                log.debug("Database error adding error log: %s", e)
                session.rollback()

    # The following functions are mostly used by external utils.

    @classlock
    def register_sample(self, obj, source_url=False):
        sample_id = None
        if isinstance(obj, (File, PCAP, Static)):
            with self.Session() as session:
                fileobj = File(obj.file_path)
                file_type = fileobj.get_type()
                file_md5 = fileobj.get_md5()
                sample = None
                # check if hash is known already
                try:
                    sample = session.query(Sample).filter_by(md5=file_md5).first()
                except SQLAlchemyError as e:
                    log.debug("Error querying sample for hash: %s", e)

                if not sample:
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
                    session.add(sample)

                try:
                    session.commit()
                except IntegrityError:
                    session.rollback()
                    try:
                        sample = session.query(Sample).filter_by(md5=file_md5).first()
                    except SQLAlchemyError as e:
                        log.debug("Error querying sample for hash: %s", e)
                        return None
                except SQLAlchemyError as e:
                    log.debug("Database error adding task: %s", e)
                    return None
                finally:
                    sample_id = sample.id

            return sample_id
        return None

    @classlock
    def add(
        self,
        obj,
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
        with self.Session() as session:

            # Convert empty strings and None values to a valid int
            if not timeout:
                timeout = 0
            if not priority:
                priority = 1

            if isinstance(obj, (File, PCAP, Static)):
                fileobj = File(obj.file_path)
                file_type = fileobj.get_type()
                file_md5 = fileobj.get_md5()
                sample = None
                # check if hash is known already
                try:
                    sample = session.query(Sample).filter_by(md5=file_md5).first()
                except SQLAlchemyError as e:
                    log.debug("Error querying sample for hash: %s", e)

                if not sample:
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
                    session.add(sample)

                try:
                    session.commit()
                except IntegrityError:
                    session.rollback()
                    """
                    try:
                        sample = session.query(Sample).filter_by(md5=file_md5).first()
                    except SQLAlchemyError as e:
                        log.debug("Error querying sample for hash: %s", e)
                        session.close()
                        return None
                    """
                except SQLAlchemyError as e:
                    log.debug("Database error adding task: %s", e)
                    session.close()
                    return None

                if DYNAMIC_ARCH_DETERMINATION:
                    # Assign architecture to task to fetch correct VM type
                    # This isn't 100% full proof
                    if "PE32+" in file_type or "64-bit" in file_type or package.endswith("_x64"):
                        if tags:
                            tags += ",x64"
                        else:
                            tags = "x64"
                    else:
                        if LINUX_ENABLED and platform == "linux":
                            linux_arch = _get_linux_vm_tag(file_type)
                            if linux_arch:
                                if tags:
                                    tags += f",{linux_arch}"
                                else:
                                    tags = linux_arch
                        else:
                            if tags:
                                tags += ",x86"
                            else:
                                tags = "x86"
                try:
                    task = Task(obj.file_path)
                    task.sample_id = sample.id
                except OperationalError:
                    return None

                if isinstance(obj, (PCAP, Static)):
                    # since no VM will operate on this PCAP
                    task.started_on = datetime.now()

            elif isinstance(obj, URL):
                task = Task(obj.url)
                tags = "x64,x86"

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
                    if tag.strip():
                        # "Task" object is being merged into a Session along the backref cascade path for relationship "Tag.tasks"; in SQLAlchemy 2.0, this reverse cascade will not take place.
                        # Set cascade_backrefs to False in either the relationship() or backref() function for the 2.0 behavior; or to set globally for the whole Session, set the future=True flag
                        # (Background on this error at: https://sqlalche.me/e/14/s9r1) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)
                        task.tags.append(self._get_or_create(session, Tag, name=tag))

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

            session.add(task)

            try:
                session.commit()
                task_id = task.id
            except SQLAlchemyError as e:
                log.debug("Database error adding task: %s", e)
                session.rollback()
                return None

        return task_id

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
            timeout,
            package,
            options,
            priority,
            custom,
            machine,
            platform,
            tags,
            memory,
            enforce_timeout,
            clock,
            shrike_url,
            shrike_msg,
            shrike_sid,
            shrike_refer,
            parent_id,
            sample_parent_id,
            tlp,
            source_url=source_url,
            route=route,
            cape=cape,
            tags_tasks=tags_tasks,
            user_id=user_id,
            username=username,
        )

    def _identify_aux_func(self, file: bytes, package: str) -> tuple:
        # before demux we need to check as msix has zip mime and we don't want it to be extracted:
        tmp_package = False
        if not package:
            f = SflockFile.from_path(file)
            try:
                tmp_package = sflock_identify(f, check_shellcode=True)
            except Exception as e:
                log.error(f"Failed to sflock_ident due to {e}")
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
    ):
        """
        Handles ZIP file submissions, submitting each extracted file to the database
        Returns a list of added task IDs
        """
        task_id = False
        task_ids = []
        config = {}
        sample_parent_id = None
        # force auto package for linux files
        if platform == "linux":
            package = ""

        if not isinstance(file_path, bytes):
            file_path = file_path.encode()

        if not package:
            if "file=" in options:
                # set zip as package when specifying file= in options
                package = "zip"
            else:
                # Checking original file as some filetypes doesn't require demux
                package, _ = self._identify_aux_func(file_path, package)

        # extract files from the (potential) archive
        extracted_files = demux_sample(file_path, package, options, platform=platform)
        # check if len is 1 and the same file, if diff register file, and set parent
        if extracted_files and (file_path, platform) not in extracted_files:
            sample_parent_id = self.register_sample(File(file_path), source_url=source_url)
            if conf.cuckoo.delete_archive:
                path_delete(file_path.decode())

        # create tasks for each file in the archive
        for file, platform in extracted_files:
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
                    package, tmp_package = self._identify_aux_func(file, "")

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

        details = {}
        if config and isinstance(config, dict):
            details = {"config": config.get("cape_config", {})}
        # this is aim to return custom data, think of this as kwargs
        return task_ids, details

    @classlock
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
            timeout,
            package,
            options,
            priority,
            custom,
            machine,
            platform,
            tags,
            memory,
            enforce_timeout,
            clock,
            shrike_url,
            shrike_msg,
            shrike_sid,
            shrike_refer,
            parent_id,
            tlp,
            user_id,
            username,
        )

    @classlock
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
        extracted_files = demux_sample(file_path, package, options)
        sample_parent_id = None
        # check if len is 1 and the same file, if diff register file, and set parent
        if not isinstance(file_path, bytes):
            file_path = file_path.encode()
        if extracted_files and (file_path, platform) not in extracted_files:
            sample_parent_id = self.register_sample(File(file_path))
            if conf.cuckoo.delete_archive:
                path_delete(file_path)

        task_ids = []
        # create tasks for each file in the archive
        for file, platform in extracted_files:
            task_id = self.add(
                Static(file.decode()),
                timeout,
                package,
                options,
                priority,
                custom,
                machine,
                platform,
                tags,
                memory,
                enforce_timeout,
                clock,
                shrike_url,
                shrike_msg,
                shrike_sid,
                shrike_refer,
                tlp=tlp,
                static=static,
                sample_parent_id=sample_parent_id,
                user_id=user_id,
                username=username,
            )
            if task_id:
                task_ids.append(task_id)

        return task_ids

    @classlock
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
            timeout,
            package,
            options,
            priority,
            custom,
            machine,
            platform,
            tags,
            memory,
            enforce_timeout,
            clock,
            shrike_url,
            shrike_msg,
            shrike_sid,
            shrike_refer,
            parent_id,
            tlp,
            route=route,
            cape=cape,
            tags_tasks=tags_tasks,
            user_id=user_id,
            username=username,
        )

    @classlock
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
        with self.Session() as session:
            session.get(Task, task_id).status = TASK_RECOVERED
            try:
                session.commit()
            except SQLAlchemyError as e:
                log.debug("Database error rescheduling task: %s", e)
                session.rollback()
                return False

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

            session.get(Task, task_id).custom = f"Recovery_{new_task_id}"
            try:
                session.commit()
            except SQLAlchemyError as e:
                log.debug("Database error rescheduling task: %s", e)
                session.rollback()
                return False

            return new_task_id

    @classlock
    def count_matching_tasks(self, category=None, status=None, not_status=None):
        """Retrieve list of task.
        @param category: filter by category
        @param status: filter by task status
        @param not_status: exclude this task status from filter
        @return: number of tasks.
        """
        with self.Session() as session:
            try:
                search = session.query(Task)

                if status:
                    search = search.filter_by(status=status)
                if not_status:
                    search = search.filter(Task.status != not_status)
                if category:
                    search = search.filter_by(category=category)

                tasks = search.count()
                return tasks
            except SQLAlchemyError as e:
                log.debug("Database error counting tasks: %s", e)
                return []

    @classlock
    def check_file_uniq(self, sha256: str, hours: int = 0):
        uniq = False
        with self.Session() as session:
            try:
                if hours and sha256:
                    date_since = datetime.now() - timedelta(hours=hours)
                    date_till = datetime.now()
                    uniq = (
                        session.query(Task)
                        .join(Sample, Task.sample_id == Sample.id)
                        .filter(Sample.sha256 == sha256, Task.added_on.between(date_since, date_till))
                        .first()
                    )
                else:
                    if not Database.find_sample(self, sha256=sha256):
                        uniq = False
                    else:
                        uniq = True
            except SQLAlchemyError as e:
                log.debug("Database error counting tasks: %s", e)

        return uniq

    @classlock
    def list_sample_parent(self, sample_id=False, task_id=False):
        """
        Retrieve parent sample details by sample_id or task_id
        @param sample_id: Sample id
        @param task_id: Task id
        """
        parent_sample = {}
        parent = False
        with self.Session() as session:
            try:
                if sample_id:
                    parent = session.query(Sample.parent).filter(Sample.id == int(sample_id)).first()
                    if parent:
                        parent = parent[0]
                elif task_id:
                    _, parent = (
                        session.query(Task.sample_id, Sample.parent)
                        .join(Sample, Sample.id == Task.sample_id)
                        .filter(Task.id == task_id)
                        .first()
                    )

                if parent:
                    parent_sample = session.query(Sample).filter(Sample.id == parent).first().to_dict()

            except SQLAlchemyError as e:
                log.debug("Database error listing tasks: %s", e)
            except TypeError:
                pass

        return parent_sample

    @classlock
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
        user_id=False,
    ):
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
        @return: list of tasks.
        """
        with self.Session() as session:
            try:
                # Can we remove "options(joinedload)" it is here due to next error
                # sqlalchemy.orm.exc.DetachedInstanceError: Parent instance <Task at X> is not bound to a Session; lazy load operation of attribute 'tags' cannot proceed
                # ToDo this is inefficient but it fails if we don't join. Need to fix this
                search = session.query(Task).options(joinedload(Task.guest), joinedload(Task.errors), joinedload(Task.tags))
                if include_hashes:
                    search = search.join(Sample, Task.sample_id == Sample.id)
                if status:
                    if "|" in status:
                        search = search.filter(Task.status.in_(status.split("|")))
                    else:
                        search = search.filter(Task.status == status)
                if not_status:
                    search = search.filter(Task.status != not_status)
                if category:
                    search = search.filter(Task.category.in_([category] if isinstance(category, str) else category))
                if details:
                    search = search.options(joinedload(Task.guest), joinedload(Task.errors), joinedload(Task.tags))
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
                if user_id:
                    search = search.filter(Task.user_id == user_id)
                if order_by is not None and isinstance(order_by, tuple):
                    search = search.order_by(*order_by)
                elif order_by is not None:
                    search = search.order_by(order_by)
                else:
                    search = search.order_by(Task.added_on.desc())

                tasks = search.limit(limit).offset(offset).all()
                session.expunge_all()
                return tasks
            except RuntimeError as e:
                # RuntimeError: number of values in row (1) differ from number of column processors (62)
                log.debug("Database RuntimeError error: %s", e)
            except AttributeError as e:
                # '_NoResultMetaData' object has no attribute '_indexes_for_keys'
                log.debug("Database AttributeError error: %s", e)
            except SQLAlchemyError as e:
                log.debug("Database error listing tasks: %s", e)
            except Exception as e:
                # psycopg2.DatabaseError
                log.exception(e)

        return []

    def minmax_tasks(self):
        """Find tasks minimum and maximum
        @return: unix timestamps of minimum and maximum
        """
        with self.Session() as session:
            try:
                _min = session.query(func.min(Task.started_on).label("min")).first()
                _max = session.query(func.max(Task.completed_on).label("max")).first()
                if _min and _max and _min[0] and _max[0]:
                    return int(_min[0].strftime("%s")), int(_max[0].strftime("%s"))
            except SQLAlchemyError as e:
                log.debug("Database error counting tasks: %s", e)

        return 0, 0

    @classlock
    def get_tlp_tasks(self):
        """
        Retrieve tasks with TLP
        """
        with self.Session() as session:
            try:
                tasks = session.query(Task).filter(Task.tlp == "true").all()
                if tasks:
                    return [task.id for task in tasks]
                else:
                    return []
            except SQLAlchemyError as e:
                log.debug("Database error listing tasks: %s", e)
                return []

    @classlock
    def get_file_types(self):
        """Get sample filetypes

        @return: A list of all available file types
        """
        with self.Session() as session:
            try:
                unfiltered = session.query(Sample.file_type).group_by(Sample.file_type)
                res = [asample[0] for asample in unfiltered.all()]
                res.sort()
            except SQLAlchemyError as e:
                log.debug("Database error getting file_types: %s", e)
                return 0
        return res

    @classlock
    def get_tasks_status_count(self):
        """Count all tasks in the database
        @return: dict with status and number of tasks found example: {'failed_analysis': 2, 'running': 100, 'reported': 400}
        """
        with self.Session() as session:
            try:
                tasks_dict_count = session.query(Task.status, func.count(Task.status)).group_by(Task.status).all()
                return dict(tasks_dict_count)
            except SQLAlchemyError as e:
                log.debug("Database error counting all tasks: %s", e)
                return 0

    @classlock
    def count_tasks(self, status=None, mid=None):
        """Count tasks in the database
        @param status: apply a filter according to the task status
        @param mid: Machine id to filter for
        @return: number of tasks found
        """
        with self.Session() as session:
            try:
                unfiltered = session.query(Task)
                if mid:
                    unfiltered = unfiltered.filter_by(machine_id=mid)
                if status:
                    unfiltered = unfiltered.filter_by(status=status)
                tasks_count = get_count(unfiltered, Task.id)
                return tasks_count
            except SQLAlchemyError as e:
                log.debug("Database error counting tasks: %s", e)
                return 0

    @classlock
    def view_task(self, task_id, details=False):
        """Retrieve information on a task.
        @param task_id: ID of the task to query.
        @return: details on the task.
        """
        with self.Session() as session:
            try:
                if details:
                    task = (
                        select(Task)
                        .where(Task.id == task_id)
                        .options(joinedload(Task.guest), joinedload(Task.errors), joinedload(Task.tags), joinedload(Task.sample))
                    )
                    task = session.execute(task).first()
                else:
                    query = select(Task).where(Task.id == task_id).options(joinedload(Task.tags), joinedload(Task.sample))
                    task = session.execute(query).first()
                if task:
                    task = task[0]
                    session.expunge(task)
                    return task
            except SQLAlchemyError as e:
                print(e)
                log.debug("Database error viewing task: %s", e)

    @classlock
    def add_statistics_to_task(self, task_id, details):
        """add statistic to task
        @param task_id: ID of the task to query.
        @param: details statistic.
        @return true of false.
        """
        with self.Session() as session:
            try:
                task = session.get(Task, task_id)
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
                session.commit()
                session.refresh(task)
            except SQLAlchemyError as e:
                log.debug("Database error deleting task: %s", e)
                session.rollback()
                return False
        return True

    @classlock
    def delete_task(self, task_id):
        """Delete information on a task.
        @param task_id: ID of the task to query.
        @return: operation status.
        """
        with self.Session() as session:
            try:
                task = session.get(Task, task_id)
                session.delete(task)
                session.commit()
            except SQLAlchemyError as e:
                log.debug("Database error deleting task: %s", e)
                session.rollback()
                return False
        return True

    # classlock
    def delete_tasks(self, ids):
        with self.Session() as session:
            try:
                _ = session.query(Task).filter(Task.id.in_(ids)).delete(synchronize_session=False)
            except SQLAlchemyError as e:
                log.debug("Database error deleting task: %s", e)
                session.rollback()
                return False
        return True

    @classlock
    def view_sample(self, sample_id):
        """Retrieve information on a sample given a sample id.
        @param sample_id: ID of the sample to query.
        @return: details on the sample used in sample: sample_id.
        """
        with self.Session() as session:
            try:
                sample = session.get(Sample, sample_id)
            except AttributeError:
                return None
            except SQLAlchemyError as e:
                log.debug("Database error viewing task: %s", e)
                return None
            else:
                if sample:
                    session.expunge(sample)

        return sample

    @classlock
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
        with self.Session() as session:
            try:
                if md5:
                    sample = session.query(Sample).filter_by(md5=md5).first()
                elif sha1:
                    sample = session.query(Sample).filter_by(sha1=sha1).first()
                elif sha256:
                    sample = session.query(Sample).filter_by(sha256=sha256).first()
                elif parent:
                    sample = session.query(Sample).filter_by(parent=parent).all()
                elif sample_id:
                    sample = session.query(Sample).filter_by(id=sample_id).all()
                elif task_id:
                    sample = (
                        session.query(Task)
                        .options(joinedload(Task.sample))
                        .filter(Task.id == task_id)
                        .filter(Sample.id == Task.sample_id)
                        .all()
                    )
            except SQLAlchemyError as e:
                log.debug("Database error searching sample: %s", e)
                return None
            else:
                if sample:
                    session.expunge_all()
        return sample

    @classlock
    def sample_still_used(self, sample_hash: str, task_id: int):
        """Retrieve information if sample is used by another task(s).
        @param hash: md5/sha1/sha256/sha256.
        @param task_id: task_id
        @return: bool
        """
        with self.Session() as session:
            db_sample = (
                session.query(Sample)
                # .options(joinedload(Task.sample))
                .filter(Sample.sha256 == sample_hash)
                .filter(Task.id != task_id)
                .filter(Sample.id == Task.sample_id)
                .filter(Task.status.in_((TASK_PENDING, TASK_RUNNING, TASK_DISTRIBUTED)))
                .first()
            )
            still_used = bool(db_sample)
            return still_used

    @classlock
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

        sizes_mongo = {
            32: "md5",
            40: "sha1",
            64: "sha256",
            128: "sha512",
        }

        folders = {
            "dropped": "files",
            "CAPE": "CAPE",
            "procdump": "procdump",
        }

        if task_id:
            file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "binary")
            if path_exists(file_path):
                return [file_path]

        session = False
        # binary also not stored in binaries, perform hash lookup
        if task_id and not sample_hash:
            session = self.Session()
            db_sample = (
                session.query(Sample)
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
            try:
                if not session:
                    session = self.Session()
                db_sample = session.query(Sample).filter(query_filter == sample_hash).first()
                if db_sample is not None:
                    path = os.path.join(CUCKOO_ROOT, "storage", "binaries", db_sample.sha256)
                    if path_exists(path):
                        sample = [path]

                if not sample:
                    if repconf.mongodb.enabled:
                        tasks = mongo_find(
                            "analysis",
                            {"CAPE.payloads.file_ref": sample_hash},
                            {"CAPE.payloads": 1, "_id": 0, "info.id": 1},
                        )
                    elif repconf.elasticsearchdb.enabled:
                        tasks = [
                            d["_source"]
                            for d in es.search(
                                index=get_analysis_index(),
                                body={"query": {"match": {"CAPE.payloads.file_ref": sample_hash}}},
                                _source=["CAPE.payloads", "info.id"],
                            )["hits"]["hits"]
                        ]
                    else:
                        tasks = []

                    if tasks:
                        for task in tasks:
                            for block in task.get("CAPE", {}).get("payloads", []) or []:
                                if block[sizes_mongo.get(len(sample_hash), "")] == sample_hash:
                                    file_path = os.path.join(
                                        CUCKOO_ROOT,
                                        "storage",
                                        "analyses",
                                        str(task["info"]["id"]),
                                        folders.get("CAPE"),
                                        block["sha256"],
                                    )
                                    if path_exists(file_path):
                                        sample = [file_path]
                                        break
                            if sample:
                                break

                    for category in ("dropped", "procdump"):
                        # we can't filter more if query isn't sha256
                        if repconf.mongodb.enabled:
                            tasks = mongo_find(
                                "analysis",
                                {f"{category}.{sizes_mongo.get(len(sample_hash), '')}": sample_hash},
                                {category: 1, "_id": 0, "info.id": 1},
                            )
                        elif repconf.elasticsearchdb.enabled:
                            tasks = [
                                d["_source"]
                                for d in es.search(
                                    index=get_analysis_index(),
                                    body={"query": {"match": {f"{category}.{sizes_mongo.get(len(sample_hash), '')}": sample_hash}}},
                                    _source=["info.id", category],
                                )["hits"]["hits"]
                            ]
                        else:
                            tasks = []

                        if tasks:
                            for task in tasks:
                                for block in task.get(category, []) or []:
                                    if block[sizes_mongo.get(len(sample_hash), "")] == sample_hash:
                                        file_path = os.path.join(
                                            CUCKOO_ROOT,
                                            "storage",
                                            "analyses",
                                            str(task["info"]["id"]),
                                            folders.get(category),
                                            block["sha256"],
                                        )
                                        if path_exists(file_path):
                                            sample = [file_path]
                                            break
                                if sample:
                                    break

                if not sample:
                    # search in temp folder if not found in binaries
                    db_sample = (
                        session.query(Task).join(Sample, Task.sample_id == Sample.id).filter(query_filter == sample_hash).all()
                    )

                    if db_sample is not None:
                        samples = [_f for _f in [tmp_sample.to_dict().get("target", "") for tmp_sample in db_sample] if _f]
                        # hash validation and if exist
                        samples = [file_path for file_path in samples if path_exists(file_path)]
                        for path in samples:
                            with open(path, "rb").read() as f:
                                if sample_hash == sizes[len(sample_hash)](f).hexdigest():
                                    sample = [path]
                                    break

                if not sample:
                    # search in Suricata files folder
                    if repconf.mongodb.enabled:
                        tasks = mongo_find(
                            "analysis", {"suricata.files.sha256": sample_hash}, {"suricata.files.file_info.path": 1, "_id": 0}
                        )
                    elif repconf.elasticsearchdb.enabled:
                        tasks = [
                            d["_source"]
                            for d in es.search(
                                index=get_analysis_index(),
                                body={"query": {"match": {"suricata.files.sha256": sample_hash}}},
                                _source="suricata.files.file_info.path",
                            )["hits"]["hits"]
                        ]
                    else:
                        tasks = []

                    if tasks:
                        for task in tasks:
                            for item in task["suricata"]["files"] or []:
                                file_path = item.get("file_info", {}).get("path", "")
                                if sample_hash in file_path:
                                    if path_exists(file_path):
                                        sample = [file_path]
                                        break

            except AttributeError:
                pass
            except SQLAlchemyError as e:
                log.debug("Database error viewing task: %s", e)
            finally:
                session.close()

        return sample

    @classlock
    def count_samples(self):
        """Counts the amount of samples in the database."""
        with self.Session() as session:
            try:
                sample_count = session.query(Sample).count()
            except SQLAlchemyError as e:
                log.debug("Database error counting samples: %s", e)
                return 0
        return sample_count

    @classlock
    def view_machine(self, name):
        """Show virtual machine.
        @params name: virtual machine name
        @return: virtual machine's details
        """
        with self.Session() as session:
            try:
                machine = session.query(Machine).options(joinedload(Machine.tags)).filter(Machine.name == name).first()
                # machine = session.execute(select(Machine).filter(Machine.name == name).options(joinedload(Tag))).first()
            except SQLAlchemyError as e:
                log.debug("Database error viewing machine: %s", e)
                return None
            else:
                if machine:
                    session.expunge(machine)
        return machine

    @classlock
    def view_machine_by_label(self, label):
        """Show virtual machine.
        @params label: virtual machine label
        @return: virtual machine's details
        """
        with self.Session() as session:
            try:
                machine = session.query(Machine).options(joinedload(Machine.tags)).filter(Machine.label == label).first()
            except SQLAlchemyError as e:
                log.debug("Database error viewing machine by label: %s", e)
                return None
            else:
                if machine:
                    session.expunge(machine)
        return machine

    @classlock
    def view_errors(self, task_id):
        """Get all errors related to a task.
        @param task_id: ID of task associated to the errors
        @return: list of errors.
        """
        with self.Session() as session:
            try:
                errors = session.query(Error).filter_by(task_id=task_id).all()
            except SQLAlchemyError as e:
                log.debug("Database error viewing errors: %s", e)
                return []
        return errors

    @classlock
    def get_source_url(self, sample_id=False):
        """
        Retrieve url from where sample was downloaded
        @param sample_id: Sample id
        @param task_id: Task id
        """
        source_url = False
        with self.Session() as session:
            try:
                if sample_id:
                    source_url = session.query(Sample.source_url).filter(Sample.id == int(sample_id)).first()
                    if source_url:
                        source_url = source_url[0]
            except SQLAlchemyError as e:
                log.debug("Database error listing tasks: %s", e)
            except TypeError:
                pass

        return source_url

    @classlock
    def ban_user_tasks(self, user_id: int):
        """
        Ban all tasks submitted by user_id
        @param user_id: user id
        """

        with self.Session() as session:
            _ = (
                session.query(Task)
                .filter(Task.user_id == user_id)
                .filter(Task.status == TASK_PENDING)
                .update({Task.status: TASK_BANNED}, synchronize_session=False)
            )
            session.commit()
            session.close()

    @classlock
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

        self.set_status(task_id, TASK_COMPLETED)
        return False, "", task.status
