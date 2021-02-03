# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import sys
import json
import logging
from datetime import datetime, timedelta

import pymongo
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.colors import red
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooDatabaseError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.objects import File, URL, PCAP, Static
from lib.cuckoo.common.utils import create_folder, Singleton, classlock, SuperLock, get_options
from lib.cuckoo.common.demux import demux_sample
from lib.cuckoo.common.cape_utils import static_extraction, static_config_lookup

try:
    from sqlalchemy import create_engine, Column, event
    from sqlalchemy import Integer, String, Boolean, DateTime, Enum, func, or_
    from sqlalchemy import ForeignKey, Text, Index, Table, text
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.exc import SQLAlchemyError, IntegrityError
    from sqlalchemy.orm import sessionmaker, relationship, joinedload, backref

    Base = declarative_base()
except ImportError:
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `pip3 install sqlalchemy`)")

log = logging.getLogger(__name__)
conf = Config("cuckoo")
repconf = Config("reporting")

results_db = pymongo.MongoClient(
    repconf.mongodb.host,
    port=repconf.mongodb.port,
    username=repconf.mongodb.get("username", None),
    password=repconf.mongodb.get("password", None),
    authSource=repconf.mongodb.db,
)[repconf.mongodb.db]

SCHEMA_VERSION = "6ab863a3b510"
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

# Secondary table used in association Machine - Tag.
machines_tags = Table(
    "machines_tags", Base.metadata, Column("machine_id", Integer, ForeignKey("machines.id")), Column("tag_id", Integer, ForeignKey("tags.id"))
)

# Secondary table used in association Task - Tag.
tasks_tags = Table(
    "tasks_tags", Base.metadata, Column("task_id", Integer, ForeignKey("tasks.id")), Column("tag_id", Integer, ForeignKey("tags.id"))
)


class Machine(Base):
    """Configured virtual machines to be used as guests."""

    __tablename__ = "machines"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False)
    label = Column(String(255), nullable=False)
    ip = Column(String(255), nullable=False)
    platform = Column(String(255), nullable=False)
    tags = relationship("Tag", secondary=machines_tags, backref="machines")
    interface = Column(String(255), nullable=True)
    snapshot = Column(String(255), nullable=True)
    locked = Column(Boolean(), nullable=False, default=False)
    locked_changed_on = Column(DateTime(timezone=False), nullable=True)
    status = Column(String(255), nullable=True)
    status_changed_on = Column(DateTime(timezone=False), nullable=True)
    resultserver_ip = Column(String(255), nullable=False)
    resultserver_port = Column(String(255), nullable=False)

    def __repr__(self):
        return "<Machine('{0}','{1}')>".format(self.id, self.name)

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

    def __init__(self, name, label, ip, platform, interface, snapshot, resultserver_ip, resultserver_port):
        self.name = name
        self.label = label
        self.ip = ip
        self.platform = platform
        self.interface = interface
        self.snapshot = snapshot
        self.resultserver_ip = resultserver_ip
        self.resultserver_port = resultserver_port


class Tag(Base):
    """Tag describing anything you want."""

    __tablename__ = "tags"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False, unique=True)

    def __repr__(self):
        return "<Tag('{0}','{1}')>".format(self.id, self.name)

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
        return "<Guest('{0}','{1}')>".format(self.id, self.name)

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
        return "<Sample('{0}','{1}')>".format(self.id, self.sha256)

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
    message = Column(String(255), nullable=False)
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
        return "<Error('{0}','{1}','{2}')>".format(self.id, self.message, self.task_id)


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
    tags = relationship("Tag", secondary=tasks_tags, backref="tasks", lazy="subquery")
    options = Column(String(1024), nullable=True)
    platform = Column(String(255), nullable=True)
    memory = Column(Boolean, nullable=False, default=False)
    enforce_timeout = Column(Boolean, nullable=False, default=False)
    clock = Column(DateTime(timezone=False), default=datetime.now(), nullable=False)
    added_on = Column(DateTime(timezone=False), default=datetime.now, nullable=False)
    started_on = Column(DateTime(timezone=False), nullable=True)
    completed_on = Column(DateTime(timezone=False), nullable=True)
    status = Column(
        Enum(
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
    sample = relationship("Sample", backref="tasks", lazy="subquery")
    machine_id = Column(Integer, nullable=True)
    guest = relationship("Guest", uselist=False, backref="tasks", cascade="save-update, delete")
    errors = relationship("Error", backref="tasks", cascade="save-update, delete")

    shrike_url = Column(String(4096), nullable=True)
    shrike_refer = Column(String(4096), nullable=True)
    shrike_msg = Column(String(4096), nullable=True)
    shrike_sid = Column(Integer(), nullable=True)

    parent_id = Column(Integer(), nullable=True)
    tlp = Column(String(255), nullable=True)

    user_id = Column(Integer(), nullable=True)

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
        return "<Task('{0}','{1}')>".format(self.id, self.target)


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
        self.cfg = Config()

        if dsn:
            self._connect_database(dsn)
        elif self.cfg.database.connection:
            self._connect_database(self.cfg.database.connection)
        else:
            db_file = os.path.join(CUCKOO_ROOT, "db", "cuckoo.db")
            if not os.path.exists(db_file):
                db_dir = os.path.dirname(db_file)
                if not os.path.exists(db_dir):
                    try:
                        create_folder(folder=db_dir)
                    except CuckooOperationalError as e:
                        raise CuckooDatabaseError("Unable to create database directory: {0}".format(e))

            self._connect_database("sqlite:///%s" % db_file)

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
            raise CuckooDatabaseError("Unable to create or connect to database: {0}".format(e))

        # Get db session.
        self.Session = sessionmaker(bind=self.engine)
        # load vms tags
        self.vms_tags = dict()
        self.tasks_filters = dict()
        session = self.Session()
        machines = session.query(Machine).options(joinedload("tags")).all()
        for machine in machines:
            self.vms_tags[machine.name] = [tag.name for tag in machine.tags]
            self.tasks_filters[machine.name] = or_(*[Task.tags.any(name=tag.name) for tag in machine.tags])
        session.close()

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
                raise CuckooDatabaseError("Unable to set schema version: {0}".format(e))
            finally:
                tmp_session.close()
        else:
            # Check if db version is the expected one.
            last = tmp_session.query(AlembicVersion).first()
            tmp_session.close()
            if last.version_num != SCHEMA_VERSION and schema_check:
                print("DB schema version mismatch: found {0}, expected {1}. Try to apply all migrations".format(last.version_num, SCHEMA_VERSION))
                print(red("cd utils/db_migration/ && alembic upgrade head"))
                sys.exit()

    def __del__(self):
        """Disconnects pool."""
        try:
            self.engine.dispose()
        except KeyError:
            pass

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
                self.engine = create_engine(connection_string, connect_args={"sslmode": "disable"})
            else:
                self.engine = create_engine(connection_string)
        except ImportError as e:
            lib = e.message.split()[-1]
            raise CuckooDependencyError("Missing database driver, unable to " "import %s (install with `pip " "install %s`)" % (lib, lib))

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
            raise CuckooDatabaseError("Unable to create or connect to database: {0}".format(e))

    @classlock
    def clean_machines(self):
        """Clean old stored machines and related tables."""
        # Secondary table.
        # TODO: this is better done via cascade delete.
        self.engine.execute(machines_tags.delete())

        session = self.Session()
        try:
            session.query(Machine).delete()
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error cleaning machines: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
    def delete_machine(self, name):
        """Delete a single machine entry from DB."""

        session = self.Session()
        try:
            machine = session.query(Machine).filter_by(name=name).first()
            session.delete(machine)
            session.commit()
            return "success"
        except SQLAlchemyError as e:
            log.info("Database error deleting machine: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
    def add_machine(self, name, label, ip, platform, tags, interface, snapshot, resultserver_ip, resultserver_port):
        """Add a guest machine.
        @param name: machine id
        @param label: machine label
        @param ip: machine IP address
        @param platform: machine supported platform
        @param tags: list of comma separated tags
        @param interface: sniffing interface for this machine
        @param snapshot: snapshot name to use instead of the current one, if configured
        @param resultserver_ip: IP address of the Result Server
        @param resultserver_port: port of the Result Server
        """
        session = self.Session()
        machine = Machine(
            name=name,
            label=label,
            ip=ip,
            platform=platform,
            interface=interface,
            snapshot=snapshot,
            resultserver_ip=resultserver_ip,
            resultserver_port=resultserver_port,
        )
        # Deal with tags format (i.e., foo,bar,baz)
        if tags:
            for tag in tags.replace(" ", "").split(","):
                machine.tags.append(self._get_or_create(session, Tag, name=tag))
        session.add(machine)

        try:
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error adding machine: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
    def set_machine_interface(self, label, interface):
        session = self.Session()
        try:
            machine = session.query(Machine).filter_by(label=label).first()
            if machine is None:
                log.debug("Database error setting interface: {0} not found".format(label))
                return None
            machine.interface = interface
            session.commit()

        except SQLAlchemyError as e:
            log.debug("Database error setting interface: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
    def update_clock(self, task_id):
        session = self.Session()
        try:
            row = session.query(Task).get(task_id)

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
            log.debug("Database error setting clock: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
    def set_status(self, task_id, status):
        """Set task status.
        @param task_id: task identifier
        @param status: status string
        @return: operation status
        """
        session = self.Session()
        try:
            row = session.query(Task).get(task_id)

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
            log.debug("Database error setting status: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
    def set_task_vm(self, task_id, vmname, vm_id):
        """Set task status.
        @param task_id: task identifier
        @param vmname: virtual vm name
        @return: operation status
        """
        session = self.Session()
        try:
            row = session.query(Task).get(task_id)

            if not row:
                return

            row.machine = vmname
            row.machine_id = vm_id
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error setting status: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    @classlock
    def fetch(self, lock=True, machine=""):
        """Fetches a task waiting to be processed and locks it for running.
        @return: None or task
        """
        session = self.Session()
        row = None
        try:
            if machine != "":
                row = (
                    session.query(Task)
                    .filter_by(status=TASK_PENDING)
                    .filter_by(machine=machine)
                    .order_by(Task.priority.desc(), Task.added_on)
                    .first()
                )
                if not row and self.vms_tags.get(machine, False):
                    cond = self.tasks_filters[machine]
                    row = (
                        session.query(Task)
                        .options(joinedload("tags"))
                        .filter_by(status=TASK_PENDING)
                        .order_by(Task.priority.desc(), Task.added_on)
                        .filter(cond)
                        .first()
                    )
            else:
                row = (
                    session.query(Task)
                    .filter_by(status=TASK_PENDING)
                    .order_by(Task.priority.desc(), Task.added_on)
                    .filter(Task.tags == None)
                    .first()
                )
            if not row:
                return None

            if lock:
                self.set_status(task_id=row.id, status=TASK_RUNNING)
                session.refresh(row)

            return row
        except SQLAlchemyError as e:
            log.debug("Database error fetching task: {0}".format(e))
            log.debug(red("Ensure that your database schema version is correct"))
            session.rollback()
        finally:
            session.close()

    @classlock
    def guest_start(self, task_id, name, label, manager):
        """Logs guest start.
        @param task_id: task identifier
        @param name: vm name
        @param label: vm label
        @param manager: vm manager
        @return: guest row id
        """
        session = self.Session()
        guest = Guest(name, label, manager)
        try:
            guest.status = "init"
            session.query(Task).get(task_id).guest = guest
            session.commit()
            session.refresh(guest)
            return guest.id
        except SQLAlchemyError as e:
            log.debug("Database error logging guest start: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

    @classlock
    def guest_get_status(self, task_id):
        """Log guest start.
        @param task_id: task id
        @return: guest status
        """
        session = self.Session()
        try:
            guest = session.query(Guest).filter_by(task_id=task_id).first()
            return guest.status if guest else None
        except SQLAlchemyError as e:
            log.exception("Database error logging guest start: {0}".format(e))
            session.rollback()
            return
        finally:
            session.close()

    @classlock
    def guest_set_status(self, task_id, status):
        """Log guest start.
        @param task_id: task identifier
        @param status: status
        """
        session = self.Session()
        try:
            guest = session.query(Guest).filter_by(task_id=task_id).first()
            if guest is not None:
                guest.status = status
                session.commit()
                session.refresh(guest)
        except SQLAlchemyError as e:
            log.exception("Database error logging guest start: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

    @classlock
    def guest_remove(self, guest_id):
        """Removes a guest start entry."""
        session = self.Session()
        try:
            guest = session.query(Guest).get(guest_id)
            session.delete(guest)
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error logging guest remove: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

    @classlock
    def guest_stop(self, guest_id):
        """Logs guest stop.
        @param guest_id: guest log entry id
        """
        session = self.Session()
        try:
            session.query(Guest).get(guest_id).shutdown_on = datetime.now()
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error logging guest stop: {0}".format(e))
            session.rollback()
        except TypeError:
            log.warning("Data inconsistency in guests table detected, it might be a crash leftover. Continue")
            session.rollback()
        finally:
            session.close()

    @classlock
    def list_machines(self, locked=False, platform="", tags=[]):
        """Lists virtual machines.
        @return: list of virtual machines
        """
        session = self.Session()
        try:
            if locked:
                machines = session.query(Machine).options(joinedload("tags")).filter_by(locked=True).all()
            elif platform:
                machines = session.query(Machine).options(joinedload("tags")).filter_by(platform=platform).all()
            else:
                machines = session.query(Machine).options(joinedload("tags")).all()
            if tags:
                machines = [machine for tag in tags for machine in machines if tag in machine.to_dict()["tags"]]
            return machines
        except SQLAlchemyError as e:
            log.debug("Database error listing machines: {0}".format(e))
            return []
        finally:
            session.close()

    @classlock
    def lock_machine(self, label=None, platform=None, tags=None):
        """Places a lock on a free virtual machine.
        @param label: optional virtual machine label
        @param platform: optional virtual machine platform
        @param tags: optional tags required (list)
        @return: locked machine
        """
        session = self.Session()

        # Preventive checks.
        if label and platform:
            # Wrong usage.
            log.error("You can select machine only by label or by platform.")
            session.close()
            return None
        elif label and tags:
            # Also wrong usage.
            log.error("You can select machine only by label or by tags.")
            session.close()
            return None

        try:
            machines = session.query(Machine)
            if label:
                machines = machines.filter_by(label=label)
            if platform:
                machines = machines.filter_by(platform=platform)
            if tags:
                for tag in tags:
                    machines = machines.filter(Machine.tags.any(name=tag.name))

            # Check if there are any machines that satisfy the
            # selection requirements.
            if not machines.count():
                session.close()
                raise CuckooOperationalError("No machines match selection criteria.")

            # Get the first free machine.
            machine = machines.filter_by(locked=False).first()
        except SQLAlchemyError as e:
            log.debug("Database error locking machine: {0}".format(e))
            session.close()
            return None

        if machine:
            machine.locked = True
            machine.locked_changed_on = datetime.now()
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError as e:
                log.debug("Database error locking machine: {0}".format(e))
                session.rollback()
                return None
            finally:
                session.close()
        else:
            session.close()

        return machine

    @classlock
    def unlock_machine(self, label):
        """Remove lock form a virtual machine.
        @param label: virtual machine label
        @return: unlocked machine
        """
        session = self.Session()
        try:
            machine = session.query(Machine).filter_by(label=label).first()
        except SQLAlchemyError as e:
            log.debug("Database error unlocking machine: {0}".format(e))
            session.close()
            return None

        if machine:
            machine.locked = False
            machine.locked_changed_on = datetime.now()
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError as e:
                log.debug("Database error locking machine: {0}".format(e))
                session.rollback()
                return None
            finally:
                session.close()
        else:
            session.close()

        return machine

    @classlock
    def count_machines_available(self):
        """How many virtual machines are ready for analysis.
        @return: free virtual machines count
        """
        session = self.Session()
        try:
            machines_count = session.query(Machine).filter_by(locked=False).count()
            return machines_count
        except SQLAlchemyError as e:
            log.debug("Database error counting machines: {0}".format(e))
            return 0
        finally:
            session.close()

    @classlock
    def get_available_machines(self):
        """  Which machines are available
        @return: free virtual machines
        """
        session = self.Session()
        try:
            machines = session.query(Machine).filter_by(locked=False).all()
            return machines
        except SQLAlchemyError as e:
            log.debug("Database error getting available machines: {0}".format(e))
            return []
        finally:
            session.close()

    @classlock
    def set_machine_status(self, label, status):
        """Set status for a virtual machine.
        @param label: virtual machine label
        @param status: new virtual machine status
        """
        session = self.Session()
        try:
            machine = session.query(Machine).filter_by(label=label).first()
        except SQLAlchemyError as e:
            log.debug("Database error setting machine status: {0}".format(e))
            session.close()
            return

        if machine:
            machine.status = status
            machine.status_changed_on = datetime.now()
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError as e:
                log.debug("Database error setting machine status: {0}".format(e))
                session.rollback()
            finally:
                session.close()
        else:
            session.close()

    @classlock
    def add_error(self, message, task_id):
        """Add an error related to a task.
        @param message: error message
        @param task_id: ID of the related task
        """
        session = self.Session()
        error = Error(message=message, task_id=task_id)
        session.add(error)
        try:
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error adding error log: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    # The following functions are mostly used by external utils.

    @classlock
    def register_sample(self, obj, source_url=False):
        sample_id = None
        if isinstance(obj, File) or isinstance(obj, PCAP) or isinstance(obj, Static):
            session = self.Session()
            fileobj = File(obj.file_path)
            file_type = fileobj.get_type()
            file_md5 = fileobj.get_md5()
            sample = Sample(
                md5=file_md5,
                crc32=fileobj.get_crc32(),
                sha1=fileobj.get_sha1(),
                sha256=fileobj.get_sha256(),
                sha512=fileobj.get_sha512(),
                file_size=fileobj.get_size(),
                file_type=file_type,
                ssdeep=fileobj.get_ssdeep(),
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
                    log.debug("Error querying sample for hash: {0}".format(e))
                    session.close()
                    return None
            except SQLAlchemyError as e:
                log.debug("Database error adding task: {0}".format(e))
                session.close()
                return None
            finally:
                sample_id = sample.id
                session.close()

            return sample_id
        else:
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
        route = None,
        cape = False,
        tags_tasks = False,
        user_id = False,

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
        @return: cursor or None.
        """
        session = self.Session()

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1

        if isinstance(obj, File) or isinstance(obj, PCAP) or isinstance(obj, Static):
            fileobj = File(obj.file_path)
            file_type = fileobj.get_type()
            file_md5 = fileobj.get_md5()
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
                try:
                    sample = session.query(Sample).filter_by(md5=file_md5).first()
                except SQLAlchemyError as e:
                    log.debug("Error querying sample for hash: {0}".format(e))
                    session.close()
                    return None
            except SQLAlchemyError as e:
                log.debug("Database error adding task: {0}".format(e))
                session.close()
                return None

            # force a special tag for 64-bit binaries to prevent them from being
            # analyzed by default on VM types that can't handle them
            if not machine:
                if "PE32+" in file_type or "64-bit" in file_type:
                    if tags:
                        tags += ",x64"
                    else:
                        tags = "x64"

            task = Task(obj.file_path)
            task.sample_id = sample.id

            if isinstance(obj, PCAP) or isinstance(obj, Static):
                # since no VM will operate on this PCAP
                task.started_on = datetime.now()

        elif isinstance(obj, URL):
            task = Task(obj.url)

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
            for tag in tags.replace(" ", "").split(","):
                task.tags.append(self._get_or_create(session, Tag, name=tag))

        if clock:
            if isinstance(clock, str):
                try:
                    task.clock = datetime.strptime(clock, "%m-%d-%Y %H:%M:%S")
                except ValueError:
                    log.warning("The date you specified has an invalid format, using current timestamp.")
                    task.clock = datetime.utcfromtimestamp(0)

            else:
                task.clock = clock
        else:
            task.clock = datetime.utcfromtimestamp(0)

        task.user_id = user_id

        session.add(task)

        try:
            session.commit()
            task_id = task.id
        except SQLAlchemyError as e:
            log.debug("Database error adding task: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

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
        user_id=False,
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
        @return: cursor or None.
        """
        if not file_path or not os.path.exists(file_path):
            log.warning("File does not exist: %s.", file_path)
            return None

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1

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
        sample_parent_id=None,
        tlp=None,
        static=False,
        source_url=False,
        only_extraction=False,
        tags_tasks=False,
        route=None,
        cape=False,
        user_id=False,
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
        # extract files from the (potential) archive
        extracted_files = demux_sample(file_path, package, options)
        # check if len is 1 and the same file, if diff register file, and set parent
        if not isinstance(file_path, bytes):
            file_path = file_path.encode("utf-8")
        if extracted_files and file_path not in extracted_files:
            sample_parent_id = self.register_sample(File(file_path), source_url=source_url)
            if conf.cuckoo.delete_archive:
                os.remove(file_path)

        # Check for 'file' option indicating supporting files needed for upload; otherwise create task for each file
        opts = get_options(options)
        if "file" in opts:
            runfile = opts["file"].lower()
            if isinstance(runfile, str):
                runfile = runfile.encode("utf8")
            for xfile in extracted_files:
                if runfile in xfile.lower():
                    extracted_files = [xfile]
                    break

        # create tasks for each file in the archive
        for file in extracted_files:
            if static:
                # we don't need to process extra file if we already have it and config
                config = static_config_lookup(file)
                if not config:
                    config = static_extraction(file)
                    if config:
                        task_id = self.add_static(file_path=file, priority=priority, tlp=tlp, user_id=user_id)
                else:
                    task_ids.append(config["id"])
            if not config and only_extraction is False:
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
                )
            if task_id:
                task_ids.append(task_id)

        details = {}
        if config:
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
        user_id=None,
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
        user_id = False
    ):
        return self.add(
            Static(file_path.decode()),
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
            static,
            user_id = user_id,
        )

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
        user_id=False,
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
        @return: cursor or None.
        """

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1

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
            route = route,
            cape = cape,
            tags_tasks = tags_tasks,
            user_id = user_id,
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
        session = self.Session()
        session.query(Task).get(task_id).status = TASK_RECOVERED
        try:
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error rescheduling task: {0}".format(e))
            session.rollback()
            return False
        finally:
            session.close()

        # Normalize tags.
        if task.tags:
            tags = ",".join(tag.name for tag in task.tags)
        else:
            tags = task.tags

        return add(
            task.target,
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

    @classlock
    def count_matching_tasks(self, category=None, status=None, not_status=None):
        """Retrieve list of task.
        @param category: filter by category
        @param status: filter by task status
        @param not_status: exclude this task status from filter
        @return: number of tasks.
        """
        session = self.Session()
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
            log.debug("Database error counting tasks: {0}".format(e))
            return []
        finally:
            session.close()

    @classlock
    def check_file_uniq(self, sha256: str, hours: int=0):
        uniq = False
        session = self.Session()
        try:
            if hours and sha256:
                date_since = datetime.now()-timedelta(hours=hours)
                date_till = datetime.now()
                uniq = session.query(Task).join(Sample, Task.sample_id==Sample.id).filter(Sample.sha256==sha256, Task.added_on.between(date_since, date_till)).first()
            else:
                if not Database.find_sample(self, sha256=sha256):
                    uniq = False
                else:
                    uniq = True
        except SQLAlchemyError as e:
            log.debug("Database error counting tasks: {0}".format(e))
        finally:
            session.close()

        return uniq

    @classlock
    def list_parents(self, parent_id):
        """
            Retrieve tasks created by ID
            @param parent_id: filter tasks created by parent ID
        """
        session = self.Session()
        try:
            tasks = session.query(Task).filter(Task.parent_id == parent_id).all()
            if tasks:
                return [[task.id, task.package] for task in tasks]
            else:
                return []
        except SQLAlchemyError as e:
            log.debug("Database error listing tasks: {0}".format(e))
            return []
        finally:
            session.close()

    @classlock
    def list_sample_parent(self, sample_id=False, task_id=False):
        """
            Retrieve parent sample details by sample_id or task_id
            @param sample_id: Sample id
            @param task_id: Task id
        """
        parent_sample = dict()
        parent = False
        session = self.Session()
        try:
            if sample_id:
                parent = session.query(Sample.parent).filter(Sample.id == int(sample_id)).first()
                if parent:
                    parent = parent[0]
            elif task_id:
                _, parent = (
                    session.query(Task.sample_id, Sample.parent).join(Sample, Sample.id == Task.sample_id).filter(Task.id == task_id).first()
                )

            if parent:
                parent_sample = session.query(Sample).filter(Sample.id == parent).first().to_dict()

        except SQLAlchemyError as e:
            log.debug("Database error listing tasks: {0}".format(e))
        except TypeError:
            pass
        finally:
            session.close()

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
        tags_tasks_like=False,
        task_ids=False,
        inclide_hashes=False,
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
        @param options_like: filter tasks by specific option insde of the options
        @param tags_tasks_like: filter tasks by specific tag
        @param task_ids: list of task_id
        @param inclide_hashes: return task+samples details
        @return: list of tasks.
        """
        session = self.Session()
        try:
            search = session.query(Task)
            if inclide_hashes:
                search = search.join(Sample, Task.sample_id==Sample.id)
            if status:
                search = search.filter(Task.status==status)
            if not_status:
                search = search.filter(Task.status != not_status)
            if category:
                search = search.filter(Task.category==category)
            if details:
                search = search.options(joinedload("guest"), joinedload("errors"), joinedload("tags"))
            if sample_id is not None:
                search = search.filter(Task.sample_id==sample_id)
            if id_before is not None:
                search = search.filter(Task.id < id_before)
            if id_after is not None:
                search = search.filter(Task.id > id_after)
            if completed_after:
                search = search.filter(Task.completed_on > completed_after)
            if added_before:
                search = search.filter(Task.added_on < added_before)
            if options_like:
                search = search.filter(Task.options.like("%{}%".format(options_like)))
            if tags_tasks_like:
                search = search.filter(Task.tags_tasks.like("%{}%".format(tags_tasks_like)))
            if task_ids:
                search = search.filter(Task.id.in_(task_ids))
            if order_by is not None:
                search = search.order_by(order_by)
            else:
                search = search.order_by(Task.added_on.desc())

            return search.limit(limit).offset(offset).all()
        except SQLAlchemyError as e:
            log.debug("Database error listing tasks: {0}".format(e))
            return []
        finally:
            session.close()

    def minmax_tasks(self):
        """Find tasks minimum and maximum
         @return: unix timestamps of minimum and maximum
         """
        session = self.Session()
        try:
            _min = session.query(func.min(Task.started_on).label("min")).first()
            _max = session.query(func.max(Task.completed_on).label("max")).first()
            return int(_min[0].strftime("%s")), int(_max[0].strftime("%s"))
        except SQLAlchemyError as e:
            log.debug("Database error counting tasks: {0}".format(e))
            return 0
        finally:
            session.close()

    @classlock
    def get_tlp_tasks(self):
        """
            Retrieve tasks with TLP
        """
        session = self.Session()
        try:
            tasks = session.query(Task).filter(Task.tlp == "true").all()
            if tasks:
                return [task.id for task in tasks]
            else:
                return []
        except SQLAlchemyError as e:
            log.debug("Database error listing tasks: {0}".format(e))
            return []
        finally:
            session.close()

    @classlock
    def get_file_types(self):
        """Get sample filetypes

        @return: A list of all available file types
        """
        session = self.Session()
        try:
            unfiltered = session.query(Sample.file_type).group_by(Sample.file_type)
            res = []
            for asample in unfiltered.all():
                res.append(asample[0])
            res.sort()
        except SQLAlchemyError as e:
            log.debug("Database error getting file_types: {0}".format(e))
            return 0
        finally:
            session.close()
        return res

    @classlock
    def count_tasks(self, status=None, mid=None):
        """Count tasks in the database
        @param status: apply a filter according to the task status
        @param mid: Machine id to filter for
        @return: number of tasks found
        """
        session = self.Session()
        try:
            unfiltered = session.query(Task)
            if mid:
                unfiltered = unfiltered.filter_by(machine_id=mid)
            if status:
                unfiltered = unfiltered.filter_by(status=status)
            tasks_count = unfiltered.count()
            return tasks_count
        except SQLAlchemyError as e:
            log.debug("Database error counting tasks: {0}".format(e))
            return 0
        finally:
            session.close()

    @classlock
    def view_task(self, task_id, details=False):
        """Retrieve information on a task.
        @param task_id: ID of the task to query.
        @return: details on the task.
        """
        session = self.Session()
        try:
            if details:
                task = session.query(Task).options(joinedload("guest"), joinedload("errors"), joinedload("tags")).get(task_id)
            else:
                task = session.query(Task).get(task_id)
        except SQLAlchemyError as e:
            log.debug("Database error viewing task: {0}".format(e))
            return None
        else:
            if task:
                session.expunge(task)
            return task
        finally:
            session.close()

    @classlock
    def delete_task(self, task_id):
        """Delete information on a task.
        @param task_id: ID of the task to query.
        @return: operation status.
        """
        session = self.Session()
        try:
            task = session.query(Task).get(task_id)
            session.delete(task)
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error deleting task: {0}".format(e))
            session.rollback()
            return False
        finally:
            session.close()
        return True

    #classlock
    def delete_tasks(self, ids):
        session = self.Session()
        try:
            search = session.query(Task).filter(Task.id.in_(ids)).delete(synchronize_session=False)
        except SQLAlchemyError as e:
            log.debug("Database error deleting task: {0}".format(e))
            session.rollback()
            return False
        finally:
            session.close()
        return True

    @classlock
    def view_sample(self, sample_id):
        """Retrieve information on a sample given a sample id.
        @param sample_id: ID of the sample to query.
        @return: details on the sample used in sample: sample_id.
        """
        session = self.Session()
        try:
            sample = session.query(Sample).get(sample_id)
        except AttributeError:
            return None
        except SQLAlchemyError as e:
            log.debug("Database error viewing task: {0}".format(e))
            return None
        else:
            if sample:
                session.expunge(sample)
        finally:
            session.close()

        return sample

    @classlock
    def find_sample(self, md5=None, sha1=None, sha256=None, parent=None):
        """Search samples by MD5, SHA1, or SHA256.
        @param md5: md5 string
        @param sha1: sha1 string
        @param sha256: sha256 string
        @param parent: sample_id int
        @return: matches list
        """
        sample = False
        session = self.Session()
        try:
            if md5:
                sample = session.query(Sample).filter_by(md5=md5).first()
            elif sha1:
                sample = session.query(Sample).filter_by(sha1=sha1).first()
            elif sha256:
                sample = session.query(Sample).filter_by(sha256=sha256).first()
            elif parent:
                sample = session.query(Sample).filter_by(parent=parent).all()
        except SQLAlchemyError as e:
            log.debug("Database error searching sample: {0}".format(e))
            return None
        else:
            if sample:
                session.expunge_all()
        finally:
            session.close()
        return sample

    @classlock
    def sample_path_by_hash(self, sample_hash):
        """Retrieve information on a sample location by given hash.
        @param hash: md5/sha1/sha256/sha256.
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

        query_filter = sizes.get(len(sample_hash), "")
        sample = None
        # check storage/binaries
        if query_filter:
            session = self.Session()
            try:

                db_sample = session.query(Sample).filter(query_filter == sample_hash).first()
                if db_sample is not None:
                    path = os.path.join(CUCKOO_ROOT, "storage", "binaries", db_sample.sha256)
                    if os.path.exists(path):
                        sample = [path]

                if sample is None:
                    tasks = results_db.analysis.find({"CAPE.payloads." + sizes_mongo.get(len(sample_hash), ""): sample_hash},
                                                     {"CAPE.payloads": 1, "_id": 0, "info.id":1 })
                    if tasks:
                        for task in tasks:
                            for block in task.get("CAPE", {}).get("payloads", []) or []:
                                if block[sizes_mongo.get(len(sample_hash), "")] == sample_hash:
                                    path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["info"]["id"]), folders.get("CAPE"),
                                                        block["sha256"])
                                    if os.path.exists(path):
                                        sample = [path]
                                        break
                            if sample:
                                break

                    for category in ("dropped", "procdump"):
                        # we can't filter more if query isn't sha256
                        tasks = results_db.analysis.find({category + "." + sizes_mongo.get(len(sample_hash), ""): sample_hash},
                                                         {category: 1, "_id": 0, "info.id":1 })
                        if tasks:
                            for task in tasks:
                                for block in task.get(category, []) or []:
                                    if block[sizes_mongo.get(len(sample_hash), "")] == sample_hash:
                                        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["info"]["id"]), folders.get(category),
                                                            block["sha256"])
                                        if os.path.exists(path):
                                            sample = [path]
                                            break
                                if sample:
                                    break

                if sample is None:
                    # search in temp folder if not found in binaries
                    db_sample = session.query(Task).filter(query_filter == sample_hash).filter(Sample.id == Task.sample_id).all()
                    if db_sample is not None:
                        samples = [_f for _f in [tmp_sample.to_dict().get("target", "") for tmp_sample in db_sample] if _f]
                        # hash validation and if exist
                        samples = [path for path in samples if os.path.exists(path)]
                        for path in samples:
                            with open(path, "rb").read() as f:
                                if sample_hash == sizes[len(sample_hash)](f).hexdigest():
                                    sample = [path]
                                    break
            except AttributeError:
                pass
            except SQLAlchemyError as e:
                log.debug("Database error viewing task: {0}".format(e))
            finally:
                session.close()

        return sample

    @classlock
    def count_samples(self):
        """Counts the amount of samples in the database."""
        session = self.Session()
        try:
            sample_count = session.query(Sample).count()
        except SQLAlchemyError as e:
            log.debug("Database error counting samples: {0}".format(e))
            return 0
        finally:
            session.close()
        return sample_count

    @classlock
    def view_machine(self, name):
        """Show virtual machine.
        @params name: virtual machine name
        @return: virtual machine's details
        """
        session = self.Session()
        try:
            machine = session.query(Machine).options(joinedload("tags")).filter(Machine.name == name).first()
        except SQLAlchemyError as e:
            log.debug("Database error viewing machine: {0}".format(e))
            return None
        else:
            if machine:
                session.expunge(machine)
        finally:
            session.close()
        return machine

    @classlock
    def view_machine_by_label(self, label):
        """Show virtual machine.
        @params label: virtual machine label
        @return: virtual machine's details
        """
        session = self.Session()
        try:
            machine = session.query(Machine).options(joinedload("tags")).filter(Machine.label == label).first()
        except SQLAlchemyError as e:
            log.debug("Database error viewing machine by label: {0}".format(e))
            return None
        else:
            if machine:
                session.expunge(machine)
        finally:
            session.close()
        return machine

    @classlock
    def view_errors(self, task_id):
        """Get all errors related to a task.
        @param task_id: ID of task associated to the errors
        @return: list of errors.
        """
        session = self.Session()
        try:
            errors = session.query(Error).filter_by(task_id=task_id).all()
        except SQLAlchemyError as e:
            log.debug("Database error viewing errors: {0}".format(e))
            return []
        finally:
            session.close()
        return errors

    @classlock
    def get_source_url(self, sample_id=False):
        """
            Retrieve url from where sample was downloaded
            @param sample_id: Sample id
            @param task_id: Task id
        """
        source_url = False
        session = self.Session()
        try:
            if sample_id:
                source_url = session.query(Sample.source_url).filter(Sample.id == int(sample_id)).first()
                if source_url:
                    source_url = source_url[0]
        except SQLAlchemyError as e:
            log.debug("Database error listing tasks: {0}".format(e))
        except TypeError:
            pass
        finally:
            session.close()

        return source_url
