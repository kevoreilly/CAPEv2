# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# https://blog.miguelgrinberg.com/post/what-s-new-in-sqlalchemy-2-0
# https://docs.sqlalchemy.org/en/20/changelog/migration_20.html#

import logging
import os
import sys
from contextlib import suppress
from typing import Any, Optional

def _utcnow_naive():
    """Returns the current time in UTC as a naive datetime object."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Sflock does a good filetype recon
from sflock.abstracts import File as SflockFile
from sflock.ident import identify as sflock_identify

from lib.cuckoo.common.cape_utils import static_config_lookup, static_extraction
from lib.cuckoo.common.colors import red
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import (
    CuckooDatabaseError,
    CuckooDatabaseInitializationError,
    CuckooDependencyError,
    CuckooOperationalError
)
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.utils import create_folder

from .data.db_common import Base
from .data.guac_session import GuacSession  # noqa: F401 - must be imported before create_all()
from .data.tasking import TasksMixIn
from .data.machines import MachinesMixIn
from .data.samples import SamplesMixIn
from .data.guests import GuestsMixIn
from .data.audits import AuditsMixIn


try:
    from sqlalchemy.engine import make_url
    from sqlalchemy import String, create_engine, func, select
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import (
        scoped_session,
        sessionmaker,
        Mapped,
        mapped_column,
    )

except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")

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
    "nodejs",
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

channel_layer = None
if web_conf.general.get("real_time_updates", False):
    # Django Channels Hooks (Conditional)
    with suppress(ImportError, Exception):
        import django
        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer
        # Ensure apps are loaded if we are running inside cuckoo.py/utils
        if not django.apps.apps.ready:
            # We need to setup django to use channels, but this might fail if settings aren't configured
            # inside a standalone script.
            # Assuming CAPE environment variables are set or typical project structure.
            try:
                os.environ.setdefault("DJANGO_SETTINGS_MODULE", "web.settings")
                django.setup()
            except Exception as e:
                log.warning("Could not initialize Django Channels for real-time updates: %s", e)

        channel_layer = get_channel_layer()


if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_find
if repconf.elasticsearchdb.enabled:
    from dev_utils.elasticsearchdb import elastic_handler  # , get_analysis_index
    es = elastic_handler

def get_count(q, property):
    count_q = q.statement.with_only_columns(func.count(property)).order_by(None)
    count = q.session.execute(count_q).scalar()
    return count



class AlembicVersion(Base):
    """Table used to pinpoint actual database schema release."""

    __tablename__ = "alembic_version"

    version_num: Mapped[str] = mapped_column(String(32), nullable=False, primary_key=True)



class _Database(TasksMixIn,
                GuestsMixIn,
                MachinesMixIn,
                SamplesMixIn,
                AuditsMixIn):
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
        self.session = scoped_session(sessionmaker(bind=self.engine, expire_on_commit=False, future=True))

        # ToDo this breaks tests
        """
        # There should be a better way to clean up orphans. This runs after every flush, which is crazy.
        @event.listens_for(self.session, "after_flush")
        def delete_tag_orphans(session, ctx):
            delete_stmt = delete(Tag).where(~Tag.tasks.any()).where(~Tag.machines.any())
            session.execute(delete_stmt)
        """

        # Deal with schema versioning.
        # TODO: it's a little bit dirty, needs refactoring.
        with self.session() as tmp_session:
            # Use the modern select() and scalar() to fetch the first object
            query = select(AlembicVersion)
            last = tmp_session.scalar(query)

            if last is None:
                # Set database schema version (this part is unchanged)
                tmp_session.add(AlembicVersion(version_num=SCHEMA_VERSION))
                try:
                    tmp_session.commit()
                except SQLAlchemyError as e:  # pragma: no cover
                    tmp_session.rollback()
                    raise CuckooDatabaseError(f"Unable to set schema version: {e}")
            else:
                # Check if db version is the expected one (this part is unchanged)
                if last.version_num != SCHEMA_VERSION and schema_check:  # pragma: no cover
                    print(
                        f"DB schema version mismatch: found {last.version_num}, expected {SCHEMA_VERSION}. Try to apply all migrations"
                    )
                    print(red("Please backup your data before migration!\ncd utils/db_migration/ && poetry run alembic upgrade head"))
                    sys.exit()

    def __del__(self):
        """Disconnects pool."""
        with suppress(KeyError, AttributeError):
            self.engine.dispose()

    def _connect_database(self, connection_string):
        """Connect to a Database.
        @param connection_string: Connection string specifying the database
        """
        url = make_url(connection_string)
        engine_args = {}

        try:
            if url.drivername.startswith("sqlite"):
                # Using "check_same_thread" to disable sqlite safety check on multiple threads.
                engine_args["connect_args"] = {"check_same_thread": False}
            elif url.drivername.startswith("postgresql"):
                # See: http://www.postgresql.org/docs/9.0/static/libpq-ssl.html#LIBPQ-SSL-SSLMODE-STATEMENTS
                # Disabling SSL mode to avoid some errors using sqlalchemy and multiprocessing.
                engine_args["connect_args"] = {"sslmode": self.cfg.database.psql_ssl_mode}
                engine_args["pool_pre_ping"] = True
            # A single, clean call to create the engine
            self.engine = create_engine(connection_string, **engine_args)

        except ImportError as e:  # pragma: no cover
            lib = e.message.rsplit(maxsplit=1)[-1]
            raise CuckooDependencyError(f"Missing database driver, unable to import {lib} (install with `pip install {lib}`)")

    def _get_or_create(self, model, **kwargs):
        """Get an ORM instance or create it if not exist.
        @param session: SQLAlchemy session object
        @param model: model to query
        @return: row instance
        """
        cache = self.session.info.setdefault("_get_or_create_cache", {})
        cache_key = (model, frozenset(kwargs.items()))
        if cache_key in cache:
            return cache[cache_key]

        stmt = select(model).filter_by(**kwargs)
        # Execute with session.scalar() to get a single object or None
        instance = self.session.scalar(stmt)
        if instance:
            cache[cache_key] = instance
            return instance
        else:
            instance = model(**kwargs)
            self.session.add(instance)
            cache[cache_key] = instance

        return instance

    def drop(self):
        """Drop all tables."""
        try:
            Base.metadata.drop_all(self.engine, checkfirst=True)
        except SQLAlchemyError as e:
            raise CuckooDatabaseError(f"Unable to create or connect to database: {e}")


    # ---- Guac session helpers ----

    def create_guac_session(self, token, task_id, vm_label, guest_ip):
        """Create a new guac session for a task."""
        session = self.session()
        try:
            guac = GuacSession(token=str(token), task_id=task_id, vm_label=vm_label, guest_ip=guest_ip)
            session.add(guac)
            session.commit()
            return guac
        except Exception:
            session.rollback()
            raise

    def get_guac_session(self, token):
        """Look up a guac session by token. Returns dict or None."""
        from lib.cuckoo.core.data.guac_session import GuacSession
        session = self.session()
        try:
            row = session.query(GuacSession).filter_by(token=str(token)).first()
            if row:
                return {"task_id": row.task_id, "vm_label": row.vm_label, "guest_ip": getattr(row, "guest_ip", None)}
            return None
        except Exception:
            return None

    def delete_guac_session(self, token):
        """Delete a guac session token."""
        from lib.cuckoo.core.data.guac_session import GuacSession
        session = self.session()
        try:
            session.query(GuacSession).filter_by(token=str(token)).delete()
            session.commit()
        except Exception:
            session.rollback()

    def delete_guac_sessions_for_task(self, task_id):
        """Delete all guac sessions for a task."""
        from lib.cuckoo.core.data.guac_session import GuacSession
        session = self.session()
        try:
            session.query(GuacSession).filter_by(task_id=task_id).delete()
            session.commit()
        except Exception:
            session.rollback()

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

