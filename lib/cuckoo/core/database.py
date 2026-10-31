# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# https://blog.miguelgrinberg.com/post/what-s-new-in-sqlalchemy-2-0
# https://docs.sqlalchemy.org/en/20/changelog/migration_20.html#

import logging
import os
import sys
import time
import traceback
from contextlib import contextmanager, suppress
from typing import Any, Iterator, Optional

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


# ToDo postgresql+psycopg2 in connection
try:
    from sqlalchemy.engine import make_url
    from sqlalchemy import String, create_engine, delete, event, select
    from sqlalchemy.exc import OperationalError, SQLAlchemyError
    from sqlalchemy.orm import (
        Session,
        SessionTransactionOrigin,
        scoped_session,
        sessionmaker,
        Mapped,
        mapped_column,
    )

except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")



SCHEMA_VERSION = "4c2d_drop_inline_tenancy"

log = logging.getLogger(__name__)
conf = Config("cuckoo")
repconf = Config("reporting")
distconf = Config("distributed")
web_conf = Config("web")
LINUX_ENABLED = web_conf.linux.enabled
LINUX_STATIC = web_conf.linux.static_only
DYNAMIC_ARCH_DETERMINATION = web_conf.general.dynamic_arch_determination

if repconf.elasticsearchdb.enabled:
    from dev_utils.elasticsearchdb import elastic_handler  # , get_analysis_index
    es = elastic_handler



def is_operational_error(exc: BaseException) -> bool:
    """Return True if exc is a SQLAlchemy or DBAPI OperationalError (including SQLSTATE subclasses)."""
    return isinstance(exc, OperationalError) or any(
        cls.__name__ == "OperationalError" for cls in type(exc).__mro__
    )


def run_db_unit(db, fn, desc: str, logger: Optional[logging.Logger] = None, attempts: int = 2, backoff: float = 1.0):
    """Run fn() as one unit of work in its own db.transaction() and return its result.

    On OperationalError (server restart, dropped connection) the transaction rolls back,
    the thread-local session is discarded and fn() runs again from scratch, up to
    `attempts` times in total. fn() must be the whole unit of work and must re-read the
    ORM objects it needs by id (or merge them): objects from the discarded session are
    detached. Keep side effects that must happen once (logging, file I/O) outside fn().

    If the caller is already inside a transaction, fn() joins it and errors propagate:
    the outer transaction is aborted and only its owner can retry.

    @param desc: description of the unit of work, used in the retry log.
    """
    if db.session().info.get(_TX_DEPTH_KEY, 0):
        return fn()

    for attempt in range(1, attempts + 1):
        try:
            with db.transaction():
                return fn()
        except Exception as e:
            if attempt >= attempts or not is_operational_error(e):
                raise
            (logger or log).warning("Database connection error during %s, retrying (%d/%d): %s", desc, attempt, attempts - 1, e)
            time.sleep(backoff)


# Set to "1" to raise instead of warn when a statement runs outside db.transaction() (used by tests).
STRICT_TX_ENV = "CAPE_DB_STRICT_TRANSACTIONS"

# libpq/psycopg connect errors that a retry cannot fix.
_PERMANENT_CONNECT_ERROR_MARKERS = (
    "password authentication failed",
    "authentication failed",
    "no pg_hba.conf entry",
    "does not exist",
    "invalid dsn",
)
# SQLSTATE: 28000 invalid_authorization_specification, 28P01 invalid_password, 3D000 invalid_catalog_name
_PERMANENT_CONNECT_SQLSTATES = ("28000", "28P01", "3D000")


def _is_permanent_connect_error(exc: BaseException) -> bool:
    """Return True for connection errors caused by configuration rather than server availability."""
    sqlstate = getattr(exc, "pgcode", None) or getattr(exc, "sqlstate", None)
    if sqlstate in _PERMANENT_CONNECT_SQLSTATES:
        return True
    message = str(exc).lower()
    return any(marker in message for marker in _PERMANENT_CONNECT_ERROR_MARKERS)

_TX_DEPTH_KEY = "cape_tx_depth"
_TX_FAILED_KEY = "cape_tx_failed"
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_SKIP_FRAME_PARTS = (os.sep + "sqlalchemy" + os.sep, os.sep + "contextlib.py", __file__)


def _caller_site() -> str:
    """Return 'file:line in func' of the innermost frame outside SQLAlchemy and this module."""
    frames = [f for f in traceback.extract_stack()[:-2] if not any(p in f.filename for p in _SKIP_FRAME_PARTS)]
    if not frames:
        return "<unknown>"
    # Innermost DB helper plus its caller, e.g. "data/machines.py:400 in view_machine <- abstracts.py:475 in start"
    return " <- ".join(f"{os.path.relpath(f.filename, _REPO_ROOT)}:{f.lineno} in {f.name}" for f in reversed(frames[-2:]))



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
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.session = scoped_session(self.session_factory)

        # Transaction ownership: the *caller* owns the transaction. DB helper methods
        # (data/*.py mixins) never begin/commit/rollback; entry points wrap their unit
        # of work in `with db.transaction():`. `db.session.begin()` is kept as an alias
        # of `db.transaction()` for existing callers and third-party modules.
        self.strict_transactions = os.environ.get(STRICT_TX_ENV, "") == "1"
        self._reported_autobegin_sites = set()
        self.session.begin = self.transaction
        event.listen(self.session_factory, "after_transaction_create", self._on_transaction_create)

        # ToDo this breaks tests
        """
        # There should be a better way to clean up orphans. This runs after every flush, which is crazy.
        @event.listens_for(self.session, "after_flush")
        def delete_tag_orphans(session, ctx):
            delete_stmt = delete(Tag).where(~Tag.tasks.any()).where(~Tag.machines.any())
            session.execute(delete_stmt)
        """

        # Deal with schema versioning.
        try:
            with self.session_factory() as tmp_session, tmp_session.begin():
                last = tmp_session.scalar(select(AlembicVersion))
                if last is None:
                    tmp_session.add(AlembicVersion(version_num=SCHEMA_VERSION))
        except SQLAlchemyError as e:  # pragma: no cover
            raise CuckooDatabaseError(f"Unable to set schema version: {e}")

        # Check if db version is the expected one.
        if last is not None and last.version_num != SCHEMA_VERSION and schema_check and "pytest" not in sys.modules:  # pragma: no cover
            print(f"DB schema version mismatch: found {last.version_num}, expected {SCHEMA_VERSION}. Try to apply all migrations")
            print(
                red(
                    f"Please backup your data before migration!\ncd {os.path.join(CUCKOO_ROOT, 'utils', 'db_migration')} && poetry run alembic upgrade head"
                )
            )
            sys.exit()

    @contextmanager
    def transaction(self) -> Iterator[Session]:
        """Run the enclosed block in a database transaction on the thread-local session.

        Re-entrant: only the outermost block begins and commits; nested blocks join it.
        Any exception propagates and rolls back the whole (outermost) transaction. If a
        nested block raised a database error that an intermediate caller swallowed, the
        outermost block still rolls back and raises CuckooDatabaseError instead of
        committing a transaction the server has already aborted.

        On OperationalError (lost connection, server restart) the thread-local session is
        discarded so the next unit of work starts on a fresh connection. ORM objects loaded
        in that session become detached; re-read them or use `session.merge()`.
        """
        sess = self.session()
        depth = sess.info.get(_TX_DEPTH_KEY, 0)
        if depth:
            sess.info[_TX_DEPTH_KEY] = depth + 1
            try:
                yield sess
            except Exception as e:
                if isinstance(e, SQLAlchemyError) or is_operational_error(e):
                    sess.info[_TX_FAILED_KEY] = True
                raise
            finally:
                sess.info[_TX_DEPTH_KEY] = depth
            return

        if sess.in_transaction():
            # A statement ran outside db.transaction() and autobegan; _on_transaction_create
            # already reported where. Commit it so its writes are not silently discarded.
            sess.commit()

        sess.info[_TX_DEPTH_KEY] = 1
        sess.info[_TX_FAILED_KEY] = False
        try:
            with sess.begin():
                yield sess
                if sess.info.get(_TX_FAILED_KEY):
                    raise CuckooDatabaseError("A nested database operation failed; transaction rolled back")
        except Exception as e:
            if is_operational_error(e):
                self.session.remove()
            raise
        finally:
            sess.info[_TX_DEPTH_KEY] = 0
            sess.info[_TX_FAILED_KEY] = False

    def _on_transaction_create(self, session: Session, transaction) -> None:
        """Report statements executed outside an explicit transaction (autobegin)."""
        if transaction.parent is not None or transaction.origin is not SessionTransactionOrigin.AUTOBEGIN:
            return
        site = _caller_site()
        if self.strict_transactions:
            raise CuckooDatabaseError(f"Database statement executed outside db.transaction(): {site}")
        if site not in self._reported_autobegin_sites:
            self._reported_autobegin_sites.add(site)
            log.warning("Database statement executed outside db.transaction(), wrap the caller: %s", site)

    def __del__(self):
        """Disconnects pool."""
        with suppress(KeyError, AttributeError):
            self.engine.dispose()

    def _connect_database(self, connection_string):
        """Connect to a Database.
        @param connection_string: Connection string specifying the database
        """
        # Auto-upgrade connection string to postgresql+psycopg if postgresql:// is used with psycopg v3 installed
        if connection_string.startswith("postgresql://"):
            try:
                import psycopg  # noqa: F401
                connection_string = connection_string.replace("postgresql://", "postgresql+psycopg://", 1)
            except ImportError:
                pass

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

            if url.drivername.startswith("postgresql"):
                self._register_postgresql_connect_retry(self.engine)

        except ImportError as e:  # pragma: no cover
            lib = e.message.rsplit(maxsplit=1)[-1]
            raise CuckooDependencyError(f"Missing database driver, unable to import {lib} (install with `pip install {lib}`)")

    @staticmethod
    def _register_postgresql_connect_retry(engine, retry_delays=(1, 2, 4, 5, 5, 5, 5)):
        """Retry new PostgreSQL connections while the server restarts.

        Only transient errors are retried; configuration errors (bad credentials, missing
        database, pg_hba rejection) fail immediately so misconfiguration is not hidden
        behind ~30s of retries.
        """

        @event.listens_for(engine, "do_connect")
        def receive_do_connect(dialect, conn_rec, cargs, cparams):
            for attempt, delay in enumerate(retry_delays, start=1):
                try:
                    return dialect.connect(*cargs, **cparams)
                except Exception as e:
                    if not is_operational_error(e) or _is_permanent_connect_error(e):
                        raise
                    log.warning(
                        "Database connection failed (attempt %d/%d): %s. Retrying in %ds...",
                        attempt,
                        len(retry_delays),
                        e,
                        delay,
                    )
                    time.sleep(delay)
            return dialect.connect(*cargs, **cparams)

        return receive_do_connect

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


    # ---- Guac session helpers (caller owns the transaction) ----

    def create_guac_session(self, token, task_id, vm_label, guest_ip) -> GuacSession:
        """Create a new guac session for a task."""
        guac = GuacSession(token=str(token), task_id=task_id, vm_label=vm_label, guest_ip=guest_ip)
        self.session.add(guac)
        return guac

    def get_guac_session(self, token) -> Optional[dict]:
        """Look up a guac session by token. Returns dict or None."""
        row = self.session.scalar(select(GuacSession).where(GuacSession.token == str(token)).limit(1))
        if row is None:
            return None
        return {"task_id": row.task_id, "vm_label": row.vm_label, "guest_ip": row.guest_ip}

    def delete_guac_session(self, token) -> None:
        """Delete a guac session token."""
        self.session.execute(delete(GuacSession).where(GuacSession.token == str(token)))

    def delete_guac_sessions_for_task(self, task_id) -> None:
        """Delete all guac sessions for a task."""
        self.session.execute(delete(GuacSession).where(GuacSession.task_id == task_id))

_DATABASE: Optional[_Database] = None


class Database:
    def __getattr__(self, attr: str) -> Any:
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError(attr)
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

