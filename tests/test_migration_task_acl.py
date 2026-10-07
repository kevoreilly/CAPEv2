"""Migration 4b2c_task_acl (tenancy moved off `tasks` into `task_acl`) and the Task model's
absent-row == default invariant.

Runs the real migration functions against a live SQLite connection, because 4b2c decides
what to do by inspecting the schema -- that cannot be exercised in Alembic's offline mode.
"""
import importlib.util
import os

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

VERSIONS = os.path.join(os.path.dirname(__file__), "..", "utils", "db_migration", "versions")


def _load(filename, modname):
    spec = importlib.util.spec_from_file_location(modname, os.path.join(VERSIONS, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MIG3 = _load("3_add_tenant_visibility.py", "mig3_tenant_vis")
MIG4 = _load("4_move_tenancy_to_task_acl.py", "mig4_task_acl")


def _run(conn, fn):
    with Operations.context(MigrationContext.configure(conn)):
        fn()


def _cols(conn, table="tasks"):
    return {c["name"] for c in sa.inspect(conn).get_columns(table)}


@pytest.fixture
def conn():
    eng = sa.create_engine("sqlite://")
    with eng.begin() as c:
        c.exec_driver_sql("PRAGMA foreign_keys=ON")
        yield c


def _tasks_pre_mt(c):
    c.exec_driver_sql("CREATE TABLE tasks (id INTEGER PRIMARY KEY, target TEXT NOT NULL)")


def _tasks_with_original_3a1b(c):
    """Schema + data as left by the ORIGINAL (column-adding) 3a1b body."""
    c.exec_driver_sql(
        "CREATE TABLE tasks (id INTEGER PRIMARY KEY, target TEXT NOT NULL, "
        "tenant_id INTEGER, visibility VARCHAR(16) NOT NULL DEFAULT 'private')"
    )
    c.exec_driver_sql("CREATE INDEX ix_tasks_tenant_id ON tasks (tenant_id)")
    c.exec_driver_sql(
        "INSERT INTO tasks (id, target, tenant_id, visibility) VALUES "
        "(1, 'a', NULL, 'private'),"   # default -> must NOT be copied
        "(2, 'b', 10,   'tenant'),"
        "(3, 'c', NULL, 'public'),"    # MT-off web submission shape
        "(4, 'd', 10,   'private')"    # non-default tenant, default visibility
    )


def test_rev3_is_now_a_noop(conn):
    _tasks_pre_mt(conn)
    _run(conn, MIG3.upgrade)
    assert _cols(conn) == {"id", "target"}


def test_rev4_on_install_that_never_had_columns(conn):
    _tasks_pre_mt(conn)
    conn.exec_driver_sql("INSERT INTO tasks (id, target) VALUES (1, 'a')")
    _run(conn, MIG4.upgrade)
    assert _cols(conn) == {"id", "target"}, "tasks must not be touched"
    assert conn.exec_driver_sql("SELECT COUNT(*) FROM task_acl").scalar() == 0


def test_rev4_moves_only_non_default_rows_and_drops_columns(conn):
    _tasks_with_original_3a1b(conn)
    _run(conn, MIG4.upgrade)

    assert _cols(conn) == {"id", "target"}
    assert "ix_tasks_tenant_id" not in {i["name"] for i in sa.inspect(conn).get_indexes("tasks")}
    rows = conn.exec_driver_sql("SELECT task_id, tenant_id, visibility FROM task_acl ORDER BY task_id").fetchall()
    assert [tuple(r) for r in rows] == [(2, 10, "tenant"), (3, None, "public"), (4, 10, "private")]
    assert conn.exec_driver_sql("SELECT COUNT(*) FROM tasks").scalar() == 4, "no task lost"


def test_rev4_downgrade_restores_original_columns_and_values(conn):
    _tasks_with_original_3a1b(conn)
    _run(conn, MIG4.upgrade)
    _run(conn, MIG4.downgrade)

    assert {"tenant_id", "visibility"} <= _cols(conn)
    assert not sa.inspect(conn).has_table("task_acl")
    rows = conn.exec_driver_sql("SELECT id, tenant_id, visibility FROM tasks ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [(1, None, "private"), (2, 10, "tenant"), (3, None, "public"), (4, 10, "private")]


def test_full_walk_back_to_pre_mt(conn):
    _tasks_with_original_3a1b(conn)
    _run(conn, MIG4.upgrade)
    _run(conn, MIG4.downgrade)
    _run(conn, MIG3.downgrade)
    assert _cols(conn) == {"id", "target"}


# --- Task model: absent task_acl row == (tenant_id=None, visibility='private') ---------------


@pytest.fixture
def session():
    from sqlalchemy.orm import Session

    from lib.cuckoo.core.database import Base

    eng = sa.create_engine("sqlite://")
    Base.metadata.create_all(eng)
    with Session(eng) as s:
        yield s


def _task(target):
    from lib.cuckoo.core.data.task import Task

    t = Task(target)
    t.category = "url"
    return t


def test_tasks_table_has_no_tenancy_columns():
    from lib.cuckoo.core.data.task import Task

    assert not {"tenant_id", "visibility"} & set(Task.__table__.columns.keys())


def test_to_dict_has_no_tenancy_keys(session):
    t = _task("x")
    t.tenant_id = 5
    t.visibility = "tenant"
    session.add(t)
    session.commit()
    assert not {"tenant_id", "visibility"} & set(t.to_dict())


def test_writing_defaults_creates_no_acl_row(session):
    from lib.cuckoo.core.data.task import TaskAcl

    t = _task("x")
    t.tenant_id = None
    t.visibility = "private"
    session.add(t)
    session.commit()
    assert t.acl is None
    assert (t.tenant_id, t.visibility) == (None, "private")
    assert session.scalar(sa.select(sa.func.count()).select_from(TaskAcl)) == 0


def test_non_default_creates_row_and_roundtrips(session):
    from lib.cuckoo.core.data.task import Task

    t = _task("x")
    t.tenant_id = 7
    t.visibility = "tenant"
    session.add(t)
    session.commit()
    tid = t.id
    session.expunge_all()

    loaded = session.get(Task, tid)
    assert (loaded.tenant_id, loaded.visibility) == (7, "tenant")


def test_sql_filters_treat_absent_row_as_private(session):
    from lib.cuckoo.core.data.task import Task

    plain, pub, ten = _task("plain"), _task("pub"), _task("ten")
    pub.visibility = "public"
    ten.tenant_id, ten.visibility = 3, "tenant"
    session.add_all([plain, pub, ten])
    session.commit()

    def targets(cond):
        return sorted(session.scalars(sa.select(Task.target).where(cond)))

    assert targets(Task.visibility == "private") == ["plain"]
    assert targets(Task.visibility == "public") == ["pub"]
    assert targets(sa.and_(Task.tenant_id == 3, Task.visibility == "tenant")) == ["ten"]
    assert targets(Task.tenant_id.is_(None)) == ["plain", "pub"]


def test_acl_is_loaded_with_task_for_detached_use(session):
    """Callers read task.visibility after the session is gone (view_task etc.)."""
    from lib.cuckoo.core.data.task import Task

    t = _task("x")
    t.visibility = "public"
    session.add(t)
    session.commit()
    tid = t.id
    session.expunge_all()

    loaded = session.get(Task, tid)
    session.expunge(loaded)
    assert loaded.visibility == "public"  # would raise DetachedInstanceError if lazy-loaded


def test_deleting_task_deletes_acl(session):
    from lib.cuckoo.core.data.task import TaskAcl

    t = _task("x")
    t.tenant_id = 1
    session.add(t)
    session.commit()
    session.delete(t)
    session.commit()
    assert session.scalar(sa.select(sa.func.count()).select_from(TaskAcl)) == 0


def test_model_and_migration_agree_on_acl_index():
    """Fresh installs build the schema via create_all() (skips Alembic); migrated installs via
    4b2c. Both must produce the same tenant_id index name, or the two provisioning paths diverge."""
    from lib.cuckoo.core.data.task import TaskAcl

    names = {ix.name for ix in TaskAcl.__table__.indexes}
    assert MIG4._ACL_INDEX in names
