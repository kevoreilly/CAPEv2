"""utils/db_migration 4c2d_drop_inline_tenancy must not silently privatise public tasks."""

import importlib.util
import pathlib

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

from lib.tenancy.acl import TaskAcl, resolve_task_scope

MIGRATION = pathlib.Path(__file__).resolve().parents[1] / "utils/db_migration/versions/6_drop_inline_tenancy_columns.py"


def _load_migration():
    spec = importlib.util.spec_from_file_location("drop_inline_tenancy", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_public_tasks_stay_public_and_legacy_tenant_ids_are_not_carried(monkeypatch):
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE tasks (id INTEGER PRIMARY KEY, user_id INTEGER, tenant_id INTEGER, visibility VARCHAR(16) NOT NULL DEFAULT 'private')"))
        conn.execute(sa.text("CREATE INDEX ix_tasks_tenant_id ON tasks (tenant_id)"))
        conn.execute(sa.text("INSERT INTO tasks VALUES (1, 7, 3, 'public'), (2, 7, 3, 'tenant'), (3, 8, NULL, 'private')"))

        mod = _load_migration()
        monkeypatch.setattr(mod, "op", Operations(MigrationContext.configure(conn)))
        mod.upgrade()

        assert "visibility" not in {c["name"] for c in sa.inspect(conn).get_columns("tasks")}
        rows = conn.execute(sa.text("SELECT task_id, user_id, tenant_id, visibility FROM task_acl")).all()
        assert rows == [(1, 7, None, "public")]

    with sa.orm.Session(engine) as session:
        assert session.get(TaskAcl, 1).visibility == "public"
        assert resolve_task_scope(session, 2, fallback_user_id=7).visibility == "private"
