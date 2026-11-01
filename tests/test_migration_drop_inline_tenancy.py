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


def test_upgrade_skips_creating_task_acl_when_no_public_tasks_exist(monkeypatch):
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE tasks (id INTEGER PRIMARY KEY, user_id INTEGER, tenant_id INTEGER, visibility VARCHAR(16) NOT NULL DEFAULT 'private')"
            )
        )
        conn.execute(sa.text("INSERT INTO tasks VALUES (1, 7, 3, 'tenant'), (2, 8, NULL, 'private')"))

        mod = _load_migration()
        monkeypatch.setattr(mod, "op", Operations(MigrationContext.configure(conn)))
        mod.upgrade()

        assert "visibility" not in {c["name"] for c in sa.inspect(conn).get_columns("tasks")}
        assert "task_acl" not in sa.inspect(conn).get_table_names()


def test_upgrade_skips_public_carry_when_multitenancy_was_never_used(monkeypatch):
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE tasks (id INTEGER PRIMARY KEY, user_id INTEGER, tenant_id INTEGER, visibility VARCHAR(16) NOT NULL DEFAULT 'private')"
            )
        )
        conn.execute(sa.text("INSERT INTO tasks VALUES (1, 0, NULL, 'public'), (2, 7, NULL, 'public')"))

        mod = _load_migration()
        monkeypatch.setattr(mod, "op", Operations(MigrationContext.configure(conn)))
        mod.upgrade()

        assert "visibility" not in {c["name"] for c in sa.inspect(conn).get_columns("tasks")}
        assert "task_acl" not in sa.inspect(conn).get_table_names()


def test_django_users_migrations_0004_and_0005_are_idempotent_on_existing_tables():
    from types import SimpleNamespace

    mig_dir = pathlib.Path(__file__).resolve().parents[1] / "web/users/migrations"
    spec4 = importlib.util.spec_from_file_location("m0004", mig_dir / "0004_tenant_userprofile_is_tenant_admin_and_more.py")
    mod4 = importlib.util.module_from_spec(spec4)
    spec4.loader.exec_module(mod4)

    spec5 = importlib.util.spec_from_file_location("m0005", mig_dir / "0005_remove_inline_tenancy.py")
    mod5 = importlib.util.module_from_spec(spec5)
    spec5.loader.exec_module(mod5)

    created, added, removed = [], [], []

    class FakeIntrospection:
        def table_names(self, cursor):
            return ["users_tenant", "users_userprofile"]

        def get_table_description(self, cursor, table_name):
            # Simulates a pruned DB that already has users_tenant + tenant_id and already dropped is_tenant_admin.
            return [SimpleNamespace(name="id"), SimpleNamespace(name="tenant_id")]

    class FakeCursor:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    schema_editor = SimpleNamespace(
        connection=SimpleNamespace(alias="default", cursor=lambda: FakeCursor(), introspection=FakeIntrospection()),
        create_model=lambda m: created.append(m),
        add_field=lambda m, f: added.append(f.column),
        remove_field=lambda m, f: removed.append(f.column),
    )

    def _get_field(name):
        return SimpleNamespace(column="tenant_id" if name == "tenant" else name)

    fake_models = {
        ("users", "Tenant"): SimpleNamespace(
            _meta=SimpleNamespace(
                app_label="users", model_name="tenant", db_table="users_tenant", can_migrate=lambda conn: True
            )
        ),
        ("users", "userprofile"): SimpleNamespace(
            _meta=SimpleNamespace(
                app_label="users",
                model_name="userprofile",
                db_table="users_userprofile",
                get_field=_get_field,
                can_migrate=lambda conn: True,
            )
        ),
    }
    state = SimpleNamespace(apps=SimpleNamespace(get_model=lambda app, name: fake_models[(app, name)]))

    for op in mod4.Migration.operations:
        op.database_forwards("users", schema_editor, state, state)
    assert created == []
    assert added == ["is_tenant_admin"]  # only missing column added; existing users_tenant + tenant_id skipped

    mod5.Migration.operations[0].database_forwards("users", schema_editor, state, state)
    assert removed == []  # absent column is skipped cleanly without OperationalError
