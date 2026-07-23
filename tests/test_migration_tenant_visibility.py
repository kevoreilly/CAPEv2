"""utils/db_migration/versions/3_add_tenant_visibility.py must render on MySQL/MariaDB, not just
Postgres. MySQL rebuilds a column via MODIFY COLUMN, which Alembic cannot render without the column
type -- so `alter_column(..., nullable=False, server_default=...)` MUST pass existing_type, else
`alembic upgrade` aborts mid-migration on a MySQL-backed CAPE (the add_columns auto-commit first,
leaving the DB wedged half-applied). Adversarial-review HIGH. Postgres renders SET NOT NULL/DEFAULT
independently and was always fine.
"""
import importlib.util
import os

import pytest


def _load_migration():
    path = os.path.join(
        os.path.dirname(__file__), "..", "utils", "db_migration", "versions", "3_add_tenant_visibility.py"
    )
    spec = importlib.util.spec_from_file_location("mig_3_tenant_vis", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _mysql_op():
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy.dialects import mysql

    ctx = MigrationContext.configure(dialect=mysql.dialect(), opts={"as_sql": True})
    return Operations(ctx)


def test_migration3_upgrade_renders_on_mysql(monkeypatch):
    """The REAL upgrade() renders under a MySQL offline op without raising (existing_type present)."""
    mig = _load_migration()
    monkeypatch.setattr(mig, "op", _mysql_op(), raising=False)
    mig.upgrade()  # RED (alembic CommandError) if existing_type is omitted; GREEN with it


def test_alter_column_existing_type_is_load_bearing_on_mysql():
    """Regression guard: the bare alter_column (no existing_type) DOES raise on MySQL, so the
    existing_type in the migration is load-bearing, not cosmetic. With it, MySQL renders MODIFY."""
    import sqlalchemy as sa

    with pytest.raises(Exception):
        _mysql_op().alter_column("tasks", "visibility", nullable=False, server_default="private")

    # with existing_type it renders cleanly (no raise)
    _mysql_op().alter_column(
        "tasks", "visibility", existing_type=sa.String(length=16), nullable=False, server_default="private"
    )


def test_task_model_declares_tenant_id_index():
    """Fresh installs build the schema from the ORM (Base.metadata.create_all(), which skips Alembic),
    so the Task model MUST declare the tenant_id index that migration 3 creates -- else fresh MT
    installs seq-scan the tenant-scoped list_tasks/count_* filters. Guards the two provisioning paths
    (create_all vs alembic) from diverging."""
    from lib.cuckoo.core.data.task import Task

    col = Task.__table__.c.tenant_id
    index_cols = {tuple(c.name for c in ix.columns) for ix in Task.__table__.indexes}
    assert col.index or ("tenant_id",) in index_cols, f"tenant_id index missing on the model; indexes={index_cols}"
