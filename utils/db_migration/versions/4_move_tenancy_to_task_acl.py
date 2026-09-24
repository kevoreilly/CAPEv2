"""move task tenancy off `tasks` into the `task_acl` side table

Revision 3a1b_tenant_visibility put tenant_id + visibility directly on `tasks`, which
cost every install (including the single-tenant majority) a full-table rewrite, changed
Task.to_dict()'s API shape, and tied the core task model to multitenancy. 3a1b is now a
no-op; this revision finishes the move for any install that already applied the original.

Handles every state an install can be in when it reaches this revision:
  * never had the columns (was on 2b3c4d5e6f7g, so 3a1b ran as the no-op): create the
    empty task_acl table, nothing else. O(1), no rewrite of tasks.
  * ran the ORIGINAL 3a1b (columns present): copy every row carrying non-default tenancy
    into task_acl, then drop the columns and index. Rows at the default
    (tenant_id NULL, visibility 'private') are NOT copied: an absent task_acl row means
    exactly that, so the copy is lossless and task_acl only holds meaningful rows.
  * fresh install: never reaches here (create_all() builds task_acl from the model and
    the DB is stamped at head).

Both migrated populations report alembic_version = 3a1b_tenant_visibility on arrival, so
the state is detected by inspecting the live schema, not from the version table.
`DROP COLUMN IF EXISTS` is not portable across PostgreSQL / MySQL / MariaDB / SQLite.

Revision ID: 4b2c_task_acl
Revises: 3a1b_tenant_visibility
Create Date: 2026-09-24
"""
import sqlalchemy as sa
from alembic import op

revision = "4b2c_task_acl"
down_revision = "3a1b_tenant_visibility"
branch_labels = None
depends_on = None

_TENANCY_COLUMNS = ("tenant_id", "visibility")
_OLD_INDEX = "ix_tasks_tenant_id"
_ACL_INDEX = "ix_task_acl_tenant_id"
_STAGE = "_task_acl_migration_stage"


def _inspector():
    return sa.inspect(op.get_bind())


def _tasks_columns():
    return {c["name"] for c in _inspector().get_columns("tasks")}


def _tasks_indexes():
    return {i["name"] for i in _inspector().get_indexes("tasks")}


def _create_task_acl():
    if _inspector().has_table("task_acl"):
        return
    op.create_table(
        "task_acl",
        sa.Column("task_id", sa.Integer(), sa.ForeignKey("tasks.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("visibility", sa.String(length=16), nullable=False, server_default="private"),
    )
    op.create_index(_ACL_INDEX, "task_acl", ["tenant_id"])


def upgrade():
    cols = _tasks_columns()
    present = [c for c in _TENANCY_COLUMNS if c in cols]
    if not present:
        _create_task_acl()  # never had the columns: nothing to move
        return

    # Stage the rows in a table WITHOUT a foreign key before touching `tasks`. On SQLite,
    # batch mode recreates `tasks` (DROP TABLE + rename); with foreign_keys=ON that DROP runs
    # an implicit DELETE which would cascade into task_acl and wipe the rows just copied.
    # PRAGMA foreign_keys cannot be toggled inside the migration transaction, so order the
    # operations instead: stage -> drop columns -> create task_acl -> fill from stage.
    copy = set(_TENANCY_COLUMNS) <= cols
    if copy:
        op.create_table(
            _STAGE,
            sa.Column("task_id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), nullable=True),
            sa.Column("visibility", sa.String(length=16), nullable=False),
        )
        op.execute(
            f"INSERT INTO {_STAGE} (task_id, tenant_id, visibility) "
            "SELECT id, tenant_id, visibility FROM tasks "
            "WHERE tenant_id IS NOT NULL OR visibility <> 'private'"
        )

    drop_index = _OLD_INDEX in _tasks_indexes()
    # batch mode: SQLite cannot DROP COLUMN in place; on other backends it is a pass-through.
    with op.batch_alter_table("tasks") as batch:
        if drop_index:
            batch.drop_index(_OLD_INDEX)
        for col in present:
            batch.drop_column(col)

    _create_task_acl()
    if copy:
        op.execute(
            f"INSERT INTO task_acl (task_id, tenant_id, visibility) SELECT task_id, tenant_id, visibility FROM {_STAGE}"
        )
        op.drop_table(_STAGE)


def downgrade():
    """Restore the original 3a1b schema (columns on tasks) and copy the ACL back."""
    cols = _tasks_columns()
    with op.batch_alter_table("tasks") as batch:
        if "tenant_id" not in cols:
            batch.add_column(sa.Column("tenant_id", sa.Integer(), nullable=True))
        if "visibility" not in cols:
            batch.add_column(sa.Column("visibility", sa.String(length=16), nullable=False, server_default="private"))
    if _OLD_INDEX not in _tasks_indexes():
        op.create_index(_OLD_INDEX, "tasks", ["tenant_id"])

    if _inspector().has_table("task_acl"):
        op.execute(
            "UPDATE tasks SET "
            "tenant_id = (SELECT a.tenant_id FROM task_acl a WHERE a.task_id = tasks.id), "
            "visibility = COALESCE((SELECT a.visibility FROM task_acl a WHERE a.task_id = tasks.id), 'private') "
            "WHERE id IN (SELECT task_id FROM task_acl)"
        )
        op.drop_index(_ACL_INDEX, table_name="task_acl")
        op.drop_table("task_acl")
