"""drop inline tenant_id + visibility columns from tasks if present

Idempotently removes inline tasks.tenant_id and tasks.visibility columns on deployments
that previously applied 3a1b_tenant_visibility before multi-tenancy moved out of core.

Revision ID: 4c2d_drop_inline_tenancy
Revises: 4a6c2b_machine_attributes
Create Date: 2026-10-09
"""
import sqlalchemy as sa
from alembic import op

revision = "4c2d_drop_inline_tenancy"
down_revision = "4a6c2b_machine_attributes"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    indexes = {ix["name"] for ix in insp.get_indexes("tasks")}
    if "ix_tasks_tenant_id" in indexes:
        op.drop_index("ix_tasks_tenant_id", table_name="tasks")
    columns = {col["name"] for col in insp.get_columns("tasks")}
    if "visibility" in columns:
        _carry_public_visibility(bind, insp, columns)
        op.drop_column("tasks", "visibility")
    if "tenant_id" in columns:
        op.drop_column("tasks", "tenant_id")


def _carry_public_visibility(bind, insp, columns=()):
    """Preserve explicitly public tasks in lib.tenancy's task_acl before the column goes.

    Tasks with no task_acl row resolve to owner-only, so without this every task an operator
    made public silently turns private. Only 'public' is carried: legacy tasks.tenant_id values
    are ids in the old users_tenant table, not lib.tenancy tenant ids, so copying them could hand
    a task to an unrelated group. 'tenant' and 'private' tasks keep the owner-only default.
    On single-tenant installs where multitenancy was never used (all tenant_id values NULL and
    [multitenancy] enabled = no), skip creating task_acl so pre-MT tasks are not locked as public.
    """
    mt_enabled = False
    try:
        from lib.cuckoo.common.config import Config

        mt_enabled = bool(getattr(Config(), "multitenancy", {}).get("enabled", False))
    except Exception:
        mt_enabled = False
    has_tenant_rows = (
        bind.execute(sa.text("SELECT 1 FROM tasks WHERE tenant_id IS NOT NULL LIMIT 1")).first() is not None
        if "tenant_id" in columns
        else False
    )
    if not mt_enabled and not has_tenant_rows:
        return
    has_public = bind.execute(sa.text("SELECT 1 FROM tasks WHERE visibility = 'public' LIMIT 1")).first()
    if not has_public:
        return
    if "task_acl" not in insp.get_table_names():
        op.create_table(
            "task_acl",
            sa.Column("task_id", sa.Integer(), primary_key=True, autoincrement=False),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("tenant_id", sa.Integer(), nullable=True),
            sa.Column("visibility", sa.String(16), nullable=False, server_default="private"),
            sa.Column("visibility_seq", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("external_job_id", sa.String(128), nullable=True),
        )
        op.create_index("ix_task_acl_user_id", "task_acl", ["user_id"])
        op.create_index("ix_task_acl_external_job_id", "task_acl", ["external_job_id"])
        op.create_index("ix_task_acl_tenant_vis", "task_acl", ["tenant_id", "visibility"])
    bind.execute(
        sa.text(
            "INSERT INTO task_acl (task_id, user_id, tenant_id, visibility, visibility_seq) "
            "SELECT t.id, t.user_id, NULL, 'public', 1 FROM tasks t "
            "WHERE t.visibility = 'public' AND NOT EXISTS (SELECT 1 FROM task_acl a WHERE a.task_id = t.id)"
        )
    )


def downgrade():
    pass
