"""drop inline tenant_id + visibility columns from tasks if present

Idempotently removes inline tasks.tenant_id and tasks.visibility columns on deployments
that previously applied 3a1b_tenant_visibility before multi-tenancy moved out of core.

Revision ID: 4c2d_drop_inline_tenancy
Revises: 3a1b_tenant_visibility
Create Date: 2026-10-09
"""
import sqlalchemy as sa
from alembic import op

revision = "4c2d_drop_inline_tenancy"
down_revision = "3a1b_tenant_visibility"
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
        op.drop_column("tasks", "visibility")
    if "tenant_id" in columns:
        op.drop_column("tasks", "tenant_id")


def downgrade():
    pass
