"""add tenant_id + visibility to tasks

Multi-tenant identity & job-visibility foundation (spec #1). Adds the
per-task tenant owner and the 3-level visibility (public/tenant/private).

Back-compat (spec §9/§11): EXISTING rows are backfilled to visibility='public'
with tenant_id NULL so legacy jobs stay visible exactly as they are today if the
feature is later enabled. NEW rows that don't set it explicitly fall back to the
'private' server_default (fail-safe; the app always sets visibility via
submission_scope). With multitenancy disabled the predicate is bypassed
entirely, so the stored value is moot until the feature is turned on.

Revision ID: 3a1b_tenant_visibility
Revises: 2b3c4d5e6f7g
Create Date: 2026-06-05
"""
import sqlalchemy as sa
from alembic import op

revision = "3a1b_tenant_visibility"
down_revision = "2b3c4d5e6f7g"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tasks", sa.Column("tenant_id", sa.Integer(), nullable=True))
    # Add nullable first so existing rows can be backfilled to 'public' (legacy
    # jobs stay visible per spec §11), then enforce NOT NULL with a fail-safe
    # 'private' default for any NEW row that omits it.
    op.add_column("tasks", sa.Column("visibility", sa.String(length=16), nullable=True))
    op.execute("UPDATE tasks SET visibility = 'public' WHERE visibility IS NULL")
    op.alter_column("tasks", "visibility", nullable=False, server_default="private")
    op.create_index("ix_tasks_tenant_id", "tasks", ["tenant_id"])


def downgrade():
    op.drop_index("ix_tasks_tenant_id", table_name="tasks")
    op.drop_column("tasks", "visibility")
    op.drop_column("tasks", "tenant_id")
