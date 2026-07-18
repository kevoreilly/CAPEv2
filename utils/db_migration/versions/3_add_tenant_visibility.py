"""add tenant_id + visibility to tasks

Multi-tenant identity & job-visibility foundation (spec #1). Adds the
per-task tenant owner and the 3-level visibility (public/tenant/private).

Back-compat: EXISTING rows are backfilled FAIL-CLOSED to visibility='private' with
tenant_id NULL — matching the mongo side (mongo_backfill_tenant.py stamps orphans
private). In `locked` mode a 'public' backfill would make every historical task
cross-tenant readable (public = visible to all viewers regardless of tenant), defeating
isolation, and would disagree with the mongo store on the same rows. Private = owner-only
until an operator runs a backfill to assign tenancy/visibility. NEW rows that don't set it
explicitly also fall back to the 'private' server_default (the app sets visibility via
submission_scope). With multitenancy disabled the predicate is bypassed entirely, so the
stored value is moot until the feature is turned on.

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
    # Add nullable first so existing rows can be backfilled, then enforce NOT NULL. Backfill
    # FAIL-CLOSED to 'private' (owner-only) -- NOT 'public' (visible to every tenant) -- so enabling
    # locked MT can't retroactively expose historical tasks cross-tenant, and the SQL store agrees
    # with the mongo backfill (also private). Operators re-stamp tenancy/visibility via a backfill.
    op.add_column("tasks", sa.Column("visibility", sa.String(length=16), nullable=True))
    op.execute("UPDATE tasks SET visibility = 'private' WHERE visibility IS NULL")
    # existing_type is REQUIRED for MySQL/MariaDB: they rebuild the column via MODIFY COLUMN, which
    # Alembic cannot render without the type (Postgres renders SET NOT NULL/DEFAULT independently and
    # doesn't need it). Omitting it aborts `alembic upgrade` mid-migration on a MySQL-backed CAPE
    # (the add_columns auto-commit first -> wedged half-applied). Matches sibling "2. Database cleanup.py".
    op.alter_column("tasks", "visibility", existing_type=sa.String(length=16), nullable=False, server_default="private")
    op.create_index("ix_tasks_tenant_id", "tasks", ["tenant_id"])


def downgrade():
    op.drop_index("ix_tasks_tenant_id", table_name="tasks")
    op.drop_column("tasks", "visibility")
    op.drop_column("tasks", "tenant_id")
