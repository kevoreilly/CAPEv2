"""add tenant_id + visibility to tasks -- RETIRED, now a no-op

RETIRED: this revision originally added tenant_id/visibility columns to `tasks`, which
forced a full-table rewrite on every install, including single-tenant ones. Tenancy now
lives in the `task_acl` side table (revision 4b2c_task_acl). The revision id must stay in
the chain because deployed databases already record it in alembic_version, so upgrade()
is a no-op; 4b2c moves the data for installs that ran the original body.

Original description follows.

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
    """No-op. See the RETIRED note above; 4b2c_task_acl handles installs that ran the original."""


def downgrade():
    """Drop the original columns if present (they exist only after 4b2c's downgrade, or on an
    install that ran the original body and is being walked back past this revision)."""
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = {c["name"] for c in insp.get_columns("tasks")}
    indexes = {i["name"] for i in insp.get_indexes("tasks")}
    if not ({"tenant_id", "visibility"} & cols):
        return
    with op.batch_alter_table("tasks") as batch:
        if "ix_tasks_tenant_id" in indexes:
            batch.drop_index("ix_tasks_tenant_id")
        for col in ("visibility", "tenant_id"):
            if col in cols:
                batch.drop_column(col)
