"""no-op placeholder for historical revision 3a1b_tenant_visibility

Preserved as a no-op so existing deployments with 3a1b_tenant_visibility recorded in
alembic_version maintain a valid revision graph after multi-tenancy was moved out of core.

Revision ID: 3a1b_tenant_visibility
Revises: 2b3c4d5e6f7g
Create Date: 2026-06-05
"""

revision = "3a1b_tenant_visibility"
down_revision = "2b3c4d5e6f7g"
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
