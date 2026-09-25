# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Add attributes JSON column to machines

Revision ID: 4a6c2b_machine_attributes
Revises: 3a1b_tenant_visibility
Create Date: 2026-09-01

Adds a generic JSONB column to the machines table to  store extra per-machine data - whether
 generic (e.g. last shutdown date) or machinery-specific (e.g. VNC connection details)
semi-structured data (e.g. provider metadata, admin notes, runtime state) - without
 requiring ALTER TABLE for each new field.

On Postgres the column is stored as real JSONB; on SQLite/MySQL it falls
back to plain JSON.  Matches the Machine model which declares it with
JSON().with_variant(JSONB(), "postgresql") so fresh installs on Postgres
get the optimal type automatically via Base.metadata.create_all().
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision = "4a6c2b_machine_attributes"
down_revision = "3a1b_tenant_visibility"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Real JSONB on Postgres (matches the Machine model), plain JSON elsewhere.
    # Alembic compiles with_variant against the connection dialect at runtime.
    op.add_column(
        "machines",
        sa.Column(
            "attributes",
            sa.JSON().with_variant(JSONB(), "postgresql"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("machines", "attributes")
