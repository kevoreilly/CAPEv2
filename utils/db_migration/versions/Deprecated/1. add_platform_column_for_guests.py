# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""add_platform_column_for_guests

Revision ID: 3a1c6c03844b
Revises: None
Create Date: 2024-03-07 16:11:55.712298

"""

# revision identifiers, used by Alembic.
revision = "3a1c6c03844b"
down_revision = None

import sqlalchemy as sa
from alembic import op


def upgrade():
    # Add the platform column to the guests table with a default value of 'windows'
    op.add_column("guests", sa.Column("platform", sa.String(length=50), nullable=True))

    # Update existing rows with the default value
    op.execute("UPDATE guests SET platform = 'windows' WHERE platform IS NULL")


def downgrade():
    # Remove the platform column from the guests table
    op.drop_column("guests", "platform")
