# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""dist_1.3

Revision ID: 83fd58842164
Revises: b0fa23c3c9c0
Create Date: 2024-02-29 08:04:50.292044

"""

# revision identifiers, used by Alembic.
revision = "83fd58842164"
down_revision = "b0fa23c3c9c0"

import sqlalchemy as sa
from alembic import op


def upgrade():
    op.add_column("task", sa.Column("tlp", sa.String(length=6), nullable=True))


def downgrade():
    op.drop_column("task", "tlp")
