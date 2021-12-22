# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""add arch to machine config

Revision ID: 8537286ff4d5
Revises: 6dc79a3ee6e4
Create Date: 2021-11-04 13:41:08.438214

"""

# revision identifiers, used by Alembic.
revision = "8537286ff4d5"
down_revision = "6dc79a3ee6e4"

import sqlalchemy as sa
from alembic import op


def upgrade():
    op.add_column("machines", sa.Column("arch", sa.String(length=255), nullable=False, server_default="lorem ipsum"))
    op.alter_column("machines", "arch", server_default=None)


def downgrade():
    op.drop_column("machines", "arch")
