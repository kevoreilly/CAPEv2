# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""dist_1.1

Revision ID: 431b7f0b3240
Revises: None
Create Date: 2021-03-08 13:39:01.310802

"""

# revision identifiers, used by Alembic.
revision = "431b7f0b3240"
down_revision = None

import sqlalchemy as sa
from alembic import op


def upgrade():
    op.add_column("task", sa.Column("route", sa.String(length=128), nullable=True))


def downgrade():
    op.drop_column("task", "route")
