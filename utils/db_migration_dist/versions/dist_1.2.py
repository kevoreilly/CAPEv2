# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""dist_1.2

Revision ID: b0fa23c3c9c0
Revises: None
Create Date: 2021-06-10 13:39:01.310802

"""

# revision identifiers, used by Alembic.
revision = "b0fa23c3c9c0"
down_revision = "431b7f0b3240"

import sqlalchemy as sa
from alembic import op


def upgrade():
    op.add_column("node", sa.Column("apikey", sa.String(length=255), nullable=True))
    op.drop_column("node", "ht_user")
    op.drop_column("node", "ht_pass")


def downgrade():
    op.drop_column("node", "apikey")
    op.add_column("node", sa.Column("ht_user", sa.String(length=255), nullable=True))
    op.add_column("node", sa.Column("ht_pass", sa.String(length=255), nullable=True))
