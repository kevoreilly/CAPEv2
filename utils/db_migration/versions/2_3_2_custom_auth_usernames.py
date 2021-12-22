# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""2_3_2_custom_auth_usernames

Revision ID: 6dc79a3ee6e4
Revises: 703266a6bbc5
Create Date: 2021-06-17 08:01:32.057197

"""

# revision identifiers, used by Alembic.
revision = "6dc79a3ee6e4"
down_revision = "703266a6bbc5"

import sqlalchemy as sa
from alembic import op


def upgrade():
    op.add_column("tasks", sa.Column("username", sa.String(length=256), nullable=True))


def downgrade():
    op.drop_column("tasks", "username")
