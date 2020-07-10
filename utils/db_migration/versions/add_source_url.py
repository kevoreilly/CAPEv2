# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""add_source_url

Revision ID: 2996ec5ea15c
Revises: 7331c4d994fd
Create Date: 2020-06-24 08:41:33.661473

"""

# revision identifiers, used by Alembic.
revision = "2996ec5ea15c"
down_revision = "7331c4d994fd"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column("samples", sa.Column("source_url", sa.String(length=2000), nullable=True))


def downgrade():
    op.drop_column("samples", "source_url")
