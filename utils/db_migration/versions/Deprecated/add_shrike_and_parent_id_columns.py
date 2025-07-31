# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Add shrike and Parent ID Columns

Revision ID: f111620bb8
Revises: 4b09c454108c
Create Date: 2015-03-29 08:43:11.468664

"""

# revision identifiers, used by Alembic.
revision = "f111620bb8"
down_revision = "4b09c454108c"

import os.path
import sys

import sqlalchemy as sa

try:
    pass
except ImportError:
    print("Unable to import dateutil.parser", end=" ")
    print("(install with `poetry run pip install python-dateutil`)")
    sys.exit()

try:
    from alembic import op
except ImportError:
    print("Unable to import alembic (install with `poetry run pip install alembic`)")
    sys.exit()

curdir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(curdir, "..", "..", ".."))


def upgrade():
    op.add_column("tasks", sa.Column("shrike_url", sa.String(length=4096), nullable=True))
    op.add_column("tasks", sa.Column("shrike_refer", sa.String(length=4096), nullable=True))
    op.add_column("tasks", sa.Column("shrike_msg", sa.String(length=4096), nullable=True))
    op.add_column("tasks", sa.Column("shrike_sid", sa.Integer(), nullable=True))
    op.add_column("tasks", sa.Column("parent_id", sa.Integer(), nullable=True))


def downgrade():
    op.drop_column("tasks", "shrike_url")
    op.drop_column("tasks", "shrike_refer")
    op.drop_column("tasks", "shrike_msg")
    op.drop_column("tasks", "shrike_sid")
    op.drop_column("tasks", "parent_sid")
