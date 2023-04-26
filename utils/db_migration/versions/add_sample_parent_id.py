# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# https://www.pythoncentral.io/migrate-sqlalchemy-databases-alembic/

"""add_sample_parent

Revision ID: 36926b59dfbb
Revises: 3c8bf4133b44
Create Date: 2019-05-03 08:14:52.075368

"""

# revision identifiers, used by Alembic.
revision = "36926b59dfbb"
down_revision = "3c8bf4133b44"

import os.path
import sys

import sqlalchemy as sa

try:
    from alembic import op
except ImportError:
    print("Unable to import alembic (install with `poetry run pip install alembic`)")
    sys.exit()

curdir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(curdir, "..", "..", ".."))


def upgrade():
    op.add_column("samples", sa.Column("parent", sa.Integer, nullable=True))


def downgrade():
    op.drop_column("samples", "parent")
