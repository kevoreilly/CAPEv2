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
from __future__ import absolute_import
from __future__ import print_function

revision = "36926b59dfbb"
down_revision = "3c8bf4133b44"

from alembic import op
import sqlalchemy as sa

import os.path
import sqlalchemy as sa
import sys
from datetime import datetime

try:
    from dateutil.parser import parse
except ImportError:
    print("Unable to import dateutil.parser", end=" ")
    print("(install with `pip3 install python-dateutil`)")
    sys.exit()

try:
    from alembic import op
except ImportError:
    print("Unable to import alembic (install with `pip3 install alembic`)")
    sys.exit()

curdir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(curdir, "..", "..", ".."))

import lib.cuckoo.core.database as db


def upgrade():
    op.add_column("samples", sa.Column("parent", sa.Integer, nullable=True))


def downgrade():
    op.drop_column("samples", "parent")
