# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""2.2-cape

Revision ID: c554ed5f32a0
Revises: 2996ec5ea15c
Create Date: 2020-11-19 15:14:27.973963

"""

# revision identifiers, used by Alembic.
revision = 'c554ed5f32a0'
down_revision = '2996ec5ea15c'

import sys
import os.path
import sqlalchemy as sa
from datetime import datetime


try:
    from alembic import op
except ImportError:
    print("Unable to import alembic (install with `pip3 install alembic`)")
    sys.exit()

curdir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(curdir, "..", "..", ".."))

import lib.cuckoo.core.database as db


def upgrade():
    op.add_column("tasks", sa.Column("cape", sa.String(length=2048), nullable=True))
    op.add_column("tasks", sa.Column("route", sa.String(length=128), nullable=True))
    op.add_column("tasks", sa.Column("tags_tasks", sa.String(length=256), nullable=True))


def downgrade():
    op.drop_column("tasks", "cape")
    op.drop_column("tasks", "route")
    op.drop_column("tasks", "tags_tasks")
