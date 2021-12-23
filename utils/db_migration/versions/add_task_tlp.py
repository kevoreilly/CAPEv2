# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""add_task_tlp

Revision ID: 7331c4d994fd
Revises: 30d0230de7cd
Create Date: 2020-04-10 12:17:18.530901

"""
from __future__ import absolute_import
from __future__ import print_function

# revision identifiers, used by Alembic.
revision = "7331c4d994fd"
down_revision = "30d0230de7cd"

import sqlalchemy as sa
import sys

try:
    from alembic import op
except ImportError:
    print("Unable to import alembic (install with `pip3 install alembic`)")
    sys.exit()


def upgrade():
    op.add_column("tasks", sa.Column("tlp", sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column("tasks", "tlp")
