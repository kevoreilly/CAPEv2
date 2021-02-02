# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""2.3_task2user_id

Revision ID: 6ab863a3b510
Revises: c554ed5f32a0
Create Date: 2021-02-02 07:28:09.576652

"""

# revision identifiers, used by Alembic.
revision = '6ab863a3b510'
down_revision = 'c554ed5f32a0'


import sys
from datetime import datetime


from alembic import op
import sqlalchemy as sa


try:
    from alembic import op
except ImportError:
    print("Unable to import alembic (install with `pip3 install alembic`)")
    sys.exit()

def upgrade():
    op.add_column("tasks", sa.Column("user_id", sa.Integer, nullable=True))

def downgrade():
    op.drop_column("tasks", "user_id")
