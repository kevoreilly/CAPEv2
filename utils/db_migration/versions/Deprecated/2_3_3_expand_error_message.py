# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""2.3.3 expand error message

Revision ID: 02af0b0ec686
Revises: 8537286ff4d5
Create Date: 2022-07-28 18:46:00.169029

"""

# revision identifiers, used by Alembic.
revision = "02af0b0ec686"
down_revision = "8537286ff4d5"

import sqlalchemy as sa
from alembic import op


def upgrade():
    op.alter_column("errors", "message", existing_type=sa.String(length=255), type_=sa.String(length=1024), existing_nullable=True)


def downgrade():
    op.alter_column("errors", "message", existing_type=sa.String(length=1024), type_=sa.String(length=255), existing_nullable=True)
