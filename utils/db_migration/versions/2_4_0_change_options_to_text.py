# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""2_4_0_change_options_to_text

Revision ID: a8441ab0fd0f
Revises: d6aa5d949b70
Create Date: 2023-02-24 16:59:10.667367

"""

# revision identifiers, used by Alembic.
revision = "a8441ab0fd0f"
down_revision = "d6aa5d949b70"

import sqlalchemy as sa
from alembic import op


def upgrade():
    op.alter_column("tasks", "options", existing_type=sa.String(length=1024), type_=sa.Text(), existing_nullable=True)


def downgrade():
    op.alter_column("tasks", "options", existing_type=sa.Text(), type_=sa.String(length=1024), existing_nullable=True)
