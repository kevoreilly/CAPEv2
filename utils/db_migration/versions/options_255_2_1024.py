# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""options_255_to_1014

Revision ID: 30d0230de7cd
Revises: e4954d358c80
Create Date: 2019-10-11 11:00:31.364356

"""

# revision identifiers, used by Alembic.
revision = "30d0230de7cd"
down_revision = "e4954d358c80"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column("tasks", "options", existing_type=sa.String(length=255), type_=sa.String(length=1024), existing_nullable=True)


def downgrade():
    op.alter_column("tasks", "options", existing_type=sa.String(length=1024), type_=sa.String(length=255), existing_nullable=True)
