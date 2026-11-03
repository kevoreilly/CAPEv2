# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Add generic attributes JSON column to machines and tasks

Revision ID: 4a6c2b_machine_attributes
Revises: errors_task_id_cascade
Create Date: 2026-04-06 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "4a6c2b_machine_attributes"
down_revision = "errors_task_id_cascade"


def _has_column(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = [col["name"] for col in inspector.get_columns(table_name)]
    return column_name in columns


def upgrade():
    col_type = sa.JSON().with_variant(JSONB(), "postgresql")
    for table_name in ("machines", "tasks"):
        if not _has_column(table_name, "attributes"):
            op.add_column(table_name, sa.Column("attributes", col_type, nullable=True))


def downgrade():
    for table_name in ("tasks", "machines"):
        if _has_column(table_name, "attributes"):
            op.drop_column(table_name, "attributes")
