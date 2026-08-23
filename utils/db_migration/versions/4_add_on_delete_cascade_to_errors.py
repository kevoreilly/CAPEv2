# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""add on delete cascade to errors fkey

Revision ID: errors_task_id_cascade
Revises: 3a1b_tenant_visibility
Create Date: 2026-08-23
"""

from alembic import op


revision = "errors_task_id_cascade"
down_revision = "3a1b_tenant_visibility"
branch_labels = None
depends_on = None


def upgrade():
    try:
        # Standard upgrade using batch operations for SQLite/MySQL/Postgres compatibility
        with op.batch_alter_table("errors") as batch_op:
            batch_op.drop_constraint("errors_task_id_fkey", type_="foreignkey")
    except Exception:
        try:
            # Fallback for other standard naming conventions
            with op.batch_alter_table("errors") as batch_op:
                batch_op.drop_constraint("fk_errors_task_id_tasks", type_="foreignkey")
        except Exception:
            pass

    with op.batch_alter_table("errors") as batch_op:
        batch_op.create_foreign_key(
            "errors_task_id_fkey",
            "tasks",
            ["task_id"],
            ["id"],
            ondelete="CASCADE"
        )


def downgrade():
    try:
        with op.batch_alter_table("errors") as batch_op:
            batch_op.drop_constraint("errors_task_id_fkey", type_="foreignkey")
    except Exception:
        pass

    with op.batch_alter_table("errors") as batch_op:
        batch_op.create_foreign_key(
            "errors_task_id_fkey",
            "tasks",
            ["task_id"],
            ["id"]
        )
