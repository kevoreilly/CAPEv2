# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""add on delete cascade to errors fkey

Revision ID: errors_task_id_cascade
Revises: 3a1b_tenant_visibility
Create Date: 2026-08-23
"""

import sqlalchemy as sa
from alembic import op


revision = "errors_task_id_cascade"
down_revision = "3a1b_tenant_visibility"
branch_labels = None
depends_on = None

_NAMING_CONVENTION = {
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
}


def _get_errors_task_fks(bind):
    inspector = sa.inspect(bind)
    if "errors" not in inspector.get_table_names():
        return []
    return [
        fk
        for fk in inspector.get_foreign_keys("errors")
        if fk.get("referred_table") == "tasks" and fk.get("constrained_columns") == ["task_id"]
    ]


def upgrade():
    bind = op.get_bind()
    task_fks = _get_errors_task_fks(bind)
    if len(task_fks) == 1 and (task_fks[0].get("options") or {}).get("ondelete", "").upper() == "CASCADE":
        return

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("errors", naming_convention=_NAMING_CONVENTION) as batch_op:
            for fk in task_fks:
                fk_name = fk.get("name") or "fk_errors_task_id_tasks"
                batch_op.drop_constraint(fk_name, type_="foreignkey")
            batch_op.create_foreign_key(
                "errors_task_id_fkey",
                "tasks",
                ["task_id"],
                ["id"],
                ondelete="CASCADE",
            )
    else:
        for fk in task_fks:
            if fk.get("name"):
                op.drop_constraint(fk["name"], "errors", type_="foreignkey")
        op.create_foreign_key(
            "errors_task_id_fkey",
            "errors",
            "tasks",
            ["task_id"],
            ["id"],
            ondelete="CASCADE",
        )


def downgrade():
    bind = op.get_bind()
    task_fks = _get_errors_task_fks(bind)
    if len(task_fks) == 1 and not (task_fks[0].get("options") or {}).get("ondelete"):
        return

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("errors", naming_convention=_NAMING_CONVENTION) as batch_op:
            for fk in task_fks:
                fk_name = fk.get("name") or "fk_errors_task_id_tasks"
                batch_op.drop_constraint(fk_name, type_="foreignkey")
            batch_op.create_foreign_key(
                "errors_task_id_fkey",
                "tasks",
                ["task_id"],
                ["id"],
            )
    else:
        for fk in task_fks:
            if fk.get("name"):
                op.drop_constraint(fk["name"], "errors", type_="foreignkey")
        op.create_foreign_key(
            "errors_task_id_fkey",
            "errors",
            "tasks",
            ["task_id"],
            ["id"],
        )
