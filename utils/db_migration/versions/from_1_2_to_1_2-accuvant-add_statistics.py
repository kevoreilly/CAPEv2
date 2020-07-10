# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), KillerInstinct, Cuckoo Foundation
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""add statistics

Revision ID: 4b09c454108c
Revises: 495d5a6edef3
Create Date: 2015-03-05 07:39:21.036983

"""

# revision identifiers, used by Alembic.
from __future__ import absolute_import
from __future__ import print_function

revision = "4b09c454108c"
down_revision = "495d5a6edef3"

from alembic import op
import sqlalchemy as sa

import os.path
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
sys.path.append(os.path.join(curdir, "..", ".."))

import lib.cuckoo.core.database as db


def _perform(upgrade):
    conn = op.get_bind()

    # Read data.
    tasks_data = []
    old_tasks = conn.execute(
        "select id, target, category, timeout, priority, custom, machine, package, options, platform, memory, enforce_timeout, clock, added_on, started_on, completed_on, status, sample_id from tasks"
    ).fetchall()

    for item in old_tasks:
        d = {}
        d["id"] = item[0]
        d["target"] = item[1]
        d["category"] = item[2]
        d["timeout"] = item[3]
        d["priority"] = item[4]
        d["custom"] = item[5]
        d["machine"] = item[6]
        d["package"] = item[7]
        d["options"] = item[8]
        d["platform"] = item[9]
        d["memory"] = item[10]
        d["enforce_timeout"] = item[11]

        if isinstance(item[12], datetime):
            d["clock"] = item[12]
        elif item[12]:
            d["clock"] = parse(item[12])
        else:
            d["clock"] = None

        if isinstance(item[13], datetime):
            d["added_on"] = item[13]
        elif item[13]:
            d["added_on"] = parse(item[13])
        else:
            d["added_on"] = None

        if isinstance(item[14], datetime):
            d["started_on"] = item[14]
        elif item[14]:
            d["started_on"] = parse(item[14])
        else:
            d["started_on"] = None

        if isinstance(item[15], datetime):
            d["completed_on"] = item[15]
        elif item[15]:
            d["completed_on"] = parse(item[15])
        else:
            d["completed_on"] = None

        d["status"] = item[16]
        d["sample_id"] = item[17]

        if upgrade:
            # Columns for statistics (via Thorsten's statistics page)
            d["dropped_files"] = None
            d["running_processes"] = None
            d["api_calls"] = None
            d["domains"] = None
            d["signatures_total"] = None
            d["signatures_alert"] = None
            d["files_written"] = None
            d["registry_keys_modified"] = None
            d["crash_issues"] = None
            d["anti_issues"] = None
            d["analysis_started_on"] = None
            d["analysis_finished_on"] = None
            d["processing_started_on"] = None
            d["processing_finished_on"] = None
            d["signatures_started_on"] = None
            d["signatures_finished_on"] = None
            d["reporting_started_on"] = None
            d["reporting_finished_on"] = None

            d["timedout"] = False
            d["machine_id"] = None

        tasks_data.append(d)

    if conn.engine.driver == "mysqldb":
        # Disable foreign key checking to migrate table avoiding checks.
        op.execute("SET foreign_key_checks = 0")

    # Drop old table.
    op.drop_table("tasks")

    # Create table with 1.2 schema.
    if upgrade:
        op.create_table(
            "tasks",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("category", sa.String(length=255), nullable=False),
            sa.Column("timeout", sa.Integer(), server_default="0", nullable=False),
            sa.Column("priority", sa.Integer(), server_default="1", nullable=False),
            sa.Column("custom", sa.String(length=255), nullable=True),
            sa.Column("machine", sa.String(length=255), nullable=True),
            sa.Column("package", sa.String(length=255), nullable=True),
            sa.Column("options", sa.String(length=255), nullable=True),
            sa.Column("platform", sa.String(length=255), nullable=True),
            sa.Column("memory", sa.Boolean(), nullable=False, default=False),
            sa.Column("enforce_timeout", sa.Boolean(), nullable=False, default=False),
            sa.Column("clock", sa.DateTime(timezone=False), default=datetime.now, nullable=False),
            sa.Column("added_on", sa.DateTime(timezone=False), nullable=False),
            sa.Column("started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("completed_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column(
                "status",
                sa.Enum(
                    "pending",
                    "running",
                    "completed",
                    "reported",
                    "recovered",
                    "failed_analysis",
                    "failed_processing",
                    "failed_reporting",
                    name="status_type",
                ),
                server_default="pending",
                nullable=False,
            ),
            sa.Column("sample_id", sa.Integer, sa.ForeignKey("samples.id"), nullable=True),
            sa.Column("dropped_files", sa.Integer(), nullable=True),
            sa.Column("running_processes", sa.Integer(), nullable=True),
            sa.Column("api_calls", sa.Integer(), nullable=True),
            sa.Column("domains", sa.Integer(), nullable=True),
            sa.Column("signatures_total", sa.Integer(), nullable=True),
            sa.Column("signatures_alert", sa.Integer(), nullable=True),
            sa.Column("files_written", sa.Integer(), nullable=True),
            sa.Column("registry_keys_modified", sa.Integer(), nullable=True),
            sa.Column("crash_issues", sa.Integer(), nullable=True),
            sa.Column("anti_issues", sa.Integer(), nullable=True),
            sa.Column("analysis_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("analysis_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("processing_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("processing_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("signatures_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("signatures_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("reporting_started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("reporting_finished_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("timedout", sa.Boolean(), nullable=False, default=False),
            sa.Column("machine_id", sa.Integer(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
    else:
        op.create_table(
            "tasks",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("category", sa.String(length=255), nullable=False),
            sa.Column("timeout", sa.Integer(), server_default="0", nullable=False),
            sa.Column("priority", sa.Integer(), server_default="1", nullable=False),
            sa.Column("custom", sa.String(length=255), nullable=True),
            sa.Column("machine", sa.String(length=255), nullable=True),
            sa.Column("package", sa.String(length=255), nullable=True),
            sa.Column("options", sa.String(length=255), nullable=True),
            sa.Column("platform", sa.String(length=255), nullable=True),
            sa.Column("memory", sa.Boolean(), nullable=False, default=False),
            sa.Column("enforce_timeout", sa.Boolean(), nullable=False, default=False),
            sa.Column("clock", sa.DateTime(timezone=False), default=datetime.now, nullable=False),
            sa.Column("added_on", sa.DateTime(timezone=False), nullable=False),
            sa.Column("started_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column("completed_on", sa.DateTime(timezone=False), nullable=True),
            sa.Column(
                "status",
                sa.Enum(
                    "pending",
                    "running",
                    "completed",
                    "reported",
                    "recovered",
                    "failed_analysis",
                    "failed_processing",
                    "failed_reporting",
                    name="status_type",
                ),
                server_default="pending",
                nullable=False,
            ),
            sa.Column("sample_id", sa.Integer, sa.ForeignKey("samples.id"), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )

    if conn.engine.driver == "mysqldb":
        op.execute("COMMIT")

    # Insert data.
    op.bulk_insert(db.Task.__table__, tasks_data)

    if conn.engine.driver == "mysqldb":
        # Enable foreign key.
        op.execute("SET foreign_key_checks = 1")


def upgrade():
    _perform(upgrade=True)


def downgrade():
    _perform(upgrade=False)
