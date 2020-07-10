# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# https://stackoverflow.com/questions/14845203/altering-an-enum-field-using-alembic
# https://www.pythoncentral.io/migrate-sqlalchemy-databases-alembic/
# https://blog.yo1.dog/updating-enum-values-in-postgresql-the-safe-and-easy-way/

"""add distributed_status

Revision ID: e4954d358c80
Revises: 36926b59dfbb
Create Date: 2019-09-24 10:18:40.007575

"""

# revision identifiers, used by Alembic.
from __future__ import absolute_import

revision = "e4954d358c80"
down_revision = "36926b59dfbb"

from alembic import op


def upgrade():
    op.execute("ALTER TABLE tasks alter status drop default")
    op.execute("ALTER TYPE status_type RENAME TO status_type_old;")
    op.execute(
        "CREATE TYPE status_type AS ENUM('pending', 'running', 'distributed', 'completed', 'reported', 'recovered', 'failed_analysis', 'failed_processing', 'failed_reporting');"
    )
    op.execute("ALTER TABLE tasks ALTER COLUMN status TYPE status_type USING status::text::status_type")
    op.execute("ALTER TABLE tasks ALTER status set default 'pending'::status_type")
    # op.execute("DROP TYPE status_enum_old;")


def downgrade():
    op.execute("ALTER TABLE tasks alter status drop default")
    op.execute("ALTER TYPE status_type RENAME TO status_type_old;")
    op.execute(
        "CREATE TYPE status_type AS ENUM('pending', 'running', 'completed', 'reported', 'recovered', 'failed_analysis', 'failed_processing', 'failed_reporting');"
    )
    op.execute("ALTER TABLE tasks ALTER COLUMN status TYPE status_type USING status::text::status_type")
    op.execute("ALTER TABLE tasks ALTER status set default 'pending'::status_type")
    # op.execute("DROP TYPE status_enum_old;")
