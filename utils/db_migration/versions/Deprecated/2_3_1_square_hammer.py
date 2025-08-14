# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""2.3.1_square_hammer

Revision ID: 703266a6bbc5
Revises: 6ab863a3b510
Create Date: 2021-05-02 18:24:43.075702

"""

from contextlib import suppress

# revision identifiers, used by Alembic.
revision = "703266a6bbc5"
down_revision = "6ab863a3b510"

from alembic import op


def upgrade():
    op.execute("ALTER TABLE tasks alter status drop default")
    op.execute("ALTER TYPE status_type RENAME TO status_type_old;")
    op.execute(
        "CREATE TYPE status_type AS ENUM('banned', 'pending', 'running', 'distributed', 'completed', 'reported', 'recovered', 'failed_analysis', 'failed_processing', 'failed_reporting');"
    )
    op.execute("ALTER TABLE tasks ALTER COLUMN status TYPE status_type USING status::text::status_type")
    op.execute("ALTER TABLE tasks ALTER status set default 'pending'::status_type")
    op.execute("DROP TYPE status_type_old;")


def downgrade():
    with suppress(Exception):
        op.execute("DROP TYPE status_type_old;")
    op.execute("ALTER TABLE tasks alter status drop default")
    op.execute("ALTER TYPE status_type RENAME TO status_type_old;")
    op.execute(
        "CREATE TYPE status_type AS ENUM('pending', 'running', 'distributed', 'completed', 'reported', 'recovered', 'failed_analysis', 'failed_processing', 'failed_reporting');"
    )
    op.execute("ALTER TABLE tasks ALTER COLUMN status TYPE status_type USING status::text::status_type")
    op.execute("ALTER TABLE tasks ALTER status set default 'pending'::status_type")
    op.execute("DROP TYPE status_type_old;")
