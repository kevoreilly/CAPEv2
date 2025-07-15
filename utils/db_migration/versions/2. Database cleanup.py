# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2b3c4d5e6f7g'
down_revision = '4e000e02a409'
branch_labels = None
depends_on = None


def upgrade() -> None:

    op.alter_column('samples', 'file_size',
        existing_type=sa.INTEGER(),
        type_=sa.BIGINT(),
        existing_nullable=False
    )

    op.drop_column('samples', 'parent')
    op.drop_column('tasks', 'parent_id')
    op.drop_column('tasks', 'shrike_sid')
    op.drop_column('tasks', 'shrike_msg')
    op.drop_column('tasks', 'shrike_refer')
    op.drop_column('tasks', 'shrike_url')
    op.drop_column('tasks', 'username')

def downgrade() -> None:
    # First, drop the foreign key constraint
    op.drop_constraint('fk_samples_parent_id_samples', 'samples', type_='foreignkey')

    # Then, rename the column back to 'parent'
    op.add_column('samples', sa.Column('parent', sa.INTEGER(), autoincrement=False, nullable=True))

    op.alter_column('samples', 'file_size',
        existing_type=sa.BIGINT(),
        type_=sa.INTEGER(),
        existing_nullable=False
    )

    op.add_column('tasks', sa.Column('shrike_url', sa.VARCHAR(length=4096), autoincrement=False, nullable=True))
    op.add_column('tasks', sa.Column('shrike_refer', sa.VARCHAR(length=4096), autoincrement=False, nullable=True))
    op.add_column('tasks', sa.Column('shrike_msg', sa.VARCHAR(length=4096), autoincrement=False, nullable=True))
    op.add_column('tasks', sa.Column('shrike_sid', sa.INTEGER(), autoincrement=False, nullable=True))
    op.add_column('tasks', sa.Column('parent_id', sa.INTEGER(), autoincrement=False, nullable=True))

    # 1. Add the old parent_id column back
    op.add_column('samples', sa.Column('parent_id', sa.INTEGER(), autoincrement=False, nullable=True))

    # 2. Drop the new association table
    op.drop_table('sample_associations')
