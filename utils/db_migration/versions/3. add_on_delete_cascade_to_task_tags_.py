# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Add ON DELETE CASCADE to tasks_tags foreign keys

Revision ID: 4e000e02a409
Revises: c2bd0eb5e69d
Create Date: 2025-04-11 09:58:42.957359

"""

# revision identifiers, used by Alembic.
revision = '4e000e02a409'
down_revision = 'c2bd0eb5e69d'

from alembic import op


def upgrade():
     op.drop_constraint('tasks_tags_task_id_fkey', 'tasks_tags', type_='foreignkey')
     op.create_foreign_key('tasks_tags_task_id_fkey', 'tasks_tags', 'tasks', ['task_id'], ['id'], ondelete='CASCADE')

     op.drop_constraint('tasks_tags_tag_id_fkey', 'tasks_tags', type_='foreignkey')
     op.create_foreign_key('tasks_tags_tag_id_fkey', 'tasks_tags', 'tags', ['tag_id'], ['id'], ondelete='CASCADE')


def downgrade():
     op.drop_constraint('tasks_tags_task_id_fkey', 'tasks_tags', type_='foreignkey')
     op.create_foreign_key('tasks_tags_task_id_fkey', 'tasks_tags', 'tasks', ['task_id'], ['id'])

     op.drop_constraint('tasks_tags_tag_id_fkey', 'tasks_tags', type_='foreignkey')
     op.create_foreign_key('tasks_tags_tag_id_fkey', 'tasks_tags', 'tags', ['tag_id'], ['id'])
