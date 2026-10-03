# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pytest
from lib.cuckoo.common import cleaners_utils


def test_free_space_monitor(mocker):
    # Will not enter main loop
    cleaners_utils.free_space_monitor(return_value=True)


@pytest.mark.parametrize(("first", "last"), [(1, 2), (1, 1), (None, None)])
def test_clean_range_tasks_commits(db, mocker, first, last):
    with db.session.begin():
        task_ids = [db.add_url(f"https://example.invalid/{index}") for index in range(4)]

    mocker.patch.object(cleaners_utils, "db", db)
    mocker.patch.object(cleaners_utils, "create_structure")
    delete_folders = mocker.patch.object(cleaners_utils, "delete_bulk_tasks_n_folders")
    delete_mongo = mocker.patch.object(cleaners_utils, "mongo_delete_data", create=True)
    start = task_ids[first] if first is not None else max(task_ids) + 1
    end = task_ids[last] if last is not None else max(task_ids) + 2
    selected = set(task_ids[first : last + 1]) if first is not None else set()

    cleaners_utils.cuckoo_clean_range_tasks(f"{start}-{end}")

    delete_mongo.assert_called_once()
    assert set(delete_mongo.call_args.args[0]) == selected
    delete_folders.assert_called_once_with(delete_mongo.call_args.args[0], delete_mongo=False)
    # A read in the same session would also see an uncommitted deletion.
    db.session.remove()
    with db.session.begin():
        assert {task.id for task in db.list_tasks()} == set(task_ids) - selected
