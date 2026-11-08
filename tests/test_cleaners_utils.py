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


def test_files_clean_before_preserves_mongodb_sha256_docs(tmp_path, monkeypatch):
    import os
    import time

    monkeypatch.setattr(cleaners_utils, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(cleaners_utils.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(cleaners_utils, "is_reporting_db_connected", lambda: True)

    sha_kept = "a" * 64
    sha_gone = "b" * 64
    monkeypatch.setattr(
        cleaners_utils,
        "mongo_find",
        lambda coll, q, proj: [{"_id": "507f1f77bcf86cd799439011", "sha256": sha_kept}],
        raising=False,
    )

    files_dir = tmp_path / "storage" / "files" / "aa" / "aa"
    files_dir.mkdir(parents=True)
    kept_file = files_dir / sha_kept
    kept_file.write_bytes(b"kept")
    gone_dir = tmp_path / "storage" / "files" / "bb" / "bb"
    gone_dir.mkdir(parents=True)
    gone_file = gone_dir / sha_gone
    gone_file.write_bytes(b"gone")

    old_ts = time.time() - 7200
    os.utime(kept_file, (old_ts, old_ts))
    os.utime(gone_file, (old_ts, old_ts))
    monkeypatch.setattr(
        cleaners_utils,
        "path_get_date",
        lambda path, key="st_ctime": os.stat(path).st_mtime,
    )

    cleaners_utils.files_clean_before("1h")
    assert kept_file.exists()
    assert not gone_file.exists()


def test_binaries_clean_before_deletes_older_and_keeps_newer(tmp_path, monkeypatch):
    import os
    import time

    monkeypatch.setattr(cleaners_utils, "CUCKOO_ROOT", str(tmp_path))
    bin_dir = tmp_path / "storage" / "binaries"
    bin_dir.mkdir(parents=True)

    sha_old = "c" * 64
    sha_new = "d" * 64
    old_bin = bin_dir / sha_old
    new_bin = bin_dir / sha_new
    old_bin.write_bytes(b"old")
    new_bin.write_bytes(b"new")

    now = time.time()
    os.utime(old_bin, (now - 7200, now - 7200))
    os.utime(new_bin, (now, now))
    monkeypatch.setattr(cleaners_utils, "path_get_date", lambda path, key="st_ctime": os.stat(path).st_mtime)

    class _FakeDB:
        def transaction(self):
            from contextlib import nullcontext

            return nullcontext()

        def sample_still_used(self, sha256, task_id):
            return False

    monkeypatch.setattr(cleaners_utils, "db", _FakeDB())

    cleaners_utils.binaries_clean_before("1h")
    assert not old_bin.exists()
    assert new_bin.exists()


def test_cuckoo_clean_before_mongo_filters_query_and_task_ids(db, tmp_path, mocker, monkeypatch):
    from datetime import datetime, timedelta

    monkeypatch.setattr(cleaners_utils, "CUCKOO_ROOT", str(tmp_path))
    mocker.patch.object(cleaners_utils, "db", db)
    mocker.patch.object(cleaners_utils, "create_structure")
    mocker.patch.object(cleaners_utils, "is_reporting_db_connected", return_value=True)

    with db.session.begin():
        t1 = db.add_url("https://example.invalid/1")
        t2 = db.add_url("https://example.invalid/2")
        for tid in (t1, t2):
            task = db.view_task(tid)
            task.status = "reported"
            task.added_on = datetime.utcnow() - timedelta(days=5)

    captured_queries = []

    def fake_mongo_find(coll, query, proj):
        captured_queries.append(query)
        return [{"info": {"id": t1}}]

    monkeypatch.setattr(cleaners_utils, "mongo_find", fake_mongo_find, raising=False)
    cleaners_utils.cuckoo_clean_before({"delete_older_than": "1d", "suricata_zero_alert_filter": True})

    assert len(captured_queries) == 1
    assert set(captured_queries[0]["info.id"]["$in"]) == {t1, t2}
    db.session.remove()
    with db.session.begin():
        remaining = {t.id for t in db.list_tasks()}
    assert t1 not in remaining
    assert t2 in remaining

