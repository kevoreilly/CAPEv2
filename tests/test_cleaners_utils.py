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
    from datetime import timedelta
    from lib.cuckoo.core.data.db_common import _utcnow_naive

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
            task.added_on = _utcnow_naive() - timedelta(days=5)

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


def test_convert_into_time_accepts_positive_int_and_rejects_bool_or_non_positive():
    from datetime import datetime, timedelta

    now = datetime.now()
    dt = cleaners_utils.convert_into_time(3)
    delta = now - dt
    assert timedelta(days=2, hours=23) < delta < timedelta(days=3, seconds=10)

    for bad in (True, False, 0, -2, "", "d", "0x", "5w"):
        with pytest.raises(ValueError):
            cleaners_utils.convert_into_time(bad)


def test_tmp_clean_before_cleans_all_managed_tmp_subdirs_only(tmp_path, custom_conf_path, monkeypatch):
    import os
    import time

    from lib.cuckoo.common.config import ConfigMeta

    tmppath = tmp_path / "tmproot"
    tmppath.mkdir()
    (custom_conf_path / "cuckoo.conf").write_text(f"[cuckoo]\ntmppath = {tmppath}\n", encoding="utf-8")
    ConfigMeta.refresh()

    old_ts = time.time() - 7200
    old_files = []
    for subdir in cleaners_utils.CLEANED_TMP_SUBDIRS:
        d = tmppath / subdir
        d.mkdir()
        f = d / f"old_{subdir}.bin"
        f.write_bytes(b"old")
        os.utime(f, (old_ts, old_ts))
        old_files.append(f)

    fresh_ext = tmppath / "cape-external" / "fresh.bin"
    fresh_ext.write_bytes(b"fresh")

    # Broken symlink inside cape-external must also be removed when older than cutoff.
    broken_link = tmppath / "cape-external" / "broken_symlink"
    os.symlink("/nonexistent/target/file", str(broken_link))

    unmanaged_stray = tmppath / "stray_root.bin"
    unmanaged_stray.write_bytes(b"stray")
    os.utime(unmanaged_stray, (old_ts, old_ts))

    real_lstat = os.lstat

    def _fake_lstat(path, *args, **kwargs):
        st = real_lstat(path, *args, **kwargs)
        if str(path) == str(broken_link):
            from types import SimpleNamespace

            return SimpleNamespace(st_mode=st.st_mode, st_ctime=old_ts, st_mtime=old_ts)
        return st

    monkeypatch.setattr(cleaners_utils, "path_get_date", lambda path, key="st_ctime": os.stat(path).st_mtime)
    monkeypatch.setattr(cleaners_utils.os, "lstat", _fake_lstat)

    cleaners_utils.tmp_clean_before("1h")

    for f in old_files:
        assert not f.exists()
    assert not os.path.lexists(broken_link)
    assert fresh_ext.exists()
    assert unmanaged_stray.exists()


def test_collect_disk_usage_report_structure_budget_and_gcs_failure_isolation(tmp_path, monkeypatch, caplog):
    import logging

    tmppath = tmp_path / "tmproot"
    (tmppath / "cape-external").mkdir(parents=True)
    (tmppath / "cape-external" / "staged.zip").write_bytes(b"x" * 64)
    (tmppath / "stray_root.bin").write_bytes(b"y" * 256)

    for sub in ("analyses", "binaries", "files", "baseline"):
        (tmp_path / "storage" / sub).mkdir(parents=True)
    (tmp_path / "storage" / "analyses" / "1.bin").write_bytes(b"a" * 128)
    (tmp_path / "log").mkdir()
    (tmp_path / "log" / "cuckoo.log").write_bytes(b"l" * 32)

    monkeypatch.setattr(cleaners_utils, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(cleaners_utils, "_resolve_tmppath", lambda: str(tmppath))

    uploaded_reports = []
    monkeypatch.setattr(
        "lib.cuckoo.common.gcp.gcs_upload_disk_report",
        lambda rep: uploaded_reports.append(rep) or "gs://diag/report.json",
    )

    with caplog.at_level(logging.ERROR, logger="lib.cuckoo.common.cleaners_utils"):
        report = cleaners_utils.collect_disk_usage_report(str(tmp_path / "storage" / "analyses"), max_items=5)

    assert len(report["mounts"]) == 1  # Same st_dev deduplicated
    assert report["uncleaned_tmp_root"]["cleaned_by_cape"] is False
    assert [i["name"] for i in report["uncleaned_tmp_root"]["top_items"]] == ["stray_root.bin"]
    assert report["tmppath_cleaned"]["cape-external"]["files"] == 1
    assert report["storage"]["analyses"]["bytes"] == 128
    assert report["log"]["bytes"] == 32
    assert len(uploaded_reports) == 1
    assert any("Disk usage breakdown" in r.message for r in caplog.records)

    # Tight budget sets truncated=True and GCS upload errors are swallowed cleanly.
    monkeypatch.setattr(
        "lib.cuckoo.common.gcp.gcs_upload_disk_report",
        lambda _rep: (_ for _ in ()).throw(RuntimeError("upload failed")),
    )
    truncated_report = cleaners_utils.collect_disk_usage_report(max_items=2, max_entries=1, max_seconds=5.0)
    assert truncated_report["truncated"] is True


def test_execute_cleanup_runs_tmp_first_and_isolates_errors(monkeypatch):
    order = []
    monkeypatch.setattr(cleaners_utils, "init_console_logging", lambda: order.append("init_log"))
    monkeypatch.setattr(cleaners_utils, "tmp_clean_before", lambda val: order.append(("tmp", val)))

    def _failing_cuckoo(_args):
        order.append("cuckoo")
        raise RuntimeError("db error")

    monkeypatch.setattr(cleaners_utils, "cuckoo_clean_before", _failing_cuckoo)
    monkeypatch.setattr(cleaners_utils, "binaries_clean_before", lambda val: order.append(("binaries", val)))

    args = {
        "delete_tmp_items_older_than": "1d",
        "delete_older_than": "1d",
        "delete_binaries_items_older_than": "1d",
    }

    cleaners_utils.execute_cleanup(args, init_log=False, isolate_errors=True)
    assert order == [("tmp", "1d"), "cuckoo", ("binaries", "1d")]

    order.clear()
    with pytest.raises(RuntimeError, match="db error"):
        cleaners_utils.execute_cleanup(args, init_log=False, isolate_errors=False)
    assert order == [("tmp", "1d"), "cuckoo"]


def test_free_space_monitor_validation_throttling_and_state_recovery(tmp_path, monkeypatch, caplog):
    import logging
    from collections import namedtuple
    from types import SimpleNamespace

    _DiskUsage = namedtuple("DiskUsage", ["total", "used", "free"])

    # 1. Non-numeric / bool / non-positive freespace returns cleanly without sys.exit.
    for raw_val in ("invalid", True, 0):
        fake_cfg = SimpleNamespace(
            cleaner=SimpleNamespace(
                mongo=False, binaries="", get=lambda _k: "", tmp="", analysis="", unused_files_in_mongodb=False, enabled=False
            ),
            cuckoo=SimpleNamespace(freespace=raw_val, freespace_processing=0),
        )
        monkeypatch.setattr(cleaners_utils, "config", fake_cfg)
        monkeypatch.setattr(cleaners_utils, "HAVE_TMPFS", False)
        assert cleaners_utils.free_space_monitor(str(tmp_path), return_value=False, analysis=True) is None

    # 2. Missing path auto-created; throttling at 300s/1800s; delay 30 vs 5; state callback cleared on recovery.
    mon_path = tmp_path / "missing_analyses"
    fake_cfg = SimpleNamespace(
        cleaner=SimpleNamespace(
            mongo=False, binaries="", get=lambda _k: "", tmp="1h", analysis="1d", unused_files_in_mongodb=False, enabled=True
        ),
        cuckoo=SimpleNamespace(freespace=100, freespace_processing=0),
    )
    monkeypatch.setattr(cleaners_utils, "config", fake_cfg)

    # Sequence of disk_usage reads:
    # iter1: start=10MB -> after clean=10MB (delay=30)
    # iter2: start=10MB -> after clean=10MB (delay=30)
    # iter3: start=10MB -> after clean=20MB (delay=5)
    # iter4: start=10MB -> after clean=10MB (delay=30)
    # iter5: start=200MB (recovered -> break)
    free_mb_seq = [10, 10, 10, 10, 10, 20, 10, 10, 200]
    usage_idx = {"i": 0}

    def _fake_disk_usage(_p):
        idx = usage_idx["i"]
        usage_idx["i"] += 1
        free = free_mb_seq[idx] << 20
        return _DiskUsage(1000 << 20, (1000 << 20) - free, free)

    monkeypatch.setattr(cleaners_utils.shutil, "disk_usage", _fake_disk_usage)

    monotonic_vals = iter([100.0, 105.0, 450.0, 2000.0])
    monkeypatch.setattr(cleaners_utils.time, "monotonic", lambda: next(monotonic_vals))

    cleanup_calls = []
    report_calls = []
    sleeps = []
    states = []

    monkeypatch.setattr(
        cleaners_utils,
        "execute_cleanup",
        lambda arg, init_log=True, isolate_errors=False: cleanup_calls.append((init_log, isolate_errors)),
    )
    monkeypatch.setattr(cleaners_utils, "collect_disk_usage_report", lambda p=None: report_calls.append(p))

    with caplog.at_level(logging.ERROR, logger="lib.cuckoo.common.cleaners_utils"):
        cleaners_utils.free_space_monitor(
            str(mon_path),
            analysis=True,
            on_state_change=lambda need, avail: states.append((need, avail)),
            _sleep_fn=sleeps.append,
        )

    assert mon_path.is_dir()
    assert sleeps == [30, 30, 5, 30]
    assert cleanup_calls == [(False, True)] * 4
    # Report called at t=100 and t=2000 (>= 1800s elapsed); skipped at t=105 and t=450.
    assert report_calls == [str(mon_path), str(mon_path)]
    # Error logged at t=100, t=450 (>= 300s), t=2000 (>= 300s); skipped at t=105.
    err_logs = [r for r in caplog.records if "Not enough free disk space" in r.message]
    assert len(err_logs) == 3
    assert states == [(True, 10), (False, 200)]

    # 3. Cleaner disabled sleeps 30s; unrecovered break (exception or should_stop) does NOT falsely emit on_state_change(False).
    fake_cfg.cleaner.enabled = False
    monkeypatch.setattr(cleaners_utils.shutil, "disk_usage", lambda _p: _DiskUsage(1000 << 20, 990 << 20, 10 << 20))
    monkeypatch.setattr(cleaners_utils.time, "monotonic", lambda: 100.0)
    disabled_sleeps = []
    disabled_states = []

    def _abort_sleep(d):
        disabled_sleeps.append(d)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        cleaners_utils.free_space_monitor(
            str(mon_path),
            analysis=True,
            on_state_change=lambda need, avail: disabled_states.append((need, avail)),
            _sleep_fn=_abort_sleep,
        )
    assert disabled_sleeps == [30]
    assert disabled_states == [(True, 10)]

    # 4. should_stop stops loop cleanly without sleeping or clearing low-space state prematurely.
    stop_states = []
    stop_flag = {"stop": False}

    def _clean_sets_stop(*_a, **_kw):
        stop_flag["stop"] = True

    fake_cfg.cleaner.enabled = True
    monkeypatch.setattr(cleaners_utils, "execute_cleanup", _clean_sets_stop)
    cleaners_utils.free_space_monitor(
        str(mon_path),
        analysis=True,
        on_state_change=lambda need, avail: stop_states.append((need, avail)),
        should_stop=lambda: stop_flag["stop"],
        _sleep_fn=lambda _d: (_ for _ in ()).throw(AssertionError("should not sleep after should_stop")),
    )
    assert stop_states == [(True, 10)]


