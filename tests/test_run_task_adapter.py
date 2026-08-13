import utils.process as proc


def test_run_task_calls_process_with_task_and_auto(monkeypatch, db, temp_pe32):
    captured = {}

    def fake_process(target=None, sample_sha256=None, task=None, report=False, auto=False, **kw):
        captured["task_id"] = task.id
        captured["auto"] = auto
        captured["report"] = report

    monkeypatch.setattr(proc, "process", fake_process)
    monkeypatch.setattr(proc, "db", db)

    # Force path_exists to return True so the analysis path check succeeds
    monkeypatch.setattr(proc, "path_exists", lambda *args, **kwargs: True)

    with db.session.begin():
        tid = db.add_path(temp_pe32)
        task = db.view_task(tid)

    proc.run_task(task)

    assert captured["task_id"] == tid
    assert captured["auto"] is True and captured["report"] is True


def test_run_task_fails_gracefully_when_analysis_dir_missing(monkeypatch, db, temp_pe32):
    process_called = False

    def fake_process(*args, **kwargs):
        nonlocal process_called
        process_called = True

    monkeypatch.setattr(proc, "process", fake_process)
    monkeypatch.setattr(proc, "db", db)

    # Force path_exists to return False for the analysis path
    original_path_exists = proc.path_exists
    def fake_path_exists(path, *args, **kwargs):
        if "storage/analyses" in str(path):
            return False
        return original_path_exists(path, *args, **kwargs)

    monkeypatch.setattr(proc, "path_exists", fake_path_exists)

    with db.session.begin():
        tid = db.add_path(temp_pe32)
        task = db.view_task(tid)

    proc.run_task(task)

    assert not process_called, "process should not have been called when analysis dir is missing"

    with db.session.begin():
        updated_task = db.view_task(tid)
        assert updated_task.status == proc.TASK_FAILED_PROCESSING
