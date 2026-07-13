import utils.process as proc


def test_run_task_calls_process_with_task_and_auto(monkeypatch, db, temp_pe32):
    captured = {}

    def fake_process(target=None, sample_sha256=None, task=None, report=False, auto=False, **kw):
        captured["task_id"] = task.id
        captured["auto"] = auto
        captured["report"] = report

    monkeypatch.setattr(proc, "process", fake_process)
    monkeypatch.setattr(proc, "db", db)

    with db.session.begin():
        tid = db.add_path(temp_pe32)
        task = db.view_task(tid)

    proc.run_task(task)

    assert captured["task_id"] == tid
    assert captured["auto"] is True and captured["report"] is True
