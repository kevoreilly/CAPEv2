from lib.cuckoo.core.data.task import TASK_COMPLETED, TASK_FAILED_PROCESSING
from lib.cuckoo.core.processing_engine.source import TaskSource


def test_fetch_returns_completed_tasks_excluding_inflight(db, temp_pe32):
    with db.session.begin():
        t1 = db.add_path(temp_pe32)
        t2 = db.add_path(temp_pe32)
        db.set_status(t1, TASK_COMPLETED)
        db.set_status(t2, TASK_COMPLETED)

    src = TaskSource(db)
    got = src.fetch(limit=10, exclude_ids={t2})
    ids = [t.id for t in got]
    assert t1 in ids and t2 not in ids


def test_mark_failed_sets_status(db, temp_pe32):
    with db.session.begin():
        t1 = db.add_path(temp_pe32)
        db.set_status(t1, TASK_COMPLETED)

    src = TaskSource(db)
    src.mark_failed(t1)

    with db.session.begin():
        assert db.view_task(t1).status == TASK_FAILED_PROCESSING


def test_fetch_with_failed_processing_returns_failed_tasks(db, temp_pe32):
    with db.session.begin():
        t1 = db.add_path(temp_pe32)
        t2 = db.add_path(temp_pe32)
        db.set_status(t1, TASK_FAILED_PROCESSING)
        db.set_status(t2, TASK_COMPLETED)

    src = TaskSource(db, failed_processing=True)
    got = src.fetch(limit=10, exclude_ids=set())
    ids = [t.id for t in got]
    assert t1 in ids and t2 not in ids
