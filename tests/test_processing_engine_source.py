import contextlib

from lib.cuckoo.core.data.task import TASK_COMPLETED, TASK_FAILED_PROCESSING
from lib.cuckoo.core.processing_engine.source import TaskSource


class _FakeTask:
    def __init__(self, tid):
        self.id = tid


class _FakeSession:
    def begin(self):
        return contextlib.nullcontext()

    def expunge_all(self):
        pass


class _FakeDB:
    def __init__(self, tasks):
        self._tasks = tasks
        self.limit_seen = None
        self.session = _FakeSession()

    def list_tasks(self, status, limit, order_by):
        self.limit_seen = limit
        return self._tasks[:limit]


def test_fetch_widens_db_limit_to_avoid_starvation():
    """DB limit must be widened by len(exclude_ids): if the oldest tasks are all
    in-flight, querying only `limit` returns nothing eligible even though other
    work waits. Result is sliced back to `limit`."""
    db = _FakeDB([_FakeTask(i) for i in range(1, 6)])  # ids 1..5; 1..3 in-flight
    src = TaskSource(db)

    got = src.fetch(limit=2, exclude_ids={1, 2, 3})

    assert db.limit_seen == 5, "DB query must fetch limit + len(exclude_ids) rows"
    assert [t.id for t in got] == [4, 5], "eligible tasks returned, sliced to limit"


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


def test_mark_failed_does_not_overwrite_reported_task(db, temp_pe32):
    from lib.cuckoo.core.data.task import TASK_REPORTED

    with db.session.begin():
        t1 = db.add_path(temp_pe32)
        db.set_status(t1, TASK_REPORTED)

    src = TaskSource(db)
    src.mark_failed(t1)

    with db.session.begin():
        assert db.view_task(t1).status == TASK_REPORTED


def test_mark_failed_atomic_update_ignores_stale_identity_map(db, temp_pe32):
    from sqlalchemy import text

    from lib.cuckoo.core.data.task import TASK_REPORTED

    with db.session.begin():
        t1 = db.add_path(temp_pe32)
        db.set_status(t1, TASK_COMPLETED)
        # Keep Task(id=t1) cached in db.session's identity map (expire_on_commit=False).
        cached = db.view_task(t1)
        assert cached is not None and cached.status == TASK_COMPLETED

    # Simulate another process/connection finishing reporting while db.session holds cached COMPLETED.
    with db.engine.begin() as conn:
        conn.execute(text("UPDATE tasks SET status = :st WHERE id = :tid"), {"st": TASK_REPORTED, "tid": t1})

    src = TaskSource(db)
    src.mark_failed(t1)

    # DB status must remain TASK_REPORTED and the cached ORM instance must be expired to reflect it.
    with db.engine.connect() as conn:
        assert conn.execute(text("SELECT status FROM tasks WHERE id = :tid"), {"tid": t1}).scalar_one() == TASK_REPORTED
    with db.session.begin():
        assert cached.status == TASK_REPORTED
        assert db.view_task(t1).status == TASK_REPORTED


def test_mark_failed_mock_db_fallback_respects_reported_status():
    from lib.cuckoo.core.data.task import TASK_REPORTED

    class _MockDB:
        def __init__(self, status):
            self.session = _FakeSession()
            self._status = status
            self.set_calls = []

        def view_task(self, task_id):
            return type("_T", (), {"id": task_id, "status": self._status})()

        def set_status(self, task_id, status):
            self.set_calls.append((task_id, status))

    reported_db = _MockDB(TASK_REPORTED)
    TaskSource(reported_db).mark_failed(10)
    assert reported_db.set_calls == []

    completed_db = _MockDB(TASK_COMPLETED)
    TaskSource(completed_db).mark_failed(11)
    assert completed_db.set_calls == [(11, TASK_FAILED_PROCESSING)]
