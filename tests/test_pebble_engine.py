import functools
import os
import pickle
import time

from lib.cuckoo.core.data.task import TASK_COMPLETED
from lib.cuckoo.core.processing_engine.pebble import PebbleEngine
from lib.cuckoo.core.processing_engine.source import TaskSource


# Must be module-level (not a closure) so pickle can serialise it.
def _task_fn_write_sentinel(task):
    """Writes task.id to an env-var-specified sentinel file.

    Runs inside a pebble subprocess.  Uses os.environ to communicate the
    sentinel path because closures are not picklable with stdlib pickle.
    """
    sentinel = os.environ.get("_PEBBLE_TEST_SENTINEL", "")
    if sentinel:
        with open(sentinel, "w") as fh:
            fh.write(str(task.id))


def test_pebble_engine_processes_one_task(db, temp_pe32, tmp_path, monkeypatch):
    """PebbleEngine schedules a TASK_COMPLETED task, calls task_fn in a
    worker subprocess, drains completely, and returns.

    We use a filesystem sentinel to confirm task_fn executed.
    threading.Event cannot cross process boundaries; closures are not
    picklable with stdlib pickle so we pass the path via os.environ."""
    with db.session.begin():
        tid = db.add_path(temp_pe32)
        db.set_status(tid, TASK_COMPLETED)

    # run() calls free_space_monitor(storage/analyses, ...), which sys.exit()s when
    # that path doesn't exist (as in CI). Stub it — disk policy isn't under test here.
    monkeypatch.setattr("lib.cuckoo.common.cleaners_utils.free_space_monitor", lambda *a, **k: None)

    sentinel = str(tmp_path / "ran.txt")
    monkeypatch.setenv("_PEBBLE_TEST_SENTINEL", sentinel)

    eng = PebbleEngine(task_fn=_task_fn_write_sentinel, worker_init=lambda: None,
                       source=TaskSource(db), parallel=2, timeout=30, max_count=1)
    eng.run()

    # run() only returns after all in-flight futures complete (drain guarantee).
    assert eng._pending == {}, "drain loop should leave _pending empty"
    # Confirm task_fn actually executed in the worker subprocess.
    assert os.path.exists(sentinel), "worker did not write sentinel — task_fn never ran"
    assert open(sentinel).read().strip() == str(tid)


def test_autoprocess_task_fn_is_picklable():
    """Regression: pebble dispatches task_fn over multiprocessing pipes; a
    function-scope lambda would crash with 'Can't pickle local object' on the
    first task. functools.partial is picklable; lambdas are not."""
    from utils.process import run_task
    task_fn = functools.partial(run_task, memory_debugging=False, debug=False)
    pickle.dumps(task_fn)  # would raise PicklingError for a lambda


class _CountingSource:
    def __init__(self):
        self.failed = []

    def mark_failed(self, task_id):
        self.failed.append(task_id)


class _MockFuture:
    def __init__(self):
        self._cancelled = False

    def cancel(self):
        self._cancelled = True
        return True

    def result(self):
        return None


class _BaseExceptionRaisingFuture(_MockFuture):
    def result(self):
        raise BaseException("panic!")


def test_reaper_fails_a_task_that_was_never_picked_up():
    source = _CountingSource()
    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=lambda: None,
        source=source,
        parallel=1,
        timeout=1,
        stall_grace=1
    )
    future = _MockFuture()

    with engine._lock:
        engine._pending[future] = 77
        engine._scheduled_at[future] = time.monotonic() - 3600  # long overdue

    engine._reap_stalled()

    with engine._lock:
        assert engine._pending == {}, "overdue task left in _pending"
        assert engine._scheduled_at == {}, "overdue task left in _scheduled_at"
    assert source.failed == [77], "overdue task was never marked failed"
    assert future._cancelled, "overdue task future was not cancelled"


def test_reaper_leaves_a_task_that_is_still_within_its_deadline():
    source = _CountingSource()
    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=lambda: None,
        source=source,
        parallel=1,
        timeout=10,
        stall_grace=5
    )
    future = _MockFuture()

    with engine._lock:
        engine._pending[future] = 88
        engine._scheduled_at[future] = time.monotonic()  # brand new

    engine._reap_stalled()

    with engine._lock:
        assert engine._pending == {future: 88}, "in-flight task was reaped early"
        assert engine._scheduled_at == {future: engine._scheduled_at[future]}, "in-flight task scheduled_at cleared"
    assert source.failed == [], "in-flight task was marked failed"
    assert not future._cancelled, "in-flight task future was cancelled"


def test_done_handles_base_exception_robustly():
    source = _CountingSource()
    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=lambda: None,
        source=source,
        parallel=1,
        timeout=10,
        stall_grace=5
    )
    future = _BaseExceptionRaisingFuture()

    with engine._lock:
        engine._pending[future] = 99
        engine._scheduled_at[future] = time.monotonic()

    # _done should handle the BaseException from future.result() and not raise/propagate it.
    engine._done(future)

    with engine._lock:
        assert future not in engine._pending, "future not removed from pending"
        assert future not in engine._scheduled_at, "future not removed from scheduled_at"
    assert source.failed == [99], "task was not marked failed on BaseException"

