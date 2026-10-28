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
    def __init__(self, running=False):
        self._cancelled = False
        self._running = running

    def cancel(self):
        self._cancelled = True
        return True

    def cancelled(self):
        return self._cancelled

    def running(self):
        return self._running

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


def test_done_and_reaper_survive_mark_failed_db_exception():
    """If source.mark_failed raises a transient DB error inside _done() or
    _reap_stalled(), the exception must be caught and logged rather than
    escaping into pebble's callback thread or crashing the supervisor."""
    class _FailingMarkSource:
        def __init__(self):
            self.attempts = []

        def mark_failed(self, task_id):
            self.attempts.append(task_id)
            raise RuntimeError("transient DB disconnect")

    source = _FailingMarkSource()
    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=lambda: None,
        source=source,
        parallel=1,
        timeout=1,
        stall_grace=1,
    )

    # 1. _done with failing mark_failed must not raise
    f1 = _BaseExceptionRaisingFuture()
    with engine._lock:
        engine._pending[f1] = 101
        engine._scheduled_at[f1] = time.monotonic()
    engine._done(f1)
    assert source.attempts == [101]

    # 2. _reap_stalled with failing mark_failed must not raise
    f2 = _MockFuture()
    with engine._lock:
        engine._pending[f2] = 102
        engine._scheduled_at[f2] = time.monotonic() - 3600
    engine._reap_stalled()
    assert source.attempts == [101, 102]


def test_done_logs_task_fn_name_on_timeout(caplog):
    """When pebble raises ProcessExpired/TimeoutError('Task timeout', 900),
    _done() must log the task function name rather than error.args[1] (the timeout integer)."""
    import logging
    from concurrent.futures import TimeoutError

    class _TimeoutFuture(_MockFuture):
        def result(self):
            raise TimeoutError("Task timeout", 900)

    def sample_worker_fn(task, debug=False):
        return None

    source = _CountingSource()
    engine = PebbleEngine(
        task_fn=functools.partial(sample_worker_fn, debug=False),
        worker_init=lambda: None,
        source=source,
        parallel=1,
        timeout=900,
    )
    future = _TimeoutFuture()
    with engine._lock:
        engine._pending[future] = 42
        engine._scheduled_at[future] = time.monotonic()

    with caplog.at_level(logging.ERROR, logger="lib.cuckoo.core.processing_engine.pebble"):
        engine._done(future)

    assert source.failed == [42]
    assert "Function: sample_worker_fn" in caplog.text
    assert "Function: 900" not in caplog.text


def test_reaper_two_tier_deadline_unstarted_vs_running():
    """Tasks that never started (running() is False) must be reaped after
    stall_grace without waiting for timeout + stall_grace, whereas running
    tasks must wait for the full timeout + stall_grace."""
    source = _CountingSource()
    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=lambda: None,
        source=source,
        parallel=2,
        timeout=900,
        stall_grace=10,
    )
    unstarted_future = _MockFuture(running=False)
    running_future = _MockFuture(running=True)

    now = time.monotonic()
    with engine._lock:
        # Both scheduled 15s ago: past stall_grace (10s), well before timeout + stall_grace (910s).
        engine._pending[unstarted_future] = 201
        engine._scheduled_at[unstarted_future] = now - 15
        engine._pending[running_future] = 202
        engine._scheduled_at[running_future] = now - 15

    engine._reap_stalled()

    with engine._lock:
        assert unstarted_future not in engine._pending, "unstarted task past stall_grace must be reaped"
        assert running_future in engine._pending, "running task within timeout+stall_grace must not be reaped"
    assert source.failed == [201]
    assert unstarted_future.cancelled()
    assert not running_future.cancelled()

    # Now age running_future past timeout + stall_grace (910s).
    with engine._lock:
        engine._scheduled_at[running_future] = time.monotonic() - 915

    engine._reap_stalled()

    with engine._lock:
        assert running_future not in engine._pending
    assert source.failed == [201, 202]
    assert running_future.cancelled()


def test_reaper_pickup_clock_starts_at_pool_creation():
    """An unstarted task scheduled before the current pool was (re)created must
    not be reaped until pickup_grace has elapsed since pool creation, so workers
    still running worker_init are not penalised."""
    source = _CountingSource()
    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=lambda: None,
        source=source,
        parallel=1,
        timeout=900,
        stall_grace=10,
    )
    future = _MockFuture(running=False)
    now = time.monotonic()
    engine._pool_created_at = now - 5  # pool recreated 5s ago
    with engine._lock:
        engine._pending[future] = 301
        engine._scheduled_at[future] = now - 15  # scheduled 15s ago

    engine._reap_stalled()
    assert future in engine._pending, "pickup clock must start at pool creation"
    assert source.failed == []

    engine._pool_created_at = now - 11
    engine._reap_stalled()
    assert future not in engine._pending
    assert source.failed == [301]


def test_reaper_pickup_grace_overrides_stall_grace():
    source = _CountingSource()
    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=lambda: None,
        source=source,
        parallel=1,
        timeout=900,
        stall_grace=10,
        pickup_grace=60,
    )
    future = _MockFuture(running=False)
    with engine._lock:
        engine._pending[future] = 302
        engine._scheduled_at[future] = time.monotonic() - 15

    engine._reap_stalled()
    assert future in engine._pending, "pickup_grace (60s) must override stall_grace (10s)"

    with engine._lock:
        engine._scheduled_at[future] = time.monotonic() - 61
    engine._reap_stalled()
    assert source.failed == [302]


def test_new_pool_records_creation_time():
    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=None,
        source=_CountingSource(),
        parallel=1,
        timeout=30,
    )
    assert engine._pool_created_at == 0.0
    before = time.monotonic()
    pool = engine._new_pool()
    try:
        assert engine._pool_created_at >= before
    finally:
        engine._teardown_pool(pool, force=True)


def test_reaper_cancel_with_real_process_future_does_not_log_cancelled_error(caplog):

    """When _reap_stalled cancels a real pebble.ProcessFuture that has
    engine._done registered via add_done_callback, _done runs synchronously
    inside cancel() and must not log a spurious CancelledError traceback."""
    import logging
    from pebble import ProcessFuture

    source = _CountingSource()
    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=lambda: None,
        source=source,
        parallel=1,
        timeout=60,
        stall_grace=5,
    )
    future = ProcessFuture()
    with engine._lock:
        engine._pending[future] = 303
        engine._scheduled_at[future] = time.monotonic() - 30
    future.add_done_callback(engine._done)

    with caplog.at_level(logging.ERROR, logger="lib.cuckoo.core.processing_engine.pebble"):
        engine._reap_stalled()

    assert source.failed == [303]
    assert "Exception when processing task" not in caplog.text


def test_pebble_engine_batches_multiple_tasks_per_fetch(monkeypatch):
    """PebbleEngine.run() must fetch and schedule up to `launchable` tasks in a
    single pass rather than breaking after the first task on every iteration."""
    from pebble import ProcessFuture

    monkeypatch.setattr("lib.cuckoo.common.cleaners_utils.free_space_monitor", lambda *a, **k: None)

    class _TaskObj:
        def __init__(self, tid):
            self.id = tid

    class _BatchSource:
        def __init__(self):
            self.fetch_limits = []
            self.failed = []
            self._tasks = [_TaskObj(1), _TaskObj(2), _TaskObj(3)]

        def fetch(self, limit, exclude_ids):
            self.fetch_limits.append(limit)
            return [t for t in self._tasks if t.id not in exclude_ids][:limit]

        def mark_failed(self, task_id):
            self.failed.append(task_id)

    scheduled_ids = []

    class _FakePool:
        active = True

        def schedule(self, fn, args=(), timeout=None):
            scheduled_ids.append(args[0].id)
            fut = ProcessFuture()
            fut.set_result(None)
            return fut

        def close(self):
            pass

        def join(self, timeout=None):
            pass

        def stop(self):
            pass

    source = _BatchSource()
    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=lambda: None,
        source=source,
        parallel=3,
        timeout=30,
        max_count=3,
    )
    monkeypatch.setattr(engine, "_new_pool", lambda: _FakePool())
    engine.run()

    assert scheduled_ids == [1, 2, 3]
    assert source.fetch_limits == [3], "all 3 available slots should be filled in a single fetch"


def test_pebble_engine_recovers_from_broken_pool_on_schedule(monkeypatch):
    """If pool.schedule raises RuntimeError('Unexpected error within the Pool')
    when the pool enters PoolStatus.ERROR, PebbleEngine must tear down the dead
    pool, recreate a fresh pool, and schedule the task without crashing."""
    from pebble import ProcessFuture

    monkeypatch.setattr("lib.cuckoo.common.cleaners_utils.free_space_monitor", lambda *a, **k: None)

    class _TaskObj:
        def __init__(self, tid):
            self.id = tid

    class _SingleTaskSource:
        def __init__(self):
            self.failed = []
            self.done_ids = []

        def fetch(self, limit, exclude_ids):
            if 10 in exclude_ids or 10 in self.done_ids:
                return []
            return [_TaskObj(10)]

        def mark_failed(self, task_id):
            self.failed.append(task_id)

    source = _SingleTaskSource()

    class _BrokenPool:
        active = False
        stopped = False

        def schedule(self, fn, args=(), timeout=None):
            raise RuntimeError("Unexpected error within the Pool")

        def stop(self):
            self.stopped = True

        def join(self, timeout=None):
            pass

    class _HealthyPool:
        active = True
        closed = False

        def schedule(self, fn, args=(), timeout=None):
            source.done_ids.append(args[0].id)
            fut = ProcessFuture()
            fut.set_result(None)
            return fut

        def close(self):
            self.closed = True

        def join(self, timeout=None):
            pass

        def stop(self):
            pass

    broken = _BrokenPool()
    healthy = _HealthyPool()
    pools = [broken, healthy]

    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=lambda: None,
        source=source,
        parallel=1,
        timeout=30,
        max_count=1,
    )
    monkeypatch.setattr(engine, "_new_pool", lambda: pools.pop(0))
    engine.run()

    assert broken.stopped is True, "broken pool must be force-stopped"
    assert healthy.closed is True, "replacement healthy pool must be cleanly closed on exit"
    assert source.done_ids == [10], "task must be scheduled on replacement pool"
    assert source.failed == []


def test_teardown_pool_escalates_to_stop_on_join_timeout():
    """Bounded pool teardown must escalate to pool.stop() if graceful pool.join()
    exceeds join_timeout."""
    class _HangingPool:
        active = True

        def __init__(self):
            self.closed = False
            self.stopped = False
            self.join_timeouts = []

        def close(self):
            self.closed = True

        def join(self, timeout=None):
            self.join_timeouts.append(timeout)
            if len(self.join_timeouts) == 1:
                raise TimeoutError("tasks still unfinished")

        def stop(self):
            self.stopped = True

    engine = PebbleEngine(
        task_fn=lambda t: None,
        worker_init=lambda: None,
        source=_CountingSource(),
        parallel=1,
        timeout=30,
        join_timeout=12,
        stop_join_timeout=3,
    )
    pool = _HangingPool()
    engine._teardown_pool(pool)

    assert pool.closed is True
    assert pool.stopped is True
    assert pool.join_timeouts == [12, 3]


def test_is_pool_healthy_handles_stopped_and_raising_active():
    """_is_pool_healthy returns False when PoolStatus is STOPPED/ERROR or when
    accessing pool.active raises an exception."""
    try:
        from pebble.pool.base_pool import PoolStatus
    except ImportError:
        PoolStatus = None

    class _MockThread:
        def is_alive(self):
            return True

    class _Context:
        def __init__(self, status):
            self.status = status

    class _BaseMockPool:
        def __init__(self, status):
            self._task_scheduler_loop = _MockThread()
            self._pool_manager_loop = _MockThread()
            self._message_manager_loop = _MockThread()
            self._context = _Context(status)

    # 1. PoolStatus.STOPPED (or status=3) -> False
    stopped_status = PoolStatus.STOPPED if PoolStatus is not None else 3
    stopped_pool = _BaseMockPool(stopped_status)
    stopped_pool.active = True
    assert PebbleEngine._is_pool_healthy(stopped_pool) is False

    # 2. PoolStatus.ERROR (or status=4) -> False
    error_status = PoolStatus.ERROR if PoolStatus is not None else 4
    error_pool = _BaseMockPool(error_status)
    error_pool.active = True
    assert PebbleEngine._is_pool_healthy(error_pool) is False

    # 3. Accessing pool.active raises an exception -> False
    running_status = PoolStatus.RUNNING if PoolStatus is not None else 1

    class _RaisingActivePool(_BaseMockPool):
        @property
        def active(self):
            raise RuntimeError("broken pool state")

    raising_pool = _RaisingActivePool(running_status)
    assert PebbleEngine._is_pool_healthy(raising_pool) is False

    # 4. Healthy pool with active=True -> True
    class _HealthyActivePool(_BaseMockPool):
        active = True

    healthy_pool = _HealthyActivePool(running_status)
    assert PebbleEngine._is_pool_healthy(healthy_pool) is True

    # 5. PoolStatus.CREATED (status=0) -> True even if active is False
    created_status = PoolStatus.CREATED if PoolStatus is not None else 0
    created_pool = _BaseMockPool(created_status)
    created_pool.active = False
    assert PebbleEngine._is_pool_healthy(created_pool) is True




