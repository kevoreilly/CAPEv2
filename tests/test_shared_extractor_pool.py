"""Extractor sub-pool lifecycle: per-call (pebble default) vs shared-per-child
(prefork). Under prefork a single pool is reused across every extracted file in
the task child and torn down once; under pebble each call gets a fresh pool that
is closed+joined immediately (avoids the recycle-join deadlock)."""
import os

import lib.cuckoo.common.integrations.file_extra_info as fx
from lib.cuckoo.core.processing_engine.prefork import PreforkEngine


class _FakePool:
    """Records close/join without forking real worker processes."""

    _counter = 0

    def __init__(self):
        _FakePool._counter += 1
        self.id = _FakePool._counter
        self.closed = False
        self.stopped = False
        self.joined = False

    def close(self):
        self.closed = True

    def stop(self):
        self.stopped = True

    def join(self, timeout=None):
        self.joined = True


def _reset(monkeypatch):
    """Point the pool factory at _FakePool and reset shared state."""
    if fx._SHARED_EXTRACTOR_POOL is not None:
        fx.shutdown_shared_extractor_pool()
    monkeypatch.setattr(fx, "_new_extractor_pool", lambda max_workers=None: _FakePool())
    monkeypatch.setattr(fx, "_SHARED_EXTRACTOR_POOL", None, raising=False)
    monkeypatch.setattr(fx, "_USE_SHARED_POOL", False, raising=False)


def test_per_call_mode_returns_fresh_pool_each_time(monkeypatch):
    _reset(monkeypatch)
    pool_a, shared_a = fx._acquire_extractor_pool()
    pool_b, shared_b = fx._acquire_extractor_pool()
    assert shared_a is False and shared_b is False
    assert pool_a is not pool_b


def test_shared_mode_reuses_same_pool(monkeypatch):
    _reset(monkeypatch)
    fx.enable_shared_extractor_pool()
    pool_a, shared_a = fx._acquire_extractor_pool()
    pool_b, shared_b = fx._acquire_extractor_pool()
    assert shared_a is True and shared_b is True
    assert pool_a is pool_b


def test_shutdown_closes_and_clears_shared_pool(monkeypatch):
    _reset(monkeypatch)
    fx.enable_shared_extractor_pool()
    pool, _ = fx._acquire_extractor_pool()
    fx.shutdown_shared_extractor_pool()
    assert pool.closed is True
    assert pool.joined is True
    assert fx._USE_SHARED_POOL is False
    # Re-enabling and acquiring must build a brand-new pool, not reuse the dead one.
    fx.enable_shared_extractor_pool()
    pool_next, shared_next = fx._acquire_extractor_pool()
    assert shared_next is True
    assert pool_next is not pool


def test_shutdown_is_idempotent_when_no_pool(monkeypatch):
    _reset(monkeypatch)
    # No pool created yet, shared mode off: must not raise.
    fx.shutdown_shared_extractor_pool()
    fx.enable_shared_extractor_pool()
    # Enabled but never acquired: still a no-op, no raise.
    fx.shutdown_shared_extractor_pool()


class _HangingPool:
    """Graceful join times out (wedged grandchild); after stop() the reap succeeds."""

    def __init__(self):
        self.closed = False
        self.stopped = False
        self.join_timeouts = []

    def close(self):
        self.closed = True

    def join(self, timeout=None):
        self.join_timeouts.append(timeout)
        if len(self.join_timeouts) == 1:
            raise TimeoutError("pool still draining")  # graceful join times out
        # post-stop reap succeeds (stop() SIGKILLed the workers)

    def stop(self):
        self.stopped = True


class _CleanPool:
    def __init__(self):
        self.stopped = False
        self.joined = False

    def close(self):
        pass

    def join(self, timeout=None):
        self.joined = True

    def stop(self):
        self.stopped = True


def test_teardown_force_stops_when_join_times_out():
    pool = _HangingPool()
    fx._teardown_extractor_pool(pool)
    assert pool.closed is True
    assert pool.stopped is True, "a wedged pool must be force-stopped, not left to hang"
    # Both the graceful join and the post-stop reap are bounded (no unbounded wait).
    assert pool.join_timeouts == [fx.EXTRACTOR_POOL_JOIN_TIMEOUT, fx.EXTRACTOR_POOL_STOP_JOIN_TIMEOUT]


def test_teardown_does_not_stop_when_join_succeeds():
    pool = _CleanPool()
    fx._teardown_extractor_pool(pool)
    assert pool.joined is True
    assert pool.stopped is False, "a cleanly-drained pool must not be force-stopped"


def test_teardown_none_is_noop():
    fx._teardown_extractor_pool(None)  # must not raise


class _AlwaysHangingPool:
    """Every join times out — even the post-stop reap (grandchild stuck in D-state).
    Teardown must still return instead of blocking forever."""

    def __init__(self):
        self.closed = False
        self.stopped = False
        self.join_timeouts = []

    def close(self):
        self.closed = True

    def join(self, timeout=None):
        self.join_timeouts.append(timeout)
        raise TimeoutError("never drains")

    def stop(self):
        self.stopped = True


def test_teardown_bounds_post_stop_join_and_returns():
    pool = _AlwaysHangingPool()
    fx._teardown_extractor_pool(pool)  # must return, not hang
    assert pool.stopped is True
    # both the initial join AND the post-stop reap must be bounded (no None/unbounded).
    assert len(pool.join_timeouts) == 2
    assert all(t is not None for t in pool.join_timeouts)


class _Task:
    id = 1
    category = "file"


def test_prefork_child_enables_and_tears_down_shared_pool(tmp_path):
    """The prefork child must (1) opt into the shared extractor pool before
    running the task and (2) tear it down once when the task finishes. Verified
    across a real fork: the child records both observations to marker files."""
    enabled_marker = tmp_path / "enabled"
    closed_marker = tmp_path / "closed"

    def task_fn(task):
        # Runs inside the forked child. Observe that shared mode is already on,
        # then install a fake pool so teardown has something to close.
        enabled_marker.write_text("yes" if fx._USE_SHARED_POOL else "no")

        class _FakeChildPool:
            def close(self):
                closed_marker.write_text("closed")

            def join(self, timeout=None):
                pass

        fx._new_extractor_pool = lambda max_workers=None: _FakeChildPool()
        fx._acquire_extractor_pool()  # store the shared fake pool

    eng = PreforkEngine(task_fn=task_fn, worker_init=lambda: None,
                        source=None, parallel=1, timeout=30)

    pid = os.fork()
    if pid == 0:
        try:
            eng._child_main(_Task())
        finally:
            os._exit(0)
    os.waitpid(pid, 0)

    assert enabled_marker.read_text() == "yes"
    assert closed_marker.read_text() == "closed"


def test_generic_file_extractors_skips_pool_when_nothing_enabled(monkeypatch, tmp_path):
    """When no extractor modules/functions are enabled for a file,
    generic_file_extractors must not fork or tear down an empty ProcessPool."""
    acquired = []
    monkeypatch.setattr(fx, "_acquire_extractor_pool", lambda **kw: acquired.append(kw) or (_FakePool(), False))
    monkeypatch.setattr(fx, "extra_info_modules", [])
    monkeypatch.setattr(fx, "file_info_funcs", [])

    fx.generic_file_extractors(
        file=str(tmp_path / "dummy.bin"),
        destination_folder=str(tmp_path / "extracted"),
        data_dictionary={},
        options={},
        results={},
        duplicated={},
    )
    assert acquired == [], "generic_file_extractors must not create a ProcessPool when 0 extractors are enabled"


def test_shared_mode_recreates_unhealthy_pool(monkeypatch):
    """If the shared extractor pool enters an unhealthy/broken state
    (active=False), _acquire_extractor_pool must tear it down and create a new pool."""
    _reset(monkeypatch)
    fx.enable_shared_extractor_pool()
    pool_a, shared_a = fx._acquire_extractor_pool()
    assert shared_a is True

    # Simulate pool entering PoolStatus.ERROR (active = False)
    pool_a.active = False

    pool_b, shared_b = fx._acquire_extractor_pool()
    assert shared_b is True
    assert pool_b is not pool_a, "broken shared pool must be replaced"
    # An unhealthy pool is force-stopped (close+drain is pointless on a broken pool).
    assert pool_a.stopped is True and pool_a.joined is True, "broken shared pool must be torn down"


def test_per_call_mode_right_sizes_max_workers(monkeypatch):
    """In per-call mode, _acquire_extractor_pool(max_workers=N) forwards
    max_workers to _new_extractor_pool so a file with 2 enabled extractors
    does not fork more workers than needed."""
    requested_workers = []

    def _recording_new_pool(max_workers=None):
        requested_workers.append(max_workers)
        return _FakePool()

    monkeypatch.setattr(fx, "_new_extractor_pool", _recording_new_pool)
    monkeypatch.setattr(fx, "_SHARED_EXTRACTOR_POOL", None, raising=False)
    monkeypatch.setattr(fx, "_USE_SHARED_POOL", False, raising=False)

    pool, shared = fx._acquire_extractor_pool(max_workers=2)
    assert shared is False
    assert requested_workers == [2]
    fx._teardown_extractor_pool(pool)


def test_stop_active_extractor_pools_stops_live_pools(monkeypatch):
    """_stop_active_extractor_pools() must force-stop any registered live pool,
    close worker channels and terminate worker processes (used by the multiprocessing
    Finalize hook on worker SIGTERM/exit)."""
    _reset(monkeypatch)
    fx._ACTIVE_EXTRACTOR_POOLS.clear()

    class _MockProc:
        def __init__(self):
            self.terminated = False

        def terminate(self):
            self.terminated = True

    class _MockWorkerManager:
        def __init__(self):
            self.channels_closed = False
            self.proc = _MockProc()
            self.workers = {1: self.proc}

        def close_channels(self):
            self.channels_closed = True

    class _MockPoolManager:
        def __init__(self):
            self.worker_manager = _MockWorkerManager()

    class _StoppablePool(_FakePool):
        def __init__(self):
            super().__init__()
            self.stopped = False
            self._pool_manager = _MockPoolManager()

        def stop(self):
            self.stopped = True

    monkeypatch.setattr(fx, "_new_extractor_pool", lambda max_workers=None: _StoppablePool())
    pool, _ = fx._acquire_extractor_pool(max_workers=1)
    assert pool in fx._ACTIVE_EXTRACTOR_POOLS

    fx._stop_active_extractor_pools()
    assert pool.stopped is True
    assert pool._pool_manager.worker_manager.channels_closed is True
    assert pool._pool_manager.worker_manager.proc.terminated is True
    assert len(fx._ACTIVE_EXTRACTOR_POOLS) == 0

    # Also verify with a real pebble.ProcessPool that no worker child survives.
    import multiprocessing
    import pebble

    real_pool = pebble.ProcessPool(max_workers=1, context=multiprocessing.get_context("fork"))
    fx._register_extractor_pool(real_pool)
    future = real_pool.schedule(os.getpid)
    future.result()
    assert len(multiprocessing.active_children()) > 0
    fx._stop_active_extractor_pools()
    real_pool.join(timeout=2)
    assert len(multiprocessing.active_children()) == 0


def test_generic_file_extractors_recreates_shared_pool_on_schedule_error(monkeypatch, tmp_path):
    """If pool.schedule() raises RuntimeError or BrokenProcessPool in shared mode,
    generic_file_extractors must tear down the broken shared pool, acquire a fresh
    shared pool, and retry pool.schedule() successfully."""
    _reset(monkeypatch)
    fx.enable_shared_extractor_pool()

    class _MockResultFuture:
        def result(self):
            return {"result": {"extracted_files": []}, "took_seconds": 0.1}

    class _BrokenSchedulePool(_FakePool):
        def __init__(self):
            super().__init__()
            self.schedule_calls = 0

        def schedule(self, fn, args=(), kwargs=None, timeout=None):
            self.schedule_calls += 1
            raise RuntimeError("Unexpected error within the Pool")

    class _WorkingPool(_FakePool):
        def __init__(self):
            super().__init__()
            self.schedule_calls = 0

        def schedule(self, fn, args=(), kwargs=None, timeout=None):
            self.schedule_calls += 1
            return _MockResultFuture()

    pool_1 = _BrokenSchedulePool()
    pool_2 = _WorkingPool()
    pools = [pool_1, pool_2]

    monkeypatch.setattr(fx, "_new_extractor_pool", lambda max_workers=None: pools.pop(0))

    def _dummy_extractor(file, **kwargs):
        return {"result": {"extracted_files": []}}

    _dummy_extractor.enabled = True
    _dummy_extractor.__name__ = "dummy_extractor"

    monkeypatch.setattr(fx, "extra_info_modules", [])
    monkeypatch.setattr(fx, "file_info_funcs", [_dummy_extractor])

    dummy_file = tmp_path / "sample.bin"
    dummy_file.write_bytes(b"MZ\x90\x00")

    fx.generic_file_extractors(
        file=str(dummy_file),
        destination_folder=str(tmp_path / "extracted"),
        data_dictionary={},
        options={},
        results={},
        duplicated={},
    )

    assert pool_1.schedule_calls == 1
    assert pool_1.closed is True and pool_1.joined is True, "broken shared pool must be torn down"
    assert pool_2.schedule_calls == 1
    assert pool_2.closed is False, "recreated shared pool must remain warm for subsequent files"
    assert fx._SHARED_EXTRACTOR_POOL is pool_2
    fx.shutdown_shared_extractor_pool()
    assert pool_2.closed is True and pool_2.joined is True




def test_unreaped_pool_stays_registered_for_exit_finalizer(monkeypatch):
    """A pool whose workers could not be reaped must stay in
    _ACTIVE_EXTRACTOR_POOLS so the exit finalizer still terminates them;
    a cleanly reaped pool must be unregistered."""
    import threading

    class _WedgedPool:
        active = True

        def __init__(self):
            self.stopped = False
            self._never = threading.Event()

        def close(self):
            pass

        def stop(self):
            self.stopped = True

        def join(self, timeout=None):
            self._never.wait()

    monkeypatch.setattr(fx, "EXTRACTOR_POOL_JOIN_TIMEOUT", 0.1)
    monkeypatch.setattr(fx, "EXTRACTOR_POOL_STOP_JOIN_TIMEOUT", 0.1)
    fx._ACTIVE_EXTRACTOR_POOLS.clear()

    wedged = _WedgedPool()
    fx._ACTIVE_EXTRACTOR_POOLS.add(wedged)
    fx._teardown_extractor_pool(wedged)  # must return, not hang
    assert wedged.stopped is True
    assert wedged in fx._ACTIVE_EXTRACTOR_POOLS

    clean = _CleanPool()
    fx._ACTIVE_EXTRACTOR_POOLS.add(clean)
    fx._teardown_extractor_pool(clean)
    assert clean not in fx._ACTIVE_EXTRACTOR_POOLS
    fx._ACTIVE_EXTRACTOR_POOLS.clear()
